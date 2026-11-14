"""Loopback TLS only: immutable cached incremental replay and reopened resume."""
import argparse
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading

from pstream_peer import upload_value, value
from test_probe import check, wire

MIB = 1024 * 1024
SIZE = 5 * MIB
CHECKPOINT = 65536  # Allocation-context cache records, despite 1 MiB upload blocks.


def lz4_block(data, expected):
    """Independent raw LZ4 decoder; no platform-specific Python/native library."""
    at, output = 0, bytearray()

    def extended(length):
        nonlocal at
        if length == 15:
            while True:
                check(at < len(data), "truncated LZ4 length")
                extra = data[at]
                at += 1
                length += extra
                if extra != 255:
                    break
        return length

    while at < len(data):
        token = data[at]
        at += 1
        literal = extended(token >> 4)
        check(at + literal <= len(data), "truncated LZ4 literals")
        output.extend(data[at:at + literal])
        at += literal
        if at == len(data):
            break
        check(at + 2 <= len(data), "truncated LZ4 distance")
        distance = int.from_bytes(data[at:at + 2], "little")
        at += 2
        check(0 < distance <= len(output), "invalid LZ4 back reference")
        length = extended(token & 15) + 4
        check(len(output) + length <= expected, "LZ4 output exceeds record")
        for _ in range(length):
            output.append(output[-distance])
    check(len(output) == expected, "LZ4 output length differs")
    return bytes(output)


def run(driver, cert, key, directory, mode):
    multi = mode.startswith("multi-")
    restart = mode.endswith("-resume")
    compressed = "-lz4" in mode
    outcome = "partial" if "-partial" in mode else "complete"
    names = ["disk-0", "disk-1"] if multi else ["disk-0"]
    target = {name: bytearray([0xa5 if name == "disk-0" else 0x5a]) * SIZE for name in names}
    for image in target.values():
        image[:MIB] = bytes([0x11]) * MIB
        image[MIB:3 * MIB] = bytes(2 * MIB)
        image[4 * MIB:] = bytes([0x22]) * MIB
    received = {name: 0 for name in names}
    errors, actions, performance = [], [], {}
    uploads = creates = metadata_count = finishes = checkpoints = 0
    completed = False
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    stop = threading.Event()
    connections = []

    def apply(block, expected_name, expected_at):
        name, at, length = block["image_name"], block["offset"], block["length"]
        check(name == expected_name and at == expected_at and length > 0 and at + length <= SIZE,
              "cached record image or coverage differs")
        unused = MIB <= at < 3 * MIB
        changed = at < MIB or at >= 4 * MIB
        cbt = not (4 * MIB <= at < 4 * MIB + 4096)
        boundary = MIB if at < MIB else 3 * MIB if unused else 4 * MIB if at < 4 * MIB else (
            4 * MIB + 4096 if not cbt else SIZE)
        check(at + length <= boundary, "cached block crosses an interval boundary")
        check(block["used"] == int(not unused) and block["changed"] == int(changed) and
              block["is_interval_cbt"] == int(cbt), "cached allocation/CBT flags changed")
        if not unused and changed:
            data = block["buffer"]
            if compressed:
                check(block.get("compressed") == 1, "cached LZ4 flag missing")
                data = lz4_block(data, length)
            else:
                check("compressed" not in block, "raw cache was recompressed")
            check(data == bytes([0xa5 if name == "disk-0" else 0x5a]) * length,
                  "cached payload differs")
            target[name][at:at + length] = data
        else:
            check("buffer" not in block and "compressed" not in block and
                  block["changed_length"] == 0, "unused/inherited cache record carries payload")
        return at + length

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(.1)

        def handle(peer):
            nonlocal uploads, creates, metadata_count, finishes, checkpoints, completed
            try:
                with peer:
                    peer.settimeout(10)
                    check(value(peer)["action"] == "encrypt_channel", "TLS upgrade missing")
                    peer.sendall(wire({}))
                    with context.wrap_socket(peer, server_side=True) as tls:
                        request = value(tls)
                        action = request["action"]
                        actions.append(action + ":" + request.get("subaction", ""))
                        if action == "query_server_info":
                            reply = {"ds_id": "test-nas"}
                        elif action == "client_trigger":
                            op = request["subaction"]
                            # Cached lineage is already fixed by the preceding
                            # snapshot. Generic latest-base selection is wrong.
                            check(op in ("add_backup_task", "update_backup_task"),
                                  "cached replay queried generic latest NAS base")
                            check(request["is_cache"] == 1 and request["is_cbt"] == 1 and
                                  request["base_version_id"] == 8, "cache handshake lost its base or cache flag")
                            if op == "add_backup_task":
                                creates += 1
                                check(request["task_id"] == 2 and request["trigger_type"] == 0 and
                                      creates == 1, "cached event creation identity differs or was repeated")
                            else:
                                check(request["running_task_id"] == 27, "cache preparation has wrong running task")
                            reply = dict(running_task_id=27, version_id=9, result_id=112, data_format=1)
                        elif action == "get_running_task_result":
                            check(restart and not completed, "unexpected result query")
                            reply = {"running_task_result": dict(task_id=2, result_id=112,
                                     job_action="backup", status="incomplete")}
                        elif action == "get_running_task":
                            checkpoints += 1
                            check(restart and checkpoints == 1 and uploads == 1, "unexpected checkpoint query")
                            offsets = {"disk-0": SIZE, "disk-1": CHECKPOINT} if multi else {"disk-0": CHECKPOINT}
                            reply = {"running_task_list": [dict(id=27, type=0, task_id=2,
                                version_id=9, result_id=112, status=2, detail_status=6,
                                is_backing_up=0, backup_task=dict(error_code=0, is_cbt=1,
                                is_cache=1, base_version_id=8, resume_info=json.dumps({
                                    name: dict(current=str(at), transfer_current=str(at))
                                    for name, at in offsets.items()})))]}
                        elif action == "backup":
                            op = request["subaction"]
                            check(request["running_task_id"] == 27, "cache request changed running task")
                            if op == "update_device_spec":
                                metadata_count += 1
                                check(request["snapshot_info"] == b"{}" and metadata_count == 1,
                                      "metadata changed or was replayed after upload interruption")
                                reply = {}
                            elif op == "upload_block":
                                uploads += 1
                                check(request["is_cache"] == 1 and request["resume"] == int(uploads == 2),
                                      "upload initialization lost cache or resume policy")
                                check(uploads <= (2 if restart else 1), "unexpected upload attempt")
                                tls.sendall(wire({"success": 1}))
                                offsets = {name: 0 for name in names}
                                if uploads == 2:
                                    offsets = {"disk-0": SIZE, "disk-1": CHECKPOINT} if multi else {
                                        "disk-0": CHECKPOINT}
                                for name in names:
                                    at = offsets[name]
                                    while at < SIZE:
                                        block = upload_value(tls, performance)
                                        at = apply(block, name, at)
                                        received[name] = at
                                        if restart and uploads == 1 and name == names[-1] and at == CHECKPOINT:
                                            return  # Drop without upload-close acknowledgment.
                                check(upload_value(tls, performance) == {"close": 1}, "cached upload close missing")
                                completed = True
                                reply = {"close": 1}
                            else:
                                check(op == "check_complete" and completed and
                                      request["status"] == outcome and request["is_cbt"] == 1 and
                                      request["result_id"] == 112, "cache finalized before exact replay completed")
                                finishes += 1
                                reply = {"status": outcome}
                        else:
                            raise AssertionError(f"unexpected cached action {action}")
                        tls.sendall(wire(reply))
            except Exception as error:
                errors.append(repr(error))

        def serve():
            while not stop.is_set():
                try:
                    peer, _ = listener.accept()
                except socket.timeout:
                    continue
                worker = threading.Thread(target=handle, args=(peer,))
                connections.append(worker)
                worker.start()

        server = threading.Thread(target=serve)
        server.start()
        try:
            result = subprocess.run([driver, str(listener.getsockname()[1]), str(cert), mode, str(directory)],
                                    capture_output=True, text=True, timeout=45)
            check(result.returncode == 0,
                  f"{mode}: {result.stdout} {result.stderr}; actions={actions}; errors={errors}")
        finally:
            stop.set()
            server.join(2)
            for connection in connections:
                connection.join(11)
    check(not errors and creates == finishes == metadata_count == 1 and completed and
          uploads == (2 if restart else 1) and checkpoints == int(restart),
          f"{mode}: cache lifecycle incomplete: {errors}; actions={actions}")
    check(all(at == SIZE for at in received.values()), "one cached image never completed")
    check("read_disk" not in performance, "cache replay reread the original snapshot payload")
    for name in names:
        expected = bytearray([0xa5 if name == "disk-0" else 0x5a]) * SIZE
        expected[MIB:3 * MIB] = bytes(2 * MIB)
        check(target[name] == expected, "NAS incremental target differs after cached replay")
    check(not list(directory.glob("cache-*.header")) and not list(directory.glob("cache-*.data")),
          "completed cache pair was not removed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("driver")
    parser.add_argument("openssl")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="opensabba-cached-backup-") as temporary:
        directory = Path(temporary)
        cert, key = directory / "cert.pem", directory / "key.pem"
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
                        "-days", "1", "-keyout", str(key), "-out", str(cert),
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"],
                       capture_output=True, check=True)
        for shape in ("single", "multi"):
            for compression in ("raw", "lz4"):
                for suffix in ("", "-resume", "-partial", "-partial-resume"):
                    mode = f"{shape}-{compression}{suffix}"
                    job = directory / mode
                    job.mkdir()
                    run(str(Path(args.driver).resolve()), cert, key, job, mode)
    print("PASS complete/partial cached raw/LZ4 single/multi lifecycle and reopened exact-checkpoint resume")


if __name__ == "__main__":
    main()
