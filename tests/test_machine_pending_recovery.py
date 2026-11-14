"""Production pending-capture handoff against independent loopback NAS/OS fixtures.

No capture acquisition is run: driver mutations fail in snapshot_source_fixture.
The service must validate and publish exactly the already acquired root+LV set.
Pending publication and transfer run in separate service lifetimes. Automatic
capture is disabled through its normal CLI between them, preserving the bound
source; this fixture does not model live mount/sysfs/LVM discovery for the next
automatic generation.
"""
import copy
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

from test_probe import wire, check
from test_backup_cli import Reader
from test_login import value
from test_snapshot import filesystem
from test_service import wait_for
from test_service_interval_parity import Nas, MIB
from machine_service_specimens import machine_disk, machine_plan, lvm_disk
from snapshot_service_fixture import SnapshotSources


def write(path, record):
    path.write_bytes(wire(record))
    path.chmod(0o600)


def recovery_records(journal, renewed):
    current = copy.deepcopy(journal)
    prepared = copy.deepcopy(current)
    prepared.update(phase="prepared", snapshot=None, artifact=None)
    volumes = [current["plan"]["root"], *current["plan"]["selected_extra"]]
    current_reservations = [current["reservation"], *current["reservation"]["extras"]]
    initial_reservations = [prepared["reservation"], *prepared["reservation"]["extras"]]
    for index, (volume, original, progress) in enumerate(zip(
            volumes, initial_reservations, current_reservations)):
        acquired = current["snapshot"] if index == 0 else progress["snapshot"]
        old_path = f"/.synosnap_data/prior-{index}"
        old_uuid = acquired["uuid"] if renewed else "f"*32
        old = dict(minor=progress["minor"], origin_path=volume["device"], cow_path=old_path,
                   uuid=old_uuid if renewed else "0"*32, sequence=9 if renewed else 0,
                   active=int(renewed), unverified=int(not renewed), snapshot_mode=0,
                   cancelled=0, error_code="0" if renewed else "-22")
        cow = dict(device=100+index, inode=1000+index)
        owner = dict(format=2, device=volume["logical_path"] if "lv_uuid" in volume else volume["device"],
                     minor=progress["minor"], cow_relative=old_path,
                     filesystem_uuid=volume["filesystem_uuid"], cow=cow,
                     snapshot=dict(uuid=old_uuid, sequence=9))
        prior = dict(snapshot=old, cow=cow, cow_path=old_path, cow_relative=old_path,
                     minor=progress["minor"], tracking_filesystem_uuid=volume["filesystem_uuid"],
                     durable_owner=owner)
        original.update(prior=copy.deepcopy(prior))
        progress.update(prior=copy.deepcopy(prior), tracking_recovery=(
            "durable-owner-renewed-without-history" if renewed else "durable-owner-fresh-chain"))
        for key in ("cow_unused", "filesystem_unused", "cache_unused"):
            original.pop(key, None)
        for key in ("changes", "previous_capture_id", "previous_directory"):
            original.pop(key, None)
            progress.pop(key, None)
        if index == 0:
            original.update(snapshot_attempted=0, snapshot_released=0, snapshot_time=0)
        else:
            original.update(attempted=0, released=0, snapshot=None)
    return prepared, current


def main():
    exe, driver, openssl, fixture = map(str, sys.argv[1:5])
    for renewed, post_aborted, post_failed in ((False, False, False), (True, False, False),
                                               (False, True, False), (False, False, True)):
        with tempfile.TemporaryDirectory(prefix="machine-pending-recovery-") as temporary:
            root = Path(temporary)
            part = filesystem(root)
            primary, boot, boot_size, root_at = machine_disk(part)
            plan = machine_plan(primary, boot, boot_size, root_at, len(part))
            pv, lv_data, pv_plan, lv, group = lvm_disk(root)
            plan.update(other_disk_count=1, selected_extra=[lv], additional_disks=[pv_plan],
                        lvm=dict(volume_groups=[group], selected_lvs=[lv]))
            sources = SnapshotSources(root)
            if renewed:
                sources.generation = 9
            journal, capture_dir = sources.capture(plan, primary, pv, {lv["image_name"]: lv_data})
            prepared, current = recovery_records(journal, renewed)
            write(capture_dir/"capture.pstream", current)
            # Terminal cleanup consumes independent released evidence, rather
            # than asking the interposed driver to mutate a real slot.
            released = copy.deepcopy(current)
            released["reservation"]["snapshot_released"] = 1
            for extra in released["reservation"]["extras"]:
                extra["released"] = 1
            write(capture_dir/"release.pstream", released)
            config_home = root/"config"
            private = config_home/"opensabba"
            private.mkdir(parents=True, mode=0o700)
            cert, key = root/"cert.pem", root/"key.pem"
            subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
                            "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
                            "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True)
            nas = Nas(config_home, cert, key)
            # Automatic persistent tracking queries the NAS even when no
            # independent local ancestry survived the restored machine.
            nas.allow_initial_base_query = True
            nas.run_available = False
            nas.prepared_runs.add(27)
            expected = {"sda.img": bytes(primary), "sdc.img": pv, lv["image_name"]: lv_data}
            unused = {"sda.img": [(root_at+len(part)+MIB, root_at+len(part)+5*MIB)],
                      "sdc.img": [(MIB, 17*MIB)], lv["image_name"]: []}
            nas.select(expected, unused, {name: [] for name in expected}, False, ["/", "/data"])
            machine = dict(format=2, ds_id="test-nas", device_uuid="test-device", username="test-user",
                           task_id=2, task_uuid="fixture-task")
            write(private/"session.pstream", dict(
                format=2, host="127.0.0.1", port=nas.port, ca_file=str(cert), username="test-user",
                device_uuid="test-device", token="test-token", ds_id="test-nas", registration_state="confirmed"))
            pending = private/"service-machine-pending.pstream"
            write(pending, dict(task_owner=machine, run=27, task_uuid="fixture-task", base_version_id=0,
                preparation=dict(running_task_id=27,version_id=9,result_id=14,data_format=1,base_version_id=0),
                capture=prepared))
            env = dict(os.environ, XDG_CONFIG_HOME=str(config_home), LD_PRELOAD=fixture,
                       OPENSABBA_SOURCE_FIXTURE=str(sources.manifest),
                       OPENSABBA_SOURCE_TRACE=str(sources.trace))
            process = None
            try:
                # Wrong markers/ancestry fail at the pending handoff before
                # publishing a source, preparing NAS work or changing evidence.
                for role in ("root", "extra"):
                    for field, wrong in (("tracking_recovery", "unknown"),
                                         ("previous_capture_id", "a"*32)):
                        invalid = copy.deepcopy(current)
                        reservation = invalid["reservation"] if role == "root" else invalid["reservation"]["extras"][0]
                        reservation[field] = wrong
                        write(capture_dir/"capture.pstream", invalid)
                        capture_bytes, pending_bytes = (capture_dir/"capture.pstream").read_bytes(), pending.read_bytes()
                        refused = subprocess.run([exe, "service", "run"], env=env, capture_output=True,
                                                 text=True, timeout=15)
                        check(refused.returncode != 0, refused.stdout+refused.stderr)
                        check((capture_dir/"capture.pstream").read_bytes() == capture_bytes and
                              pending.read_bytes() == pending_bytes, "rejected progress rewrote evidence")
                        check(not (private/"service-source.pstream").exists(), "rejected progress was bound")
                        check("upload_block" not in nas.requests and "update_backup_task" not in nas.requests,
                              "rejected progress prepared or uploaded NAS work")
                write(capture_dir/"capture.pstream", current)
                if post_aborted or post_failed:
                    # Published acquisition with either an aborted post or a
                    # completed mode-1 failure, without a snapshot_reused marker.
                    # Restart the production daemon; neither script may replay.
                    content = f"echo replayed >> '{root / 'script-replayed'}'\n".encode()
                    definition = dict(enabled=1, error=0, extension=".sh",
                                      sha256=hashlib.sha256(content).hexdigest())
                    retained = dict(script_exec_mode=1)
                    for side in ("pre", "post"):
                        retained.update({side+"_script_enabled": 1, side+"_script_error": 0,
                                         side+"_script_extension": ".sh", side+"_script_content": content})
                    settings = {k: v for k, v in retained.items() if not k.endswith("_content")}
                    nas.task_fields = dict(pre_post_script_setting=settings,
                                           pre_script_content=content, post_script_content=content)
                    complete = dict(phase="complete", log_type=7045, exit_code="0", cancelled=0,
                                    output=0, log_time=1, reported=0, output_uploaded=0)
                    aborted = (dict(complete, log_type=7051, exit_code="37") if post_failed else
                               dict(complete, log_type=0, exit_code="-1", cancelled=1))
                    script_journal = dict(schema=1, task_id=2, running_task_id=27,
                        task_uuid="fixture-task", ds_id="test-nas", device_uuid="test-device",
                        username="test-user", capture_id=current["id"], scripts=retained,
                        policy=dict(pre=definition, post=definition, stop_on_failure=1),
                        pre=complete, post=aborted)
                    write(private/"backup-scripts-27.pstream", script_journal)
                if post_failed:
                    # The process died after the mode-1 post result became
                    # durable and before pending->source publication. Recovery
                    # must report failure without binding, reading or uploading.
                    nas.expected_failure = True
                    nas.run_available = True
                    for restart in range(2):
                        polls = nas.requests.count("long_poll")
                        process = subprocess.Popen([exe, "service", "run"], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        skipped = private/"service-machine-skipped-27.pstream"
                        wait_for(lambda: nas.finished.is_set() and skipped.exists() and not pending.exists(),
                                 "mode-1 post failure was not durably retired")
                        wait_for(lambda: nas.requests.count("long_poll") > polls, "failure stopped the daemon")
                        process.send_signal(signal.SIGTERM)
                        out, err = process.communicate(timeout=8)
                        check(process.returncode == 0 and not nas.errors, out+err+str(nas.errors))
                        process = None
                    check(not (private/"service-source.pstream").exists() and
                          not (private/"backup-job.pstream").exists(), "failed post published an upload source")
                    check(nas.requests.count("check_complete") == 1 and "upload_block" not in nas.requests,
                          "failed post retried the event as a real backup")
                    check([entry["log_type"] for entry in nas.script_logs] == [7045, 7051],
                          "failed post reporting was omitted or replayed")
                    scripts = value(Reader((private/"backup-scripts-27.pstream").read_bytes()))
                    check(scripts["nas_phase"] == "terminal" and scripts["nas_outcome"] == "error" and
                          scripts["post"]["exit_code"] == "37" and scripts["post"]["reported"] == 1,
                          "failed post lost its durable error outcome")
                    check((capture_dir/"capture.pstream").read_bytes() == wire(current) and
                          not (root/"script-replayed").exists(),
                          "failed post changed the published snapshot or replayed scripts")
                    continue
                # A fresh process models restart in the acquisition->binding
                # handoff window. Withhold the queued NAS run until the ready
                # source has been published and the service has stopped.
                process = subprocess.Popen([exe, "service", "run"], env=env,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                binding_path = private/"service-source.pstream"
                wait_for(lambda: not pending.exists() and binding_path.exists() and
                         "long_poll" in nas.requests, "pending source was not published")
                process.send_signal(signal.SIGTERM)
                out, err = process.communicate(timeout=8)
                check(process.returncode == 0 and not nas.errors, out+err+str(nas.errors))
                process = None
                binding_bytes = binding_path.read_bytes()
                binding = value(Reader(binding_bytes))
                check(binding["capture"] == current and binding["queued_run"] == 27 and
                      binding["claimed_run"] == 0, "pending handoff changed source identity or claim")
                check(not (private/"backup-job.pstream").exists(), "withheld NAS run was prepared")
                nas.run_available = True
                process = subprocess.Popen([exe, "service", "run"], env=env,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if not nas.finished.wait(30):
                    process.terminate()
                    out, err = process.communicate(timeout=8)
                    raise AssertionError(f"pending capture upload missing: {nas.errors} {out} {err}")
                wait_for(lambda: value(Reader((private/"backup-job.pstream").read_bytes()))["phase"] == "complete",
                         "pending-capture completion was not durable")
                process.send_signal(signal.SIGTERM)
                out, err = process.communicate(timeout=8)
                check(process.returncode == 0 and not nas.errors, out+err+str(nas.errors))
                process = None
                check(not pending.exists(), "ready source handoff retained pending ownership")
                check((capture_dir/"capture.pstream").read_bytes() == wire(current),
                      "service rewrote immutable capture evidence")
                saved = value(Reader((private/"backup-job.pstream").read_bytes()))
                check("incremental" not in saved and nas.requests.count("upload_block") == 1,
                      "lost-history capture fabricated a base or replayed upload")
                if post_aborted:
                    scripts = value(Reader((private/"backup-scripts-27.pstream").read_bytes()))
                    check(scripts["post"] == aborted and "snapshot_reused" not in scripts,
                          "startup changed the aborted post result or fabricated reuse")
                    check(scripts["capture_id"] == current["id"] and
                          not (root/"script-replayed").exists(),
                          "published snapshot recovery replayed boundary scripts")
                    check(len(nas.script_logs) == 1 and scripts["pre"]["reported"] == 1,
                          "startup lost or repeated the completed pre result")
                sources.verify_reads()
            finally:
                if process and process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=8)
                nas.close()
    print("Production pending recovery and published/aborted-post startup uploads passed")


if __name__ == "__main__":
    main()
