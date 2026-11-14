"""Independent loopback peer checks trust decisions before application requests."""
import hashlib
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

from test_probe import check, exact, request, wire


def run_case(executable, cert, key, ca, pin, mode, accept, host="127.0.0.1"):
    errors = []
    received = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(8)

        def peer():
            try:
                with listener.accept()[0] as plain:
                    plain.settimeout(5)
                    check(exact(plain, len(request("encrypt_channel"))) == request("encrypt_channel"),
                          "unexpected plaintext before TLS")
                    plain.sendall(wire({}))
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(cert, key)
                    try:
                        secure = context.wrap_socket(plain, server_side=True)
                    except ssl.SSLError:
                        check(not accept, "valid handshake rejected")
                        return
                    with secure:
                        try:
                            data = secure.recv(4096)
                        except ConnectionResetError:
                            check(not accept, "valid connection reset")
                            data = b""
                        received.append(data)
                        if accept:
                            check(data == request("query_server_info"), "wrong authenticated boundary")
                            secure.sendall(wire({"ds_id": "mock-certificate-server"}))
                        else:
                            check(not data, "application data sent before rejecting certificate")
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=peer, daemon=True)
        worker.start()
        result = subprocess.run([executable, host, str(listener.getsockname()[1]),
                                 str(ca) if ca else "-", pin or "-", mode],
                                capture_output=True, text=True, timeout=10)
        worker.join(10)
        check(not worker.is_alive() and not errors, f"peer: {errors}; {result.stderr}")
        check(result.returncode == (0 if accept else 1), result.stderr)
        if accept:
            expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            check(result.stdout.strip() == expected, "pin is not SHA-256 of DER certificate")
        else:
            check(not result.stdout and not any(received), "rejected certificate produced application output")


def main():
    executable, openssl = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="opensabba-certificates-") as temporary:
        root = Path(temporary)
        pairs = []
        for index in range(2):
            cert, key = root / f"{index}.pem", root / f"{index}.key"
            subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
                            "-days", "1", "-keyout", str(key), "-out", str(cert),
                            "-subj", "/CN=fixture.invalid", "-addext", "subjectAltName=IP:127.0.0.1"],
                           check=True, capture_output=True)
            pairs.append((cert, key))
        first, key = pairs[0]
        second, second_key = pairs[1]
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(first.read_text())).hexdigest()
        second_pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(second.read_text())).hexdigest()
        run_case(executable, first, key, None, None, "service", False)
        run_case(executable, first, key, None, None, "quiet", True)
        run_case(executable, first, key, None, None, "interactive", True)
        run_case(executable, first, key, None, pin, "service", True)
        run_case(executable, second, second_key, None, pin, "quiet", False)
        run_case(executable, second, second_key, second, pin, "service", True)
        run_case(executable, second, second_key, first, pin, "quiet", False)
        run_case(executable, second, second_key, first, second_pin, "quiet", False)
        run_case(executable, first, key, None, None, "quiet", True, host="localhost")
        run_case(executable, first, key, first, pin, "quiet", False, host="localhost")
        print("PASS certificate pin, renewal, custom CA and pre-request rejection")


if __name__ == "__main__":
    main()
