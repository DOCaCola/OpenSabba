"""Independent NTLM CONNECT peer verifying both response families and connection affinity."""
import base64
import zipfile
import hashlib
import hmac
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

from test_probe import check
from proxy_peer import relay
from test_registration import Nas
from test_service import wait_for

exe, openssl = sys.argv[1:]
SIGNATURE = b"NTLMSSP\0"
UNICODE, SIGN, NTLM, ESS = 1, 0x10, 0x200, 0x80000
TARGET_INFO, BITS128, KEY_EXCHANGE = 0x800000, 0x20000000, 0x40000000
SERVER_CHALLENGE = bytes.fromhex("0123456789abcdef")


def md4(data):
    result = subprocess.run([openssl, "dgst", "-md4", "-provider", "legacy", "-binary"],
                            input=data, capture_output=True, check=True)
    return result.stdout


def hmac_md5(key, data):
    return hmac.new(key, data, hashlib.md5).digest()


def rc4(key, data):
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) % 256
        state[i], state[j] = state[j], state[i]
    i = j = 0
    output = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        output.append(byte ^ state[(state[i] + state[j]) % 256])
    return bytes(output)


def des_response(hash_value, challenge):
    padded = hash_value.ljust(21, b"\0")
    answer = b""
    for pos in (0, 7, 14):
        seven = padded[pos:pos + 7]
        key = bytes((((int.from_bytes(seven, 'big') >> (49 - 7 * k)) & 0x7f) << 1)
                    for k in range(8))
        # DES parity bits do not affect key scheduling.
        answer += subprocess.run([openssl, "enc", "-des-ecb", "-provider", "legacy",
                                  "-K", key.hex(), "-nopad", "-nosalt"],
                                 input=challenge, capture_output=True, check=True).stdout
    return answer


def field(message, offset):
    length, maximum, start = struct.unpack_from("<HHI", message, offset)
    check(length <= maximum and start + length <= len(message), "invalid NTLM field bounds")
    return message[start:start + length]


def read_http(peer):
    message = b""
    while not message.endswith(b"\r\n\r\n"):
        byte = peer.recv(1)
        if not byte and not message:
            raise EOFError("CONNECT handshake cancelled")
        check(byte and len(message) < 16384, "invalid CONNECT request")
        message += byte
    return message


def response_type2(version, malformed=False):
    name = "DOMAIN".encode("utf-16le")
    timestamp = struct.pack("<Q", int(time.time() * 10_000_000) + 116444736000000000)
    info = b"".join((struct.pack("<HH", 1, 8) + "SERVER".encode("utf-16le")[:8],
                     struct.pack("<HH", 2, len(name)) + name,
                     b"" if version in ("v2-mic-no-time", "v2-no-mic") else
                     struct.pack("<HH", 7, 8) + timestamp,
                     b"" if version == "v2-no-mic" else
                     struct.pack("<HH", 6, 4) + struct.pack("<I", 2),
                     b"\0\0\0\0"))
    if malformed == "unterminated":
        info = info[:-4]
    elif malformed == "short-av":
        info = struct.pack("<HH", 7, 8) + b"\x01"
    elif malformed == "duplicate-time":
        info = info[:-4] + struct.pack("<HH", 7, 8) + timestamp + b"\0\0\0\0"
    elif malformed == "duplicate-flags":
        info = info[:-4] + struct.pack("<HHI", 6, 4, 2) + b"\0\0\0\0"
    if version == "v2-no-info":
        info = b""
    flags = UNICODE | 0x4 | NTLM
    if version != "v2-no-sign":
        flags |= SIGN | BITS128 | KEY_EXCHANGE
    if version != "v2-no-info":
        flags |= TARGET_INFO
    if version not in ("v1-plain", "v2-no-ess"):
        flags |= ESS
    message = bytearray(48)
    message[:8] = SIGNATURE
    struct.pack_into("<I", message, 8, 2)
    struct.pack_into("<HHI", message, 12, len(name), len(name), 48)
    struct.pack_into("<I", message, 20, flags)
    message[24:32] = SERVER_CHALLENGE
    struct.pack_into("<HHI", message, 40, len(info), len(info),
                     0xffffffff if malformed == "offset" or version == "v2-no-info"
                     else 48 + len(name))
    message.extend(name + info)
    return bytes(message)


def verify_type3(type1, type2, message, version):
    check(message[:8] == SIGNATURE and struct.unpack_from("<I", message, 8)[0] == 3,
          "wrong NTLM message type")
    flags = struct.unpack_from("<I", message, 60)[0]
    check(flags & UNICODE and flags & NTLM, "missing negotiated NTLM flags")
    if version == "v2-no-sign":
        check(not flags & SIGN and not flags & KEY_EXCHANGE,
              "unexpected NTLM signing or key exchange")
    else:
        check(flags & SIGN and flags & KEY_EXCHANGE,
              "missing negotiated NTLM signing or key exchange")
    check(bool(flags & TARGET_INFO) == bool(struct.unpack_from("<I", type2, 20)[0] & TARGET_INFO),
          "Type 3 changed the negotiated target-info flag")
    vector = version == "v2-vector"
    unicode_account = version == "v2-unicode"
    domain = "Domain" if vector else ("Döm" if unicode_account else "DOMAIN")
    username = "User" if vector else ("müller" if unicode_account else "ProxyUser")
    check(field(message, 28) == domain.encode("utf-16le"), "wrong NTLM domain")
    check(field(message, 36) == username.encode("utf-16le"), "wrong NTLM username")
    check(field(message, 44) == "PI".encode("utf-16le"), "wrong NTLM workstation")
    lm, nt = field(message, 12), field(message, 20)
    hash_nt = md4("Password".encode("utf-16le"))
    if version.startswith("v2"):
        # Microsoft MS-NLMP 4.2.4.1.1 publishes this independent key vector.
        key = (bytes.fromhex("0c868a403bfd7a93a3001ef22ef02e3f") if vector else
               hmac_md5(hash_nt, (username.upper() + domain).encode("utf-16le")))
        check(len(nt) >= 48 and nt[16:18] == b"\x01\x01", "invalid NTLMv2 blob")
        check(nt[:16] == hmac_md5(key, SERVER_CHALLENGE + nt[16:]), "wrong NTLMv2 proof")
        if version in ("v2-mic-no-time", "v2-no-mic", "v2-no-info"):
            check(len(lm) == 24 and lm[:16] ==
                  hmac_md5(key, SERVER_CHALLENGE + lm[16:]),
                  "wrong LMv2 response without server timestamp")
        else:
            check(lm == b"\0" * 24, "timestamp challenge should suppress LMv2 response")
        av = nt[44:-4]
        if version in ("v2-no-mic", "v2-no-info"):
            check(struct.pack("<HHI", 6, 4, 2) not in av, "unexpected MIC AV flag")
        else:
            check(struct.pack("<HHI", 6, 4, 2) in av, "MIC AV flag missing")
        session_key = hmac_md5(key, nt[:16])
        if version not in ("v2-no-mic", "v2-no-info"):
            check(len(message) >= 88, "MIC missing")
            unsigned = bytearray(message)
            mic = bytes(unsigned[72:88])
            unsigned[72:88] = b"\0" * 16
            exported = (session_key if version == "v2-no-sign" else
                        rc4(session_key, field(message, 52)))
            check(mic == hmac_md5(exported, type1 + type2 + unsigned), "wrong NTLM MIC")
    elif version == "v1-ess":
        check(flags & ESS and len(lm) == 24 and lm[8:] == b"\0" * 16,
              "wrong NTLMv1 extended LM response")
        check(nt == des_response(hash_nt, hashlib.md5(SERVER_CHALLENGE + lm[:8]).digest()[:8]),
              "wrong NTLMv1 extended NT response")
        session_key = hmac_md5(md4(hash_nt), SERVER_CHALLENGE + lm[:8])
    else:
        check(not flags & ESS, "NTLMv1 plain negotiation ignored")
        check(nt == des_response(hash_nt, SERVER_CHALLENGE), "wrong NTLMv1 NT response")
        lm_hash = des_response(b"PASSWORD".ljust(21, b"\0"), b"KGS!@#$%")[:16]
        check(lm == des_response(lm_hash, SERVER_CHALLENGE), "wrong NTLMv1 LM response")
        session_key = md4(hash_nt)
    if version == "v2-no-sign":
        check(field(message, 52) == b"", "unexpected encrypted session key")
    else:
        check(len(field(message, 52)) == 16, "encrypted session key missing")


class NtlmProxy:
    def __init__(self, target):
        self.target = target
        self.version = "v2"
        self.malformed = False
        self.reject = False
        self.handshake_mode = "normal"
        self.initial_bare_done = False
        self.errors = []
        self.connections = 0
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.listener.settimeout(.1)
        self.stop = threading.Event()
        self.workers = []
        self.cancelling = threading.Event()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                peer, _ = self.listener.accept()
            except socket.timeout:
                continue
            self.connections += 1
            worker = threading.Thread(target=self.handle, args=(peer,))
            worker.start()
            self.workers.append(worker)

    def handle(self, peer):
        stage = "first"
        try:
            with peer:
                peer.settimeout(5)
                first = read_http(peer)
                check(first.startswith(b"CONNECT nas.test.invalid:5510 HTTP/1.1\r\n"),
                      "wrong CONNECT authority")
                prefix = b"Proxy-Authorization: NTLM "
                check(prefix in first, "missing NTLM Type 1")
                type1 = base64.b64decode(first.split(prefix, 1)[1].split(b"\r\n", 1)[0], validate=True)
                check(type1[:8] == SIGNATURE and struct.unpack_from("<I", type1, 8)[0] == 1,
                      "wrong NTLM Type 1")
                if self.handshake_mode == "bare":
                    peer.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                                 b"Proxy-Authenticate: NTLM\r\nContent-Length: 2\r\n\r\nno")
                    first = read_http(peer)
                    check(prefix in first, "missing repeated NTLM Type 1")
                    type1 = base64.b64decode(
                        first.split(prefix, 1)[1].split(b"\r\n", 1)[0], validate=True)
                if self.handshake_mode == "bare-close" and not self.initial_bare_done:
                    self.initial_bare_done = True
                    peer.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                                 b"Proxy-Authenticate: NTLM\r\nConnection: close\r\n\r\n")
                    return
                type2 = response_type2(self.version, self.malformed)
                body = (b"Transfer-Encoding: chunked\r\n\r\n3\r\nxyz\r\n0\r\n"
                        b"X-Test: y\r\n\r\n" if self.handshake_mode == "chunked" else
                        b"Content-Length: 3\r\n\r\nxyz")
                encoded = b"!!!!" if self.malformed == "base64" else base64.b64encode(type2)
                auth_headers = b"Proxy-Authenticate: NTLM " + encoded + b"\r\n"
                if self.handshake_mode == "mixed":
                    auth_headers = (b'Proxy-Authenticate: Digest realm="zone \\"NTLM\\""\r\n'
                                    b'Proxy-Authenticate: Basic realm="corporate NTLM, east", NTLM '
                                    + encoded + b"\r\n")
                if self.handshake_mode == "quoted-basic":
                    auth_headers = b'Proxy-Authenticate: Basic realm="corporate NTLM"\r\n'
                peer.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                             + auth_headers + (b"Connection: close\r\n" if
                                       self.handshake_mode == "type2-close" else b"") + body)
                if self.malformed or self.handshake_mode in ("type2-close", "quoted-basic"):
                    return
                stage = "second"
                second = read_http(peer)
                check(prefix in second, "missing NTLM Type 3")
                type3 = base64.b64decode(second.split(prefix, 1)[1].split(b"\r\n", 1)[0], validate=True)
                verify_type3(type1, type2, type3, self.version)
                if self.reject:
                    peer.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                    return
                peer.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                with socket.create_connection(("127.0.0.1", self.target), timeout=peer.gettimeout()) as upstream:
                    relay(peer, upstream, self.stop)
        except (ConnectionResetError, BrokenPipeError):
            pass
        except EOFError as error:
            if not self.cancelling.is_set():
                self.errors.append(f"{stage}: {error!r}")
        except Exception as error:
            self.errors.append(f"{stage} version={self.version} malformed={self.malformed} reject={self.reject}: {error!r}")

    def close(self):
        self.stop.set()
        self.thread.join()
        self.listener.close()
        for worker in self.workers:
            worker.join()


with tempfile.TemporaryDirectory(prefix="opensabba-ntlm-") as temporary:
    root = Path(temporary)
    cert, key = root / "cert.pem", root / "key.pem"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
                    "-days", "1", "-keyout", str(key), "-out", str(cert),
                    "-subj", "/CN=nas.test.invalid", "-addext",
                    "subjectAltName=DNS:nas.test.invalid"], check=True, capture_output=True)
    nas = Nas(cert, key)
    nas.allow_client_disconnect = True
    proxy = NtlmProxy(nas.port)
    env = dict(os.environ, XDG_CONFIG_HOME=str(root / "config"), TZ="CET-1")

    def cli(*args, expected=0):
        result = subprocess.run([exe, *args], env=env,
                                input="test-password-742\n123456\nPassword\n", text=True,
                                capture_output=True, timeout=10)
        check(result.returncode == expected, result.stdout + result.stderr)
        check("Password" not in result.stdout + result.stderr, "proxy secret leaked")
        return result

    options = ["--proxy-address", "127.0.0.1", "--proxy-port", str(proxy.port),
               "--ca-file", str(cert), "--proxy-auth", "ntlm", "--proxy-username", "ProxyUser",
               "--proxy-domain", "DOMAIN", "--proxy-workstation", "PI", "--proxy-password-fd", "0"]
    try:
        login = ["--connect", "--address", "nas.test.invalid", "--username", "test-user", "--password-fd", "0",
                 "--otp-fd", "0", "--quiet"]
        for version in ("v2", "v2-vector", "v2-no-ess", "v2-no-sign", "v2-unicode",
                        "v2-mic-no-time", "v2-no-mic", "v2-no-info",
                        "v1-ess", "v1-plain"):
            proxy.version = version
            opts = options + (["--proxy-ntlm-version", "1"] if version.startswith("v1") else [])
            if version == "v2-vector":
                opts[opts.index("--proxy-username") + 1] = "User"
                opts[opts.index("--proxy-domain") + 1] = "Domain"
            if version == "v2-unicode":
                opts[opts.index("--proxy-username") + 1] = "müller"
                opts[opts.index("--proxy-domain") + 1] = "Döm"
            cli(*login, *opts)
            if version not in ("v2-vector", "v2-unicode"):
                cli("probe")
            check(not cli("--status", expected=2).stdout, "no-daemon status printed saved metadata")
            check(not proxy.errors, str(proxy.errors))
        proxy.version = "v2"
        qualified = options.copy()
        domain_pos = qualified.index("--proxy-domain")
        del qualified[domain_pos:domain_pos + 2]
        qualified[qualified.index("--proxy-username") + 1] = "DOMAIN\\ProxyUser"
        cli(*login, *qualified)
        cli("probe")
        cli(*login, *options)
        cli("reconnect")
        before_service = proxy.connections
        before_auth = sum(request["action"] == "auth" for request in nas.requests)
        service = subprocess.Popen([exe, "service", "run"], env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            wait_for(lambda: proxy.connections > before_service and
                     sum(request["action"] == "auth" for request in nas.requests) > before_auth,
                     "NTLM service did not authenticate through the proxy")
        finally:
            proxy.cancelling.set()
            service.terminate()
            out, err = service.communicate(timeout=5)
            for worker in proxy.workers:
                worker.join(5)
            proxy.cancelling.clear()
        check(service.returncode == 0 and "Password" not in out + err, out + err)
        report = root / "diagnostics.zip"
        cli("--export-log", "--output-file", str(report))
        with zipfile.ZipFile(report) as archive:
            contents = archive.read("diagnostics.json")
        check(b"Password" not in contents, "NTLM password leaked in diagnostics")
        for mode in ("bare", "bare-close", "chunked", "mixed"):
            proxy.handshake_mode = mode
            proxy.initial_bare_done = False
            cli("probe")
            check(not proxy.errors, str(proxy.errors))
        proxy.handshake_mode = "normal"
        session = root / "config/opensabba/session.pstream"
        saved = session.read_bytes()
        before = len(nas.requests)
        proxy.version = "v2"
        proxy.reject = True
        cli(*login, *options, expected=3)
        check(session.read_bytes() == saved and len(nas.requests) == before,
              "rejected NTLM CONNECT changed saved session or reached NAS")
        proxy.reject = False
        for malformed, diagnostic in (
                ("offset", "invalid NTLM challenge field"),
                ("unterminated", "unterminated NTLM target info"),
                ("short-av", "invalid NTLM target info"),
                ("duplicate-time", "invalid NTLM timestamp"),
                ("duplicate-flags", "invalid NTLM AV flags"),
                ("base64", "invalid NTLM proxy challenge encoding")):
            proxy.malformed = malformed
            rejected = cli(*login, *options, expected=3)
            check(diagnostic in rejected.stderr, rejected.stderr)
            check(session.read_bytes() == saved and len(nas.requests) == before,
                  "malformed NTLM challenge changed saved session or reached NAS")
        proxy.malformed = False
        proxy.handshake_mode = "quoted-basic"
        rejected = cli(*login, *options, expected=3)
        check("did not offer NTLM" in rejected.stderr, rejected.stderr)
        check(session.read_bytes() == saved and len(nas.requests) == before,
              "quoted Basic realm triggered NTLM or reached NAS")
        proxy.handshake_mode = "type2-close"
        rejected = cli(*login, *options, expected=3)
        check("closed NTLM challenge connection" in rejected.stderr, rejected.stderr)
        check(session.read_bytes() == saved and len(nas.requests) == before,
              "closed Type 2 connection changed saved session or reached NAS")
        key = b"proxy_ntlm_version"
        marker = b"\x10" + len(key).to_bytes(2, "big") + key + b"\x01\x01\x02"
        check(saved.count(marker) == 1, "saved NTLM version marker not unique")
        corrupt = saved.replace(marker, b"\x10" + len(key).to_bytes(2, "big") +
                                key + b"\x01\x08" + (4294967297).to_bytes(8, "big"))
        session.write_bytes(corrupt)
        try:
            result = cli("reconnect", expected=1)
            check("invalid saved NTLM version" in result.stderr, result.stderr)
            check(session.read_bytes() == corrupt, "malformed saved session was rewritten")
        finally:
            session.write_bytes(saved)
        check(not proxy.errors and not nas.errors, str(proxy.errors + nas.errors))
        print("PASS NTLMv2 MIC/key exchange, NTLMv1 extended/plain, affinity and rejection")
    finally:
        proxy.close()
        nas.close()
