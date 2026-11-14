"""Independent loopback HTTP CONNECT relay used by integration tests."""
import base64
import errno
import select
import socket
import threading
from test_probe import check


def relay(peer, upstream, stop):
    """Forward with bounded buffers and cancellable backpressure in both directions."""
    sockets = (peer, upstream)
    for connection in sockets:
        connection.setblocking(False)
    pending = {connection: bytearray() for connection in sockets}
    readers = set(sockets)
    ending = set()
    limit = 65536
    while not stop.is_set():
        for connection in tuple(ending):
            if not pending[connection]:
                try:
                    connection.shutdown(socket.SHUT_WR)
                except OSError as error:
                    if error.errno != errno.ENOTCONN:
                        raise
                    # The endpoint already disconnected entirely; it has nothing left to send.
                    readers.discard(connection)
                ending.remove(connection)
        if not readers and not any(pending.values()):
            return
        readable, writable, _ = select.select(
            [connection for connection in sockets
             if connection in readers and len(pending[upstream if connection is peer else peer]) < limit],
            [connection for connection in sockets if pending[connection]], [], .1)
        for destination in writable:
            try:
                sent = destination.send(pending[destination])
            except BlockingIOError:
                continue
            del pending[destination][:sent]
        for source in readable:
            destination = upstream if source is peer else peer
            try:
                data = source.recv(limit - len(pending[destination]))
            except BlockingIOError:
                continue
            if data:
                pending[destination].extend(data)
            else:
                readers.remove(source)
                ending.add(destination)


class Proxy:
    def __init__(self, port):
        self.target = port
        self.response = b"HTTP/1.1 200 Connection established\r\n\r\n"
        self.authority = b"nas.test.invalid:5510"
        self.credentials = None
        self.requests = []
        self.errors = []
        self.respond = threading.Event()
        self.respond.set()
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.listener.settimeout(.1)
        self.workers = []
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                peer, _ = self.listener.accept()
            except socket.timeout:
                continue
            worker = threading.Thread(target=self.handle, args=(peer,))
            self.workers.append(worker)
            worker.start()

    def handle(self, peer):
        try:
            with peer:
                peer.settimeout(3)
                request = b""
                while not request.endswith(b"\r\n\r\n"):
                    byte = peer.recv(1)
                    check(byte and len(request) < 4096, "invalid CONNECT request")
                    request += byte
                self.requests.append(request)
                expected = b"CONNECT "+self.authority+b" HTTP/1.1\r\nHost: "+self.authority+b"\r\n"
                if self.credentials is not None:
                    expected += b"Proxy-Authorization: Basic "+base64.b64encode(self.credentials)+b"\r\n"
                check(request == expected+b"\r\n", "wrong CONNECT authority or proxy authorization")
                response = self.response
                while not self.respond.wait(.1):
                    if self.stop.is_set():
                        return
                peer.sendall(response)
                if response not in (b"HTTP/1.1 200 Connection established\r\n\r\n",
                                    b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.0 204 \r\n\r\n"):
                    return
                with socket.create_connection(("127.0.0.1", self.target), timeout=peer.gettimeout()) as upstream:
                    relay(peer, upstream, self.stop)
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as error:
            self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        self.thread.join()
        self.listener.close()
        for worker in self.workers:
            worker.join()
