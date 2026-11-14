"""Loopback regression for proxy forwarding and shutdown under backpressure."""
import socket
import threading
import unittest

from proxy_peer import Proxy
from test_probe import exact


class ProxyPeerTests(unittest.TestCase):
    def connection(self, server):
        server.settimeout(3)
        proxy = Proxy(server.getsockname()[1])
        peer = socket.create_connection(("127.0.0.1", proxy.port), timeout=3)
        peer.sendall(b"CONNECT nas.test.invalid:5510 HTTP/1.1\r\n"
                     b"Host: nas.test.invalid:5510\r\n\r\n")
        response = b""
        while not response.endswith(b"\r\n\r\n"):
            response += exact(peer, 1)
        self.assertEqual(response, proxy.response)
        upstream, _ = server.accept()
        upstream.settimeout(3)
        return proxy, peer, upstream

    def test_bidirectional_half_close(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen()
            proxy, peer, upstream = self.connection(server)
            try:
                peer.sendall(b"request")
                peer.shutdown(socket.SHUT_WR)
                self.assertEqual(exact(upstream, 7), b"request")
                self.assertEqual(upstream.recv(1), b"")
                upstream.sendall(b"reply")
                upstream.shutdown(socket.SHUT_WR)
                self.assertEqual(exact(peer, 5), b"reply")
                self.assertEqual(peer.recv(1), b"")
            finally:
                peer.close()
                upstream.close()
                proxy.close()
            self.assertFalse(proxy.errors, proxy.errors)

    def test_shutdown_with_backpressure(self):
        for direction in ("upstream", "client"):
            with self.subTest(direction=direction), socket.socket() as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                server.bind(("127.0.0.1", 0))
                server.listen()
                proxy, peer, upstream = self.connection(server)
                sender, blocked = (peer, upstream) if direction == "upstream" else (upstream, peer)
                blocked.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
                sender.settimeout(.2)
                closed = threading.Event()

                def close():
                    proxy.close()
                    closed.set()

                closer = threading.Thread(target=close)
                try:
                    # The receiver deliberately never reads. Fill all intervening
                    # queues until the sender observes actual backpressure.
                    with self.assertRaises(socket.timeout):
                        for _ in range(320):
                            sender.sendall(bytes(65536))
                    closer.start()
                    self.assertTrue(closed.wait(2), "proxy shutdown waited for a blocked receiver")
                finally:
                    peer.close()
                    upstream.close()
                    if closer.ident is None:
                        closer.start()
                    closer.join(4)
                self.assertFalse(closer.is_alive(), "proxy worker did not exit")
                self.assertFalse(proxy.errors, proxy.errors)


if __name__ == "__main__":
    unittest.main()
