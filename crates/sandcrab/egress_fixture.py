"""Private-network DNS, TLS and echo peers for deterministic egress acceptance."""
import ctypes
import fcntl
import http.server
import os
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import threading

from native_probe import call

ADDRESS = '93.184.216.34'


def read_exact(stream, size):
    result = bytearray()
    while len(result) < size:
        value = stream.recv(size - len(result))
        if not value:
            raise EOFError()
        result.extend(value)
    return bytes(result)


class Internet:
    def __init__(self, root):
        assert len(list(Path('/proc/self/task').iterdir())) == 1
        self.original = os.readlink('/proc/self/ns/net')
        libc = ctypes.CDLL(None, use_errno=True)
        assert libc.unshare(0x40000000) == 0, ctypes.get_errno()
        self.namespace = os.readlink('/proc/self/ns/net')
        assert self.namespace != self.original
        with socket.socket() as control:
            flags = struct.unpack('16sH22x', fcntl.ioctl(control, 0x8913, struct.pack('16sH22x', b'lo', 0)))[1]
            fcntl.ioctl(control, 0x8914, struct.pack('16sH22x', b'lo', flags | 1))
            fcntl.ioctl(control, 0x8916, struct.pack('16sH2x4s16x', b'lo:1', socket.AF_INET, socket.inet_aton(ADDRESS)))
            fcntl.ioctl(control, 0x891c, struct.pack('16sH2x4s16x', b'lo:1', socket.AF_INET, socket.inet_aton('255.255.255.255')))
        self.stopped = threading.Event()
        self.queries = []
        self.servers, self.threads = [], []
        self.rebindings = 0
        self.certificate = root / 'fixture-ca.pem'
        self.key = root / 'fixture-key.pem'
        call('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
             '-subj', '/CN=allowed.example', '-addext',
             'subjectAltName=DNS:allowed.example,DNS:tcp.example,DNS:rebind.example',
             '-keyout', str(self.key), '-out', str(self.certificate))
        self.key.chmod(0o600)
        self.resolvers = root / 'resolv.conf'
        self.resolvers.write_text('nameserver 127.0.0.1\n')

        owner = self

        class Threads(socketserver.ThreadingTCPServer):
            daemon_threads = False
            block_on_close = True

        class DnsTcp(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                try:
                    size = int.from_bytes(read_exact(self.request, 2), 'big')
                    assert 12 <= size <= 512
                    response = owner.answer(read_exact(self.request, size), 'tcp')
                    if response is not None:
                        self.request.sendall(len(response).to_bytes(2, 'big') + response)
                except (OSError, EOFError):
                    pass

        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(.1)
                while not owner.stopped.is_set():
                    try:
                        data = self.request.recv(16384)
                        if not data:
                            return
                        self.request.sendall(data)
                    except TimeoutError:
                        continue
                    except OSError:
                        return

        class Http(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'sandcrab-egress-fixture\n'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(self.certificate, self.key)

        class Https(http.server.ThreadingHTTPServer):
            daemon_threads = False
            block_on_close = True

            def get_request(self):
                stream, address = super().get_request()
                stream.settimeout(2)
                try:
                    return tls.wrap_socket(stream, server_side=True), address
                except BaseException:
                    stream.close()
                    raise

        self.dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dns.bind(('127.0.0.1', 53))
        self.dns.settimeout(.1)
        for server in [Threads(('127.0.0.1', 53), DnsTcp), Threads((ADDRESS, 0), Echo), Https((ADDRESS, 0), Http)]:
            self.servers.append(server)
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05})
            thread.start()
            self.threads.append(thread)
        self.echo_port = self.servers[1].server_address[1]
        self.https_port = self.servers[2].server_address[1]
        worker = threading.Thread(target=self.udp)
        worker.start()
        self.threads.append(worker)

    def answer(self, packet, transport):
        assert 12 <= len(packet) <= 512 and packet[4:6] == b'\0\1'
        position, labels = 12, []
        while packet[position]:
            size = packet[position]
            assert size <= 63
            labels.append(packet[position + 1:position + size + 1].decode('ascii').lower())
            position += size + 1
        position += 1
        kind, klass = struct.unpack('!HH', packet[position:position + 4])
        assert klass == 1 and position + 4 == len(packet)
        name = '.'.join(labels)
        self.queries.append((name, kind, transport))
        if name == 'slow.example':
            return None
        truncated = name == 'tcp.example' and transport == 'udp'
        address = '127.0.0.1' if name == 'private.example' else ADDRESS
        if name == 'rebind.example' and kind == 1:
            self.rebindings += 1
            if self.rebindings > 1:
                address = '127.0.0.1'
        answer = b''
        if kind == 1 and not truncated:
            answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton(address)
        return (packet[:2] + struct.pack('!HHHHH', 0x8380 if truncated else 0x8180, 1, bool(answer), 0, 0)
                + packet[12:] + answer)

    def udp(self):
        while not self.stopped.is_set():
            try:
                data, peer = self.dns.recvfrom(513)
                answer = self.answer(data, 'udp')
                if answer is not None:
                    self.dns.sendto(answer, peer)
            except TimeoutError:
                continue
            except OSError:
                if not self.stopped.is_set():
                    raise

    def close(self):
        self.stopped.set()
        self.dns.close()
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=4)
            assert not thread.is_alive()
        assert os.readlink('/proc/self/ns/net') == self.namespace
