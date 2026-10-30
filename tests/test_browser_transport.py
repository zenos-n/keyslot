"""Real pinned browser crypto/transport, checked against independent libsodium."""
import base64
import ctypes
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import tempfile
import time
import unittest

BRIDGE = os.environ.get('KEYSLOT_BROWSER_BRIDGE')
PROXY = os.environ.get('KEYSLOT_BROWSER_PROXY')
UPSTREAM_PROXY = os.environ.get('KEYSLOT_BROWSER_PROXY_UPSTREAM')
SODIUM = os.environ.get('KEYSLOT_TEST_SODIUM')
if not all((BRIDGE, PROXY, UPSTREAM_PROXY, SODIUM)):
    if os.environ.get('KEYSLOT_REQUIRE_ENGINE') == '1':
        raise RuntimeError('Native browser bridge, upstream proxy and libsodium are required by package checks')
    raise unittest.SkipTest('Build the browser transport and supply its test paths')


def b64(value):
    return base64.b64encode(value).decode('ascii')


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


def read_bytes(stream, count, timeout=3):
    result = b''
    deadline = time.monotonic() + timeout
    descriptor = stream if isinstance(stream, int) else stream.fileno()
    while len(result) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
            raise AssertionError('Browser transport timed out')
        data = os.read(descriptor, count - len(result))
        if not data:
            raise AssertionError('Browser transport closed early')
        result += data
    return result


class Crypto:
    def __init__(self):
        self.lib = ctypes.CDLL(SODIUM)
        self.lib.sodium_init()
        self.lib.crypto_box_keypair.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        signature = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong,
                     ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self.lib.crypto_box_easy.argtypes = signature
        self.lib.crypto_box_open_easy.argtypes = signature
        public, secret = ctypes.create_string_buffer(32), ctypes.create_string_buffer(32)
        assert self.lib.crypto_box_keypair(public, secret) == 0
        self.public, self.secret = public.raw, secret.raw
        self.server = None

    def encrypt(self, body, nonce):
        message = encoded(body)
        output = ctypes.create_string_buffer(len(message) + 16)
        assert self.lib.crypto_box_easy(output, message, len(message), nonce, self.server, self.secret) == 0
        return b64(output.raw)

    def decrypt(self, response, success='true'):
        ciphertext = base64.b64decode(response['message'], validate=True)
        nonce = base64.b64decode(response['nonce'], validate=True)
        output = ctypes.create_string_buffer(len(ciphertext) - 16)
        assert self.lib.crypto_box_open_easy(output, ciphertext, len(ciphertext), nonce, self.server, self.secret) == 0
        body = json.loads(output.raw)
        assert body['nonce'] == response['nonce'] and body['version'] == '2.7.12' and body['success'] == success
        return body


class BrowserTransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ks-browser-', dir='/tmp')
        self.directory = Path(self.temporary.name)
        self.environment = os.environ.copy()
        self.environment['XDG_RUNTIME_DIR'] = str(self.directory)
        self.processes, self.sockets = [], []
        self.addCleanup(self.cleanup)
        self.bridge = self.spawn(BRIDGE)
        ready = self.event()
        self.assertEqual(ready['event'], 'ready')
        self.endpoint = Path(ready['socket'])
        self.assertEqual(self.endpoint.stat().st_mode & 0o077, 0)
        self.assertEqual(self.endpoint.stat().st_mode & 0o600, 0o600)

    def spawn(self, executable):
        process = subprocess.Popen([executable], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=0, env=self.environment)
        self.processes.append(process)
        return process

    def cleanup(self):
        for client in self.sockets:
            client.close()
        for process in reversed(self.processes):
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
            process.stdin = None
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
        self.temporary.cleanup()

    def event(self):
        data = b''
        while not data.endswith(b'\n'):
            data += read_bytes(self.bridge.stdout, 1)
        return json.loads(data)

    def answer(self, event, result=None, **fields):
        response = dict(id=event['id'], **fields)
        if result is not None:
            response['result'] = result
        self.bridge.stdin.write(encoded(response) + b'\n')
        self.bridge.stdin.flush()

    def client(self):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sockets.append(client)
        client.settimeout(3)
        client.connect(str(self.endpoint))
        return client

    def response(self, client):
        data = b''
        while True:
            data += client.recv(65536)
            if not data:
                raise AssertionError('Browser socket closed before response')
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                if len(data) > 1024 * 1024:
                    raise

    def handshake(self, client, identity='fixture', crypto=None):
        crypto = crypto or Crypto()
        nonce = os.urandom(24)
        message = dict(action='change-public-keys', clientID=identity, nonce=b64(nonce), publicKey=b64(crypto.public))
        client.sendall(encoded(message))
        response = self.response(client)
        crypto.server = base64.b64decode(response['publicKey'], validate=True)
        self.assertEqual(base64.b64decode(response['nonce']), ((int.from_bytes(nonce, 'little') + 1) % (1 << 192)).to_bytes(24, 'little'))
        return crypto

    def request(self, crypto, action='get-logins', identity='fixture', nonce=None, **fields):
        nonce = nonce or os.urandom(24)
        return dict(action=action, clientID=identity, nonce=b64(nonce),
                    message=crypto.encrypt(dict(action=action, **fields), nonce))

    def test_independent_crypto_roundtrip_and_replay_rejection(self):
        client = self.client()
        crypto = self.handshake(client)
        request = self.request(crypto, url='https://fixture.invalid', keys=[])
        client.sendall(encoded(request))
        event = self.event()
        self.assertEqual(event['body']['url'], 'https://fixture.invalid')
        self.assertEqual(event['public_key'], b64(crypto.public))
        self.answer(event, {'entries': [{'login': 'fixture-user', 'password': 'public fixture secret'}]})
        response = self.response(client)
        self.assertEqual(crypto.decrypt(response)['entries'][0]['password'], 'public fixture secret')
        client.sendall(encoded(request))
        self.assertEqual(self.response(client)['errorCode'], '4')

    def test_malformed_key_nonce_ciphertext_and_action_fail_closed(self):
        client = self.client()
        client.sendall(encoded(dict(action='change-public-keys', clientID='fixture', nonce=b64(os.urandom(24)), publicKey=b64(b'short'))))
        self.assertEqual(self.response(client)['errorCode'], '3')
        crypto = self.handshake(client)
        for nonce, message in [('bad', 'bad'), (b64(os.urandom(24)), b64(b'tiny')),
                               (b64(os.urandom(24)), b64(os.urandom(64)))]:
            client.sendall(encoded(dict(action='get-logins', clientID='fixture', nonce=nonce, message=message)))
            self.assertEqual(self.response(client)['errorCode'], '4')
        request = self.request(crypto, action='get-logins')
        request['action'] = 'set-login'
        client.sendall(encoded(request))
        self.assertEqual(self.response(client)['errorCode'], '4')
        self.assertIsNone(self.bridge.poll())

    def test_fragmented_frames_and_connection_key_isolation(self):
        first, second = self.client(), self.client()
        crypto = self.handshake(first)
        other = self.handshake(second)
        request = self.request(crypto, url='https://first.invalid')
        second.sendall(encoded(request))
        self.assertEqual(self.response(second)['errorCode'], '4')
        frame = encoded(request)
        first.sendall(frame[:7])
        first.sendall(frame[7:])
        event = self.event()
        self.assertEqual(event['body']['url'], 'https://first.invalid')
        self.answer(event, {'entries': []})
        self.assertEqual(crypto.decrypt(self.response(first))['entries'], [])
        second.sendall(encoded(self.request(other, url='https://second.invalid')))
        event2 = self.event()
        self.assertNotEqual(event['connection'], event2['connection'])
        self.answer(event2, error_code=6)
        self.assertEqual(self.response(second)['errorCode'], '6')

    def test_rekey_cancels_pending_request_and_discards_late_reply(self):
        client = self.client()
        crypto = self.handshake(client)
        client.sendall(encoded(self.request(crypto)))
        old = self.event()
        crypto = self.handshake(client)
        cancelled = self.event()
        self.assertEqual(cancelled, {'event': 'cancel', 'id': old['id']})
        self.answer(old, {'password': 'must not be sent'})
        self.assertFalse(select.select([client], [], [], .1)[0])
        client.sendall(encoded(self.request(crypto)))
        event = self.event()
        self.assertEqual(old['generation'], '1')
        self.assertEqual(event['generation'], '2')
        self.answer(event, {'entries': []})
        self.assertEqual(crypto.decrypt(self.response(client))['entries'], [])

    def test_upstream_proxy_native_framing_interoperability(self):
        for executable in (PROXY, UPSTREAM_PROXY):
            proxy = self.spawn(executable)
            crypto = Crypto()
            def send(message):
                data = encoded(message)
                proxy.stdin.write(struct.pack('<I', len(data)) + data)
                proxy.stdin.flush()
            def receive():
                length = struct.unpack('<I', read_bytes(proxy.stdout, 4))[0]
                self.assertLess(length, 1024 * 1024)
                return json.loads(read_bytes(proxy.stdout, length))
            send(dict(action='change-public-keys', clientID='fixture', nonce=b64(os.urandom(24)), publicKey=b64(crypto.public)))
            crypto.server = base64.b64decode(receive()['publicKey'])
            send(self.request(crypto, action='get-databasehash'))
            event = self.event()
            self.answer(event, {'hash': 'public fixture hash'})
            self.assertEqual(crypto.decrypt(receive())['hash'], 'public fixture hash')

    def test_endpoint_is_not_replaced_and_parent_eof_cleans_up(self):
        second = self.spawn(BRIDGE)
        second.stdin.close()
        second.stdin = None
        second.communicate(timeout=3)
        self.assertEqual(second.returncode, 2)
        self.assertTrue(self.endpoint.exists())
        client = self.client()
        self.handshake(client)
        self.bridge.stdin.close()
        self.bridge.stdin = None
        self.bridge.communicate(timeout=3)
        self.assertEqual(self.bridge.returncode, 0)
        self.assertFalse(self.endpoint.exists())
        self.assertFalse(self.endpoint.is_symlink())

    def test_shutdown_preserves_a_later_stock_endpoint(self):
        self.endpoint.unlink()
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sockets.append(replacement)
        replacement.bind(str(self.endpoint))
        replacement.listen(1)
        identity = self.endpoint.stat().st_ino
        self.bridge.stdin.close()
        self.bridge.stdin = None
        self.bridge.communicate(timeout=3)
        self.assertEqual(self.bridge.returncode, 0)
        self.assertEqual(self.endpoint.stat().st_ino, identity)
        self.client()
        connection, _ = replacement.accept()
        connection.close()

    def test_state_notifications_are_fixed_public_actions_and_broadcast_to_clients(self):
        clients = [self.client(), self.client()]
        for client in clients:
            self.handshake(client)
        for notification in ("database-locked", "database-unlocked"):
            self.bridge.stdin.write(encoded({"notification": notification}) + b'\n')
            self.bridge.stdin.flush()
            for client in clients:
                self.assertEqual(self.response(client), {"action": notification})
        for invalid in ({"notification": "private-data"},
                        {"notification": "database-locked", "password": "public forbidden fixture"}):
            self.bridge.stdin.write(encoded(invalid) + b'\n')
            self.bridge.stdin.flush()
        self.assertFalse(select.select(clients, [], [], .1)[0])

    def test_only_delete_entry_can_return_a_boolean_success_string(self):
        client = self.client()
        crypto = self.handshake(client)
        for action, result, allowed in [('delete-entry', {'success': 'false'}, True),
                                        ('delete-entry', {'success': 'true'}, True),
                                        ('delete-entry', {'success': False}, False),
                                        ('delete-entry', {'success': 'unexpected'}, False),
                                        ('get-logins', {'success': 'false'}, False)]:
            with self.subTest(action=action, result=result):
                client.sendall(encoded(self.request(crypto, action=action)))
                self.answer(self.event(), result)
                response = self.response(client)
                if allowed:
                    self.assertEqual(crypto.decrypt(response, success=result['success'])['success'], result['success'])
                else:
                    self.assertEqual(response['errorCode'], '7')

    def test_passkey_timeout_cancels_pending_request_and_ignores_late_result(self):
        client = self.client()
        crypto = self.handshake(client)
        client.sendall(encoded(self.request(crypto, action='passkeys-get', publicKey={'timeout': 1000})))
        event = self.event()
        cancelled = self.event()
        self.assertEqual(cancelled, {'event': 'cancel', 'id': event['id']})
        self.assertEqual(crypto.decrypt(self.response(client))['response'], {'errorCode': 22})
        self.answer(event, {'response': {'signature': 'must not be released'}})
        self.assertFalse(select.select([client], [], [], .1)[0])

    def fake_server(self):
        self.bridge.stdin.close()
        self.bridge.stdin = None
        self.bridge.communicate(timeout=3)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sockets.append(server)
        server.bind(str(self.endpoint))
        server.listen(2)
        server.settimeout(3)
        return server

    def test_packaged_proxy_splits_coalesced_and_fragmented_json_messages(self):
        server = self.fake_server()
        proxy = self.spawn(PROXY)
        client, _ = server.accept()
        self.sockets.append(client)
        first = {'action': 'fixture', 'text': 'braces } { and escaped " \\', 'array': [{'unicode': 'café 🚀'}]}
        second = {'action': 'database-locked'}
        third = {'action': 'fixture', 'nested': {'value': [1, 2, 3]}}
        frame = json.dumps(first, ensure_ascii=False).encode()
        client.sendall(frame[:11])
        self.assertFalse(select.select([proxy.stdout], [], [], .1)[0], 'An incomplete socket message was framed')
        client.sendall(frame[11:] + b' \r\n\t' + encoded(second) + encoded(third))
        for expected in (first, second, third):
            size = struct.unpack('<I', read_bytes(proxy.stdout, 4))[0]
            self.assertEqual(json.loads(read_bytes(proxy.stdout, size)), expected)

    def test_packaged_proxy_rejects_malformed_deep_or_oversize_socket_messages(self):
        server = self.fake_server()
        for message in (b'[]', b'{"x":1]', b'{"x":' + b'[' * 65,
                        b'{"x":"' + b'x' * (1024 * 1024)):
            with self.subTest(size=len(message)):
                proxy = self.spawn(PROXY)
                client, _ = server.accept()
                self.sockets.append(client)
                client.settimeout(3)
                client.sendall(message)
                self.assertEqual(client.recv(1), b'')
                proxy.stdin.close()
                proxy.stdin = None
                output, _ = proxy.communicate(timeout=3)
                self.assertEqual(output, b'')
                self.assertEqual(proxy.returncode, 2)
