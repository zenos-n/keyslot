"""Native SSH key/settings/ownership lifecycle against disposable agents only."""
import base64
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from keyslot.core_backend import Vault, EngineError
from keyslot.backend import VaultError
from keyslot.ssh_agent import SSHAgentManager

ENGINE = shutil.which(os.environ.get("KEYSLOT_ENGINE", "keyslot-engine"))
AGENT, KEYGEN, ADD = (shutil.which(name) for name in ("ssh-agent", "ssh-keygen", "ssh-add"))
RELAY = str(Path(ENGINE).parent / "keyslot-ssh-agent") if ENGINE else None
if os.environ.get("KEYSLOT_REQUIRE_ENGINE") == "1" and not all((ENGINE, AGENT, KEYGEN, ADD, RELAY and Path(RELAY).is_file())):
    raise RuntimeError("The package must supply the native SSH relay and disposable OpenSSH test tools")


def eventually(predicate, seconds=4):
    end = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() >= end:
            raise AssertionError("The disposable SSH agent did not reach the expected state")
        time.sleep(.025)


class FakeAgent:
    """Protocol peer for deterministic delayed-add/refusal tests; no actual user agent."""
    def __init__(self, path, public):
        self.path, self.public = path, public
        self.keys = set()
        self.add_started, self.allow_add = threading.Event(), threading.Event()
        self.remove_started, self.allow_remove = threading.Event(), threading.Event()
        self.allow_add.set()
        self.allow_remove.set()
        self.refuse_add = self.refuse_remove = False
        self.fail_list = self.fail_list_after_remove = False
        self.add_during_remove = None
        self.running = True
        self.server = socket.socket(socket.AF_UNIX)
        self.server.bind(str(path))
        self.server.listen()
        self.server.settimeout(.1)
        self.clients, self.workers = [], []
        self.worker = threading.Thread(target=self.serve, daemon=True)
        self.worker.start()

    @staticmethod
    def read(stream, size):
        result = b""
        while len(result) < size:
            data = stream.recv(size - len(result))
            if not data:
                raise EOFError()
            result += data
        return result

    def serve(self):
        while self.running:
            try:
                stream, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.clients.append(stream)
            worker = threading.Thread(target=self.handle, args=(stream,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def handle(self, stream):
        try:
            size = struct.unpack(">I", self.read(stream, 4))[0]
            assert size <= 1024 * 1024
            request = self.read(stream, size)
            if request[0] == 11:
                response = b"\x0c" + struct.pack(">I", len(self.keys))
                for key in list(self.keys):
                    response += struct.pack(">I", len(key)) + key + struct.pack(">I", 7) + b"fixture"
                if self.fail_list:
                    response = b"\x05"
            elif request[0] in (17, 25):
                self.add_started.set()
                self.allow_add.wait(4)
                if not self.refuse_add:
                    self.keys.add(self.public)
                response = b"\x05" if self.refuse_add else b"\x06"
            elif request[0] == 18:
                self.remove_started.set()
                self.allow_remove.wait(4)
                if not self.refuse_remove:
                    length = struct.unpack(">I", request[1:5])[0]
                    self.keys.discard(request[5:5 + length])
                if self.add_during_remove:
                    self.keys.add(self.add_during_remove)
                    self.add_during_remove = None
                response = b"\x05" if self.refuse_remove else b"\x06"
                if self.fail_list_after_remove:
                    self.fail_list = True
            else:
                response = b"\x05"
            stream.sendall(struct.pack(">I", len(response)) + response)
        except (OSError, EOFError):
            pass
        finally:
            stream.close()

    def close(self):
        self.running = False
        self.allow_add.set()
        self.allow_remove.set()
        self.server.close()
        for stream in self.clients:
            try:
                stream.close()
            except OSError:
                pass
        self.worker.join(timeout=1)
        for worker in self.workers:
            worker.join(timeout=1)


@unittest.skipUnless(ENGINE and AGENT and KEYGEN and ADD, "Build the SSH helper and supply OpenSSH")
class SSHAgentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ks-ssh-test-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.socket = self.root / "agent"
        self.decision = self.root / "decision"
        self.decision.write_text("deny\n")
        self.asked = self.root / "asked"
        askpass = self.root / "askpass"
        # TemporaryDirectory names contain no shell metacharacters; fixtures contain no user secrets.
        askpass.write_text(f'#!/bin/sh\nprintf "asked\\n" >> "{self.asked}"\nread answer < "{self.decision}"\n'
                           'if [ "$answer" = allow ]; then printf "yes\\n"; exit 0; fi\nexit 1\n')
        askpass.chmod(0o700)
        self.environment = os.environ | {"SSH_AUTH_SOCK": str(self.socket), "SSH_ASKPASS": str(askpass),
            "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": ":keyslot-fixture"}
        self.agent = subprocess.Popen([AGENT, "-D", "-a", str(self.socket)], env=self.environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.addCleanup(self.stop_agent)
        eventually(self.socket.exists)
        self.manager = SSHAgentManager(RELAY)
        self.addCleanup(self.manager.close)
        self.vault = Vault(ENGINE)
        self.addCleanup(self.vault.lock)
        self.path = self.root / "fixture.kdbx"
        self.vault.create(self.path, "public SSH vault master")
        self.vault.ssh_configure(self.manager, socket=str(self.socket))

    def stop_agent(self):
        if self.agent.poll() is None:
            self.agent.terminate()
            self.agent.wait(timeout=3)

    def key(self, kind="ed25519", password="public SSH key passphrase", name="key"):
        path = self.root / name
        command = [KEYGEN, "-q", "-t", kind, "-N", password, "-C", "public fixture", "-f", str(path)]
        if kind == "rsa":
            command += ["-b", "2048"]
        subprocess.run(command, check=True, capture_output=True)
        return path

    def entry(self, uuid=None):
        return next(e for e in self.vault.snapshot.entries if e.uuid == uuid) if uuid else self.vault.snapshot.entries[0]

    def configure(self, source, password="public SSH key passphrase", attachment=False, **options):
        self.vault.save_entry(self.vault.snapshot.root, "SSH login", "alice", "", "Keep notes", password)
        entry = self.vault.snapshot.entries[-1]
        if attachment:
            self.vault.import_attachment(entry, source)
            entry = self.entry(entry.uuid)
        self.vault.save_ssh_settings(entry, enabled=True, source_type="attachment" if attachment else "file",
            attachment=source.name if attachment else "", file="" if attachment else str(source), remove_on_lock=True, **options)
        return self.entry(entry.uuid)

    def loaded(self):
        result = subprocess.run([ADD, "-L"], env=self.environment, capture_output=True, text=True, timeout=5)
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return result.stdout.splitlines() if result.returncode == 0 else []

    def sign(self, key, expect_success=True):
        message = b"public independent SSH signature challenge"
        result = subprocess.run([KEYGEN, "-Y", "sign", "-U", "-f", str(key) + ".pub", "-n", "keyslot-test"],
            env=self.environment, input=message, capture_output=True, timeout=5)
        if not expect_success:
            self.assertNotEqual(result.returncode, 0)
            return
        self.assertEqual(result.returncode, 0, result.stderr)
        signature, allowed = self.root / "signature", self.root / "allowed"
        signature.write_bytes(result.stdout)
        allowed.write_text("alice " + Path(str(key) + ".pub").read_text())
        verified = subprocess.run([KEYGEN, "-Y", "verify", "-f", str(allowed), "-I", "alice", "-n", "keyslot-test", "-s", str(signature)],
            input=message, capture_output=True, timeout=5)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        tampered = subprocess.run([KEYGEN, "-Y", "verify", "-f", str(allowed), "-I", "alice", "-n", "keyslot-test", "-s", str(signature)],
            input=message + b"tampered", capture_output=True, timeout=5)
        self.assertNotEqual(tampered.returncode, 0)

    def test_encrypted_file_and_attachment_keys_sign_via_real_agent_and_lock_removes_them(self):
        for index, kind in enumerate(("ed25519", "rsa", "ecdsa")):
            with self.subTest(kind=kind):
                key = self.key(kind, name="key" + str(index))
                entry = self.configure(key, attachment=index % 2 == 1)
                review = self.vault.ssh_prepare(entry)
                self.assertNotIn("PRIVATE KEY", json.dumps(review))
                self.assertNotIn("public SSH key passphrase", json.dumps(review))
                self.assertTrue(self.vault.ssh_add(review["token"], approved=True)["added"])
                self.sign(key)
        self.assertEqual(len(self.loaded()), 3)
        self.vault.lock()
        self.assertEqual(self.loaded(), [])
        self.assertTrue(self.manager.status()["cleanup_ok"])

    def test_settings_use_upstream_utf16_attachment_and_preserve_other_data(self):
        key = self.key()
        entry = self.configure(key, auto_add=True, confirm=True, lifetime=True, seconds=600)
        settings = self.vault.ssh_settings(entry)
        self.assertTrue(all(settings[name] for name in ("enabled", "auto_add", "confirm", "lifetime", "remove_on_lock")))
        xml = self.root / "settings.xml"
        self.vault.export_attachment(entry, "KeeAgent.settings", xml)
        text = xml.read_bytes().decode("utf-16")
        self.assertIn("<AddAtDatabaseOpen>true</AddAtDatabaseOpen>", text)
        self.assertIn("<LifetimeConstraintDuration>600</LifetimeConstraintDuration>", text)
        self.assertEqual((entry.username, entry.notes, self.vault.attribute(entry)), ("alice", "Keep notes", "public SSH key passphrase"))
        self.vault.ssh_configure(None)
        public = self.vault.ssh_key_info(entry)
        self.assertTrue(public["fingerprint"].startswith("SHA256:"))
        self.assertTrue(public["md5"].startswith("MD5:"))
        self.assertNotIn("PRIVATE KEY", json.dumps(public))
        self.assertEqual(public["public_key"].split()[:2], Path(str(key) + ".pub").read_text().split()[:2])
        self.vault.lock()
        self.vault.unlock(self.path, "public SSH vault master")
        self.assertEqual(self.vault.ssh_settings(self.entry()), settings)

    def test_cancel_replay_stale_database_and_cross_vault_tokens_do_not_add_keys(self):
        entry = self.configure(self.key())
        self.vault.save_ssh_settings(entry, enabled=False, auto_add=False, remove_on_lock=False)
        entry = self.entry()
        review = self.vault.ssh_prepare(entry)
        self.assertTrue(self.vault.ssh_add(review["token"])["cancelled"])
        with self.assertRaises(EngineError):
            self.vault.ssh_add(review["token"], approved=True)
        review = self.vault.ssh_prepare(entry)
        self.vault.save_ssh_settings(entry, seconds=601)
        with self.assertRaises(EngineError):
            self.vault.ssh_add(review["token"], approved=True)
        self.assertEqual(self.loaded(), [])
        other = Vault(ENGINE)
        self.addCleanup(other.lock)
        other.create(self.root / "other.kdbx", "public other master")
        other.ssh_configure(self.manager, socket=str(self.socket))
        with self.assertRaises(EngineError):
            other.ssh_add(review["token"], approved=True)
        with self.assertRaises(VaultError):
            other.ssh_settings(entry)

    def test_preexisting_external_key_is_not_adopted_and_other_vault_ownership_is_enforced(self):
        key = self.key(password="")
        subprocess.run([ADD, str(key)], env=self.environment, check=True, capture_output=True)
        entry = self.configure(key, password="")
        review = self.vault.ssh_prepare(entry)
        self.assertTrue(review["loaded"])
        self.assertEqual(self.vault.ssh_add(review["token"], approved=True), {"added": False, "existing": True, "owned": False})
        self.vault.lock()
        self.assertEqual(len(self.loaded()), 1)
        subprocess.run([ADD, "-d", str(key) + ".pub"], env=self.environment, check=True, capture_output=True)
        self.vault.unlock(self.path, "public SSH vault master")
        self.vault.ssh_configure(self.manager, socket=str(self.socket))
        self.vault.ssh_add(self.vault.ssh_prepare(self.entry())["token"], approved=True)
        copied = self.root / "copied.kdbx"
        self.vault.save_copy(copied)
        other = Vault(ENGINE)
        self.addCleanup(other.lock)
        other.unlock(copied, "public SSH vault master")
        other.ssh_configure(self.manager, socket=str(self.socket))
        review = other.ssh_prepare(other.snapshot.entries[0])
        self.assertTrue(review["other_vault"])
        with self.assertRaises(EngineError):
            other.ssh_add(review["token"], approved=True)
        other.lock()
        self.assertEqual(len(self.loaded()), 1)
        self.vault.lock()
        self.assertEqual(self.loaded(), [])

    def test_confirmation_constraint_lifetime_and_intentional_keep_on_lock(self):
        key = self.key()
        entry = self.configure(key, confirm=True)
        self.vault.ssh_add(self.vault.ssh_prepare(entry)["token"], approved=True)
        self.sign(key, expect_success=False)
        self.assertTrue(self.asked.exists())
        self.decision.write_text("allow\n")
        self.sign(key)
        self.vault.save_ssh_settings(self.entry(), confirm=False, lifetime=True, seconds=1, remove_on_lock=False)
        self.vault.ssh_add(self.vault.ssh_prepare(self.entry())["token"], approved=True)
        self.vault.lock()
        self.assertEqual(len(self.loaded()), 1)
        eventually(lambda: not self.loaded())

    def test_managed_removal_works_after_original_key_file_is_gone_and_disable_keeps_vault_open(self):
        key = self.key()
        entry = self.configure(key)
        self.vault.ssh_add(self.vault.ssh_prepare(entry)["token"], approved=True)
        key.unlink()
        owned = self.vault.ssh_owned()
        self.assertEqual(len(owned), 1)
        self.assertTrue(self.vault.ssh_remove(owned[0]["fingerprint"], owned[0]["socket"])["removed"])
        self.assertEqual(self.loaded(), [])
        self.vault.ssh_configure(None)
        self.assertTrue(self.vault.unlocked)
        with self.assertRaises(VaultError):
            self.vault.ssh_prepare(entry)

    def test_bad_password_malformed_oversized_directory_and_fifo_sources_do_not_reach_agent(self):
        key = self.key()
        entry = self.configure(key, password="wrong")
        with self.assertRaises(EngineError):
            self.vault.ssh_prepare(entry)
        self.assertEqual(self.loaded(), [])
        for index, data in enumerate((b"invalid", b"x" * (1024 * 1024 + 1))):
            bad = self.root / ("bad" + str(index))
            bad.write_bytes(data)
            self.vault.save_ssh_settings(self.entry(), file=str(bad))
            with self.assertRaises(EngineError):
                self.vault.ssh_prepare(self.entry())
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for bad in (self.root, fifo):
            self.vault.save_ssh_settings(self.entry(), file=str(bad))
            with self.assertRaises(EngineError):
                self.vault.ssh_prepare(self.entry())
        self.assertEqual(self.loaded(), [])

    def test_unregistered_peer_is_rejected_without_touching_registered_vault_keys(self):
        entry = self.configure(self.key())
        self.vault.ssh_add(self.vault.ssh_prepare(entry)["token"], approved=True)
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(2)
            peer.connect(str(self.manager.path))
            self.assertEqual(peer.recv(1024), b"")
        self.assertEqual(len(self.loaded()), 1)
        self.assertEqual(self.manager.status()["managed"], 1)

    def test_authenticated_framing_deadline_and_socket_permissions_preserve_other_connections(self):
        entry = self.configure(self.key())
        self.vault.ssh_add(self.vault.ssh_prepare(entry)["token"], approved=True)
        self.assertEqual(self.manager.path.parent.stat().st_mode & 0o077, 0)
        self.assertEqual(self.manager.path.stat().st_mode & 0o077, 0)
        self.manager.register(os.getpid())
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(2)
            peer.connect(str(self.manager.path))
            current = int(time.monotonic() * 1000)
            message = (json.dumps({"id": 1, "method": "owned", "deadline": current + 10000}) + "\n").encode()
            peer.sendall(message[:7])
            peer.sendall(message[7:])
            reader = peer.makefile("rb")
            self.assertEqual(json.loads(reader.readline()), {"id": 1, "result": {"keys": []}})
            peer.sendall((json.dumps({"id": 2, "method": "owned", "deadline": current - 1}) + "\n").encode())
            self.assertIn("expired", json.loads(reader.readline())["error"])
            peer.sendall(b"invalid JSON\n")
            self.assertEqual(reader.readline(), b"")
            reader.close()
        self.assertEqual(len(self.loaded()), 1)
        self.assertEqual(self.manager.status()["managed"], 1)

    def test_helper_killed_while_add_is_pending_is_cleaned_after_acknowledgement(self):
        key = self.key()
        public = base64.b64decode(Path(str(key) + ".pub").read_text().split()[1])
        fake = FakeAgent(self.root / "fake-agent", public)
        self.addCleanup(fake.close)
        fake.allow_add.clear()
        self.vault.ssh_configure(self.manager, socket=str(fake.path))
        entry = self.configure(key)
        review = self.vault.ssh_prepare(entry)
        errors = []
        def add():
            try:
                self.vault.ssh_add(review["token"], approved=True)
            except VaultError as exc:
                errors.append(exc)
        worker = threading.Thread(target=add)
        worker.start()
        self.assertTrue(fake.add_started.wait(3))
        self.vault.cancel()
        fake.allow_add.set()
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.vault.finish_lock()
        eventually(lambda: not fake.keys)
        self.assertTrue(self.manager.status()["cleanup_ok"])
        self.assertEqual(self.manager.status()["managed"], 0)

    def test_agent_refused_removal_is_reported_instead_of_claimed_success(self):
        key = self.key()
        public = base64.b64decode(Path(str(key) + ".pub").read_text().split()[1])
        fake = FakeAgent(self.root / "fake-agent", public)
        self.addCleanup(fake.close)
        self.vault.ssh_configure(self.manager, socket=str(fake.path))
        entry = self.configure(key)
        self.vault.ssh_add(self.vault.ssh_prepare(entry)["token"], approved=True)
        fake.refuse_remove = True
        owned = self.vault.ssh_owned()[0]
        with self.assertRaises(EngineError):
            self.vault.ssh_remove(owned["fingerprint"], owned["socket"])
        self.vault.lock()
        self.assertFalse(self.manager.status()["cleanup_ok"])
        self.assertTrue(fake.keys)
        fake.refuse_remove = False
        self.assertTrue(self.manager.retry_cleanup()["cleanup_ok"])
        self.assertFalse(fake.keys)

    def test_relay_sigterm_and_parent_pipe_eof_cleanup_do_not_lock_the_vault(self):
        entry = self.configure(self.key())
        self.vault.ssh_add(self.vault.ssh_prepare(entry)["token"], approved=True)
        process = self.manager.process
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)
        self.assertEqual(self.loaded(), [])
        self.assertTrue(self.vault.unlocked)
        self.manager.close()
        self.assertTrue(self.manager.cleanup_ok)
        self.manager = SSHAgentManager(RELAY)
        self.addCleanup(self.manager.close)
        self.vault.ssh_configure(self.manager, socket=str(self.socket))
        self.vault.ssh_add(self.vault.ssh_prepare(self.entry())["token"], approved=True)
        self.manager.close()
        self.assertTrue(self.manager.cleanup_ok)
        self.assertEqual(self.loaded(), [])
        self.assertTrue(self.vault.unlocked)

    def test_truncated_or_dtd_settings_are_not_silently_replaced_and_expired_tokens_fail(self):
        entry = self.configure(self.key())
        source = self.root / "KeeAgent.settings"
        for text in ("<EntrySettings><AllowUseOfSshKey>true</AllowUseOfSshKey>",
                     '<!DOCTYPE EntrySettings [<!ENTITY x "file">]><EntrySettings/>'):
            source.write_text(text)
            self.vault.import_attachment(self.entry(), source, replace=True)
            before = self.path.read_bytes()
            with self.assertRaises(EngineError):
                self.vault.ssh_settings(self.entry())
            with self.assertRaises(EngineError):
                self.vault.save_ssh_settings(self.entry(), enabled=True)
            self.assertEqual(self.path.read_bytes(), before)
        self.vault.remove_attachment(self.entry(), "KeeAgent.settings")
        self.vault.save_ssh_settings(self.entry(), enabled=True, file=str(self.root / "key"), remove_on_lock=True)
        review = self.vault.ssh_prepare(self.entry())
        self.vault.ssh_add(self.vault.ssh_prepare(self.entry())["token"], approved=True)
        removal = self.vault.ssh_review_removal(clear=True)
        time.sleep(30.1)
        with self.assertRaises(EngineError):
            self.vault.ssh_add(review["token"], approved=True)
        with self.assertRaises(EngineError):
            self.vault.ssh_finish_removal(removal["token"], approved=True)
        self.assertEqual(len(self.loaded()), 1)
        self.vault.lock()
        self.assertEqual(self.loaded(), [])

    def test_reviewed_external_removal_cancel_replay_and_unrelated_new_keys(self):
        first, second = self.key(password="", name="external-one"), self.key(password="", name="external-two")
        subprocess.run([ADD, str(first)], env=self.environment, capture_output=True, check=True)
        original = first.read_bytes()
        info = self.vault.ssh_agent_keys()
        self.assertEqual(info["socket"], str(self.socket))
        self.assertEqual(len(info["keys"]), 1)
        key = info["keys"][0]
        self.assertFalse(key["owned"] or key["other_vault"])
        self.assertTrue(key["public_key"].startswith("ssh-ed25519 "))
        review = self.vault.ssh_review_removal([key["fingerprint"]])
        self.assertTrue(self.vault.ssh_finish_removal(review["token"])["cancelled"])
        with self.assertRaises(EngineError):
            self.vault.ssh_finish_removal(review["token"], approved=True)
        self.assertEqual(len(self.loaded()), 1)
        review = self.vault.ssh_review_removal([key["fingerprint"]])
        subprocess.run([ADD, str(second)], env=self.environment, capture_output=True, check=True)
        result = self.vault.ssh_finish_removal(review["token"], approved=True)
        self.assertTrue(result["confirmed"] and result["complete"])
        self.assertEqual((result["removed"], result["agent_remaining"]), (1, 1))
        self.assertEqual(first.read_bytes(), original)
        self.assertEqual(self.loaded()[0].split()[1], second.with_suffix(".pub").read_text().split()[1])

    def test_clear_review_includes_other_vault_and_external_keys_without_changing_databases(self):
        entry = self.configure(self.key())
        self.vault.ssh_add(self.vault.ssh_prepare(entry)["token"], approved=True)
        external = self.key(password="", name="external")
        subprocess.run([ADD, str(external)], env=self.environment, capture_output=True, check=True)
        other = Vault(ENGINE)
        self.addCleanup(other.lock)
        other_path = self.root / "other.kdbx"
        other.create(other_path, "public other master")
        other_key = self.key(password="", name="other-key")
        other.save_entry(other.snapshot.root, "Other vault key", "bob", "", "Preserve", "")
        other.save_ssh_settings(other.snapshot.entries[0], enabled=True, source_type="file", file=str(other_key), remove_on_lock=True)
        other.ssh_configure(self.manager, socket=str(self.socket))
        other.ssh_add(other.ssh_prepare(other.snapshot.entries[0])["token"], approved=True)
        before, other_before = self.path.read_bytes(), other_path.read_bytes()
        review = self.vault.ssh_review_removal(clear=True)
        self.assertEqual(len(review["keys"]), 3)
        self.assertEqual(sum(k["owned"] for k in review["keys"]), 1)
        self.assertEqual(sum(k["other_vault"] for k in review["keys"]), 1)
        result = self.vault.ssh_finish_removal(review["token"], approved=True)
        self.assertTrue(result["complete"])
        self.assertEqual(result["removed"], 3)
        self.assertEqual(self.loaded(), [])
        self.assertEqual(self.vault.ssh_owned(), [])
        self.assertEqual(other.ssh_owned(), [])
        self.assertTrue(self.vault.unlocked and other.unlocked)
        self.assertEqual((self.path.read_bytes(), other_path.read_bytes()), (before, other_before))

    def test_changed_clear_list_comment_and_ownership_require_fresh_review(self):
        first, second = self.key(password="", name="one"), self.key(password="", name="two")
        entry = self.configure(first, password="")
        subprocess.run([ADD, str(first)], env=self.environment, capture_output=True, check=True)
        review = self.vault.ssh_review_removal(clear=True)
        subprocess.run([ADD, str(second)], env=self.environment, capture_output=True, check=True)
        with self.assertRaisesRegex(EngineError, "changed"):
            self.vault.ssh_finish_removal(review["token"], approved=True)
        self.assertEqual(len(self.loaded()), 2)
        fingerprint = self.vault.ssh_key_info(entry)["fingerprint"]
        review = self.vault.ssh_review_removal([fingerprint])
        subprocess.run([ADD, "-d", str(first) + ".pub"], env=self.environment, capture_output=True, check=True)
        subprocess.run([KEYGEN, "-c", "-P", "", "-C", "changed comment", "-f", str(first)], capture_output=True, check=True)
        subprocess.run([ADD, str(first)], env=self.environment, capture_output=True, check=True)
        with self.assertRaisesRegex(EngineError, "changed"):
            self.vault.ssh_finish_removal(review["token"], approved=True)
        review = self.vault.ssh_review_removal([fingerprint])
        subprocess.run([ADD, "-d", str(first) + ".pub"], env=self.environment, capture_output=True, check=True)
        self.vault.ssh_add(self.vault.ssh_prepare(self.entry())["token"], approved=True)
        with self.assertRaisesRegex(EngineError, "ownership changed"):
            self.vault.ssh_finish_removal(review["token"], approved=True)
        self.assertEqual(len(self.loaded()), 2)

    def test_removal_tokens_reject_database_changes_other_helpers_and_reconfiguration(self):
        entry = self.configure(self.key())
        self.vault.ssh_add(self.vault.ssh_prepare(entry)["token"], approved=True)
        review = self.vault.ssh_review_removal(clear=True)
        other = Vault(ENGINE)
        self.addCleanup(other.lock)
        copied = self.root / "copy.kdbx"
        self.vault.save_copy(copied)
        other.unlock(copied, "public SSH vault master")
        other.ssh_configure(self.manager, socket=str(self.socket))
        with self.assertRaises(EngineError):
            other.ssh_finish_removal(review["token"], approved=True)
        self.assertEqual(len(self.loaded()), 1)
        self.vault.save_entry(entry.group, "Changed title", entry.username, entry.url, entry.notes, entry=entry)
        with self.assertRaises(EngineError):
            self.vault.ssh_finish_removal(review["token"], approved=True)
        review = self.vault.ssh_review_removal(clear=True)
        self.vault.ssh_configure(self.manager, socket=str(self.socket), provider="internal")
        with self.assertRaises(EngineError):
            self.vault.ssh_finish_removal(review["token"], approved=True)
        self.assertEqual(len(self.loaded()), 1)

    def test_refused_or_unconfirmed_reviewed_removal_is_reported_and_cleanup_can_retry(self):
        key = self.key()
        public = base64.b64decode(Path(str(key) + ".pub").read_text().split()[1])
        fake = FakeAgent(self.root / "refusing-agent", public)
        self.addCleanup(fake.close)
        self.vault.ssh_configure(self.manager, socket=str(fake.path))
        self.vault.ssh_add(self.vault.ssh_prepare(self.configure(key))["token"], approved=True)
        fake.refuse_remove = True
        review = self.vault.ssh_review_removal(clear=True)
        result = self.vault.ssh_finish_removal(review["token"], approved=True)
        self.assertTrue(result["confirmed"])
        self.assertFalse(result["complete"])
        self.assertEqual((result["removed"], result["agent_remaining"]), (0, 1))
        fake.refuse_remove, fake.fail_list_after_remove = False, True
        review = self.vault.ssh_review_removal(clear=True)
        result = self.vault.ssh_finish_removal(review["token"], approved=True)
        self.assertFalse(result["confirmed"] or result["complete"])
        self.assertFalse(self.manager.status()["cleanup_ok"])
        fake.fail_list_after_remove = fake.fail_list = False
        self.assertTrue(self.manager.retry_cleanup()["cleanup_ok"])
        self.assertEqual(fake.keys, set())
        self.assertTrue(self.vault.unlocked)

    def test_replaced_agent_invalidates_reviews_and_old_cleanup_cannot_remove_replacement_keys(self):
        key = self.key()
        public = base64.b64decode(Path(str(key) + ".pub").read_text().split()[1])
        original = FakeAgent(self.root / "changing-agent", public)
        self.addCleanup(original.close)
        self.vault.ssh_configure(self.manager, socket=str(original.path))
        self.vault.ssh_add(self.vault.ssh_prepare(self.configure(key))["token"], approved=True)
        review = self.vault.ssh_review_removal(clear=True)
        saved = self.root / "original-agent"
        original.path.rename(saved)
        replacement = FakeAgent(original.path, public)
        self.addCleanup(replacement.close)
        replacement.keys.add(public)
        with self.assertRaisesRegex(EngineError, "agent changed"):
            self.vault.ssh_finish_removal(review["token"], approved=True)
        record = self.vault.ssh_owned()[0]
        with self.assertRaises(EngineError):
            self.vault.ssh_remove(record["fingerprint"], record["socket"])
        self.assertFalse(self.manager.retry_cleanup()["cleanup_ok"])
        self.assertEqual(replacement.keys, {public})
        info = self.vault.ssh_agent_keys()["keys"][0]
        self.assertFalse(info["owned"] or info["other_vault"])
        review = self.vault.ssh_review_removal(clear=True)
        self.assertTrue(self.vault.ssh_finish_removal(review["token"], approved=True)["complete"])
        self.assertEqual(original.keys, {public})
        self.assertFalse(self.manager.status()["cleanup_ok"])
        replacement.close()
        original.path.unlink()
        saved.rename(original.path)
        self.assertTrue(self.manager.retry_cleanup()["cleanup_ok"])
        self.assertEqual(original.keys, set())

    def test_helper_death_during_clear_stops_removing_further_external_keys(self):
        first, second = self.key(password="", name="one"), self.key(password="", name="two")
        public = [base64.b64decode(Path(str(key) + ".pub").read_text().split()[1]) for key in (first, second)]
        fake = FakeAgent(self.root / "blocked-removal", public[0])
        self.addCleanup(fake.close)
        fake.keys.update(public)
        fake.allow_remove.clear()
        self.vault.ssh_configure(self.manager, socket=str(fake.path))
        review = self.vault.ssh_review_removal(clear=True)
        failures = []
        def remove():
            try:
                self.vault.ssh_finish_removal(review["token"], approved=True)
            except VaultError as exc:
                failures.append(exc)
        worker = threading.Thread(target=remove)
        worker.start()
        self.assertTrue(fake.remove_started.wait(2))
        process = self.vault._process
        self.vault.cancel()
        process.wait(timeout=2)
        fake.allow_remove.set()
        worker.join(timeout=4)
        self.assertFalse(worker.is_alive())
        self.assertTrue(failures)
        self.vault.finish_lock()
        self.assertTrue(self.manager.status()["cleanup_ok"])
        self.assertEqual(len(fake.keys), 1)

    def test_clear_preserves_a_new_key_loaded_during_the_reviewed_removals(self):
        keys = [self.key(password="", name=name) for name in ("one", "two", "new")]
        public = [base64.b64decode(Path(str(key) + ".pub").read_text().split()[1]) for key in keys]
        fake = FakeAgent(self.root / "concurrent-agent", public[0])
        self.addCleanup(fake.close)
        fake.keys.update(public[:2])
        self.vault.ssh_configure(self.manager, socket=str(fake.path))
        review = self.vault.ssh_review_removal(clear=True)
        fake.add_during_remove = public[2]
        result = self.vault.ssh_finish_removal(review["token"], approved=True)
        self.assertEqual((result["removed"], result["total"], result["agent_remaining"]), (2, 2, 1))
        self.assertTrue(result["confirmed"])
        self.assertFalse(result["complete"])
        self.assertEqual(fake.keys, {public[2]})

    def test_external_key_paths_preserve_upstream_syntax_and_bound_recursive_variables(self):
        key = self.key()
        self.configure(key)
        env = {"KEYSLOT_SSH_TEST_BASE": str(self.root), "KEYSLOT_SSH_TEST_NEST": "$KEYSLOT_SSH_TEST_BASE",
               "KEYSLOT_SSH_TEST_SELF": "$KEYSLOT_SSH_TEST_SELF", "KEYSLOT_SSH_TEST_A": "$KEYSLOT_SSH_TEST_B",
               "KEYSLOT_SSH_TEST_B": "$KEYSLOT_SSH_TEST_A", "KEYSLOT_SSH_TEST_GROW": "$KEYSLOT_SSH_TEST_GROW/x",
               "KEYSLOT_SSH_TEST_UNDEFINED": "", "KEYSLOT_SSH_TEST_LARGE": "x" * 16385}
        with patch.dict(os.environ, env):
            self.vault.lock()
            self.vault.unlock(self.path, "public SSH vault master")
        self.vault.ssh_configure(self.manager, socket=str(self.socket))
        for path in ("key", "$KEYSLOT_SSH_TEST_BASE/key", "$KEYSLOT_SSH_TEST_NEST/key",
                     "~/" + os.path.relpath(key, Path.home()), "$KEYSLOT_SSH_TEST_UNDEFINED" + str(key)):
            with self.subTest(path=path):
                self.vault.save_ssh_settings(self.entry(), file=path)
                if path.startswith("~/") and not Path.home().is_dir():
                    # Nix's absent homeless-shelter cannot be traversed, even via ../.
                    with self.assertRaises(EngineError):
                        self.vault.ssh_key_info(self.entry(), decrypt=True)
                else:
                    self.assertTrue(self.vault.ssh_key_info(self.entry(), decrypt=True)["public_key"].startswith("ssh-ed25519 "))
        for path in ("$KEYSLOT_SSH_TEST_SELF/key", "$KEYSLOT_SSH_TEST_A/key", "$KEYSLOT_SSH_TEST_GROW/key", "$KEYSLOT_SSH_TEST_LARGE/key"):
            self.vault.save_ssh_settings(self.entry(), file=path)
            started = time.monotonic()
            with self.assertRaisesRegex(EngineError, "large|cycle|substitutions"):
                self.vault.ssh_key_info(self.entry())
            self.assertLess(time.monotonic() - started, 2)
        self.assertTrue(self.vault.unlocked)
        self.assertEqual(self.loaded(), [])

    def test_relay_removal_validation_owner_binding_replay_and_review_limits(self):
        key = self.key(password="")
        subprocess.run([ADD, str(key)], env=self.environment, capture_output=True, check=True)
        fingerprint = self.vault.ssh_agent_keys()["keys"][0]["fingerprint"]
        def peer():
            self.manager.register(os.getpid())
            stream = socket.socket(socket.AF_UNIX)
            stream.settimeout(3)
            stream.connect(str(self.manager.path))
            self.addCleanup(stream.close)
            reader = stream.makefile("rb")
            self.addCleanup(reader.close)
            sequence = [0]
            def call(method, **options):
                sequence[0] += 1
                stream.sendall((json.dumps(dict(id=sequence[0], method=method, deadline=time.monotonic()*1000+9000, **options))+"\n").encode())
                return json.loads(reader.readline())
            self.assertIn("result", call("list", socket=str(self.socket)))
            return call
        first, second = peer(), peer()
        for options in ({"clear": False, "fingerprints": []}, {"clear": "yes", "fingerprints": []},
                        {"clear": False, "fingerprints": [fingerprint, fingerprint]},
                        {"clear": False, "fingerprints": ["missing"]}, {"clear": True, "fingerprints": [fingerprint]}):
            self.assertIn("error", first("review-remove", socket=str(self.socket), **options))
        tokens = [first("review-remove", socket=str(self.socket), clear=False, fingerprints=[fingerprint])["result"]["token"] for _ in range(128)]
        self.assertIn("error", first("review-remove", socket=str(self.socket), clear=True, fingerprints=[]))
        self.assertIn("error", second("finish-remove", token=tokens[0], approved=True))
        for token in tokens:
            self.assertTrue(first("finish-remove", token=token, approved=False)["result"]["cancelled"])
        self.assertIn("error", first("finish-remove", token=tokens[0], approved=True))
        self.assertEqual(len(self.loaded()), 1)

    def test_symlink_socket_alias_shares_cross_vault_ownership_and_cleanup_survives_unlink(self):
        alias = self.root / "agent-alias"
        alias.symlink_to(self.socket)
        self.vault.ssh_configure(self.manager, socket=str(alias))
        entry = self.configure(self.key())
        self.vault.ssh_add(self.vault.ssh_prepare(entry)["token"], approved=True)
        self.assertEqual(self.vault.ssh_owned()[0]["socket"], str(self.socket))
        other = Vault(ENGINE)
        self.addCleanup(other.lock)
        copied = self.root / "other.kdbx"
        self.vault.save_copy(copied)
        other.unlock(copied, "public SSH vault master")
        other.ssh_configure(self.manager, socket=str(self.socket))
        self.assertTrue(other.ssh_agent_keys()["keys"][0]["other_vault"])
        review = other.ssh_prepare(other.snapshot.entries[0])
        self.assertTrue(review["other_vault"])
        with self.assertRaises(EngineError):
            other.ssh_add(review["token"], approved=True)
        alias.unlink()
        self.vault.lock()
        self.assertEqual(self.loaded(), [])
        self.assertTrue(self.manager.status()["cleanup_ok"])
        self.assertTrue(other.unlocked)

    def test_hardlink_alias_shares_records_and_observed_routes_survive_a_removed_path(self):
        alias = self.root / "agent-hardlink"
        os.link(self.socket, alias)
        self.assertEqual(alias.stat().st_ino, self.socket.stat().st_ino)
        entry = self.configure(self.key())
        self.vault.ssh_add(self.vault.ssh_prepare(entry)["token"], approved=True)
        self.vault.ssh_configure(self.manager, socket=str(alias))
        info = self.vault.ssh_agent_keys()["keys"][0]
        self.assertTrue(info["owned"])
        self.vault.ssh_remove(info["fingerprint"], str(alias))
        self.assertEqual(self.vault.ssh_owned(), [])
        self.vault.ssh_add(self.vault.ssh_prepare(self.entry())["token"], approved=True)
        self.vault.ssh_configure(self.manager, socket=str(self.socket))
        self.assertTrue(self.vault.ssh_agent_keys()["keys"][0]["owned"])
        alias.unlink()
        self.vault.lock()
        self.assertEqual(self.loaded(), [])
        self.assertTrue(self.manager.status()["cleanup_ok"])
        self.vault.unlock(self.path, "public SSH vault master")
        self.vault.ssh_configure(self.manager, socket=str(self.socket))
        self.vault.ssh_add(self.vault.ssh_prepare(self.entry())["token"], approved=True)
        routes = []
        for index in range(20):
            route = self.root / f"route-{index}"
            os.link(self.socket, route)
            routes.append(route)
            self.vault.ssh_configure(self.manager, socket=str(route))
            self.assertTrue(self.vault.ssh_agent_keys()["keys"][0]["owned"])
        for route in routes[:-1]:
            route.unlink()
        self.socket.unlink()
        self.vault.lock()
        result = subprocess.run([ADD, "-L"], env=self.environment | {"SSH_AUTH_SOCK": str(routes[-1])}, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertTrue(self.manager.status()["cleanup_ok"])
        os.link(routes[-1], self.socket)

    def test_retargeted_symlink_invalidates_review_and_lock_cleans_only_original_agent(self):
        alias = self.root / "agent-alias"
        alias.symlink_to(self.socket)
        self.vault.ssh_configure(self.manager, socket=str(alias))
        key = self.key()
        self.vault.ssh_add(self.vault.ssh_prepare(self.configure(key))["token"], approved=True)
        review = self.vault.ssh_review_removal(clear=True)
        public = base64.b64decode(Path(str(key) + ".pub").read_text().split()[1])
        replacement = FakeAgent(self.root / "replacement", public)
        self.addCleanup(replacement.close)
        replacement.keys.add(public)
        alias.unlink()
        alias.symlink_to(replacement.path)
        with self.assertRaisesRegex(EngineError, "agent changed"):
            self.vault.ssh_finish_removal(review["token"], approved=True)
        self.assertFalse(self.vault.ssh_agent_keys()["keys"][0]["owned"])
        self.vault.lock()
        self.assertEqual(self.loaded(), [])
        self.assertEqual(replacement.keys, {public})
        self.assertTrue(self.manager.status()["cleanup_ok"])

    def test_retargeting_alias_during_add_never_sends_private_key_to_replacement_agent(self):
        key = self.key()
        public = base64.b64decode(Path(str(key) + ".pub").read_text().split()[1])
        original, replacement = FakeAgent(self.root / "original", public), FakeAgent(self.root / "replacement", public)
        self.addCleanup(original.close)
        self.addCleanup(replacement.close)
        alias = self.root / "agent-alias"
        alias.symlink_to(original.path)
        self.vault.ssh_configure(self.manager, socket=str(alias))
        token = self.vault.ssh_prepare(self.configure(key))["token"]
        original.allow_add.clear()
        failures = []
        def add():
            try:
                self.vault.ssh_add(token, approved=True)
            except VaultError as exc:
                failures.append(exc)
        worker = threading.Thread(target=add)
        worker.start()
        self.assertTrue(original.add_started.wait(2))
        alias.unlink()
        alias.symlink_to(replacement.path)
        original.allow_add.set()
        worker.join(timeout=4)
        self.assertFalse(worker.is_alive())
        self.assertTrue(failures)
        self.assertFalse(replacement.add_started.is_set())
        self.assertEqual(replacement.keys, set())
        self.assertTrue(self.manager.retry_cleanup()["cleanup_ok"])
        self.assertEqual(original.keys, set())

    def test_failed_startup_is_reaped_and_unexpected_relay_exit_does_not_claim_cleanup(self):
        child_pid, script = self.root / "startup.pid", self.root / "not-ready"
        script.write_text(f'#!{sys.executable}\nimport os,time\nfrom pathlib import Path\n'
                          f'Path({str(child_pid)!r}).write_text(str(os.getpid()))\ntime.sleep(30)\n')
        script.chmod(0o700)
        with self.assertRaises(VaultError):
            SSHAgentManager(script, timeout=1)
        self.assertTrue(child_pid.exists())
        with self.assertRaises(ProcessLookupError):
            os.kill(int(child_pid.read_text()), 0)
        key = self.key()
        entry = self.configure(key)
        self.vault.ssh_add(self.vault.ssh_prepare(entry)["token"], approved=True)
        self.manager.process.kill()
        self.manager.process.wait(timeout=3)
        self.manager.close()
        self.assertFalse(self.manager.cleanup_ok)
        self.assertTrue(self.vault.unlocked)
        self.assertEqual(len(self.loaded()), 1)
        # Remove only the disposable fixture identity; an abrupt helper crash cannot promise cleanup.
        subprocess.run([ADD, "-d", str(key) + ".pub"], env=self.environment, check=True, capture_output=True)
