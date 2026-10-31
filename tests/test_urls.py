"""Native URL resolution, command consent and encrypted linked-vault credentials."""
import base64
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest

from keyslot.backend import VaultError
from keyslot.core_backend import Vault

ENGINE = os.environ.get("KEYSLOT_ENGINE") or shutil.which("keyslot-engine")
MASTER = "public linked vault master"


@unittest.skipUnless(ENGINE, "native engine required")
class Urls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="keyslot-url-")
        self.directory = Path(self.temporary.name)
        self.source, self.target = Vault(ENGINE), Vault(ENGINE)
        self.source.create(self.directory / "Source.kdbx", "public source master")
        self.target_path = self.directory / "Target.kdbx"
        self.target.create(self.target_path, MASTER)
        self.target.save_entry(self.target.snapshot.root, "Target Entry", "public target user", "", "", "public target secret")
        self.target.lock()
        self.source.save_entry(self.source.snapshot.root, "Launch Entry", "public-user", "https://example.org", "", MASTER)
        self.script = self.directory / "Recorder.py"
        self.output = self.directory / "Arguments.jsonl"
        self.script.write_text('''import json, os, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
with os.fdopen(fd, "a") as stream:
    stream.write(json.dumps({"args":sys.argv[2:], "private_env":[k for k in os.environ if k.startswith("KEYSLOT_")], "stdin":sys.stdin.read()}) + "\\n")
print("Public fixture command stdout")
print("Public fixture command stderr", file=sys.stderr)
''')

    def tearDown(self):
        self.source.lock()
        self.target.lock()
        self.temporary.cleanup()

    def entry(self):
        return next(entry for entry in self.source.snapshot.entries if entry.title == "Launch Entry")

    def url(self, value, **options):
        entry = self.entry()
        self.source.save_entry(entry.group, entry.title, options.pop("username", entry.username), value, entry.notes,
                               password=options.pop("password", None), entry=entry, **options)

    def command(self, arguments=""):
        return f'cmd://"{sys.executable}" "{self.script}" "{self.output}" ' + arguments

    def records(self, count=1):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.output.exists():
                lines = self.output.read_text().splitlines()
                if len(lines) >= count:
                    return [json.loads(line) for line in lines]
            time.sleep(.01)
        self.fail("Owned command fixture did not finish")

    def linked(self, value="kdbx://Target.kdbx", **options):
        self.url(value, username=options.pop("username", ""), password=options.pop("password", MASTER), **options)
        return self.source.url_prepare(self.entry())

    def handoff(self, ticket):
        offer = self.target.url_offer(ticket)
        envelope = self.source.url_finish(ticket["token"], destination=offer)
        self.target.url_accept(envelope)
        return offer, envelope

    def test_uri_normalization_schemes_and_explicit_override_match_upstream_resolution(self):
        for raw, expected in (("example.org/a b", "http://example.org/a%20b"),
                              ("mailto:public@example.org", "mailto:public@example.org"),
                              ("ssh://public@example.org", "ssh://public@example.org"),
                              ("file:///tmp/public%20file", "file:///tmp/public%20file")):
            self.url(raw)
            ticket = self.source.url_prepare(self.entry())
            self.assertEqual(ticket["kind"], "uri")
            self.assertEqual(self.source.url_finish(ticket["token"])["uri"], expected)
        self.url("https://original.example/{USERNAME}", override_url="https://override.example/{USERNAME}")
        normal = self.source.url_prepare(self.entry())
        self.assertEqual(self.source.url_finish(normal["token"])["uri"], "https://original.example/public-user")
        override = self.source.url_prepare(self.entry(), True)
        self.assertEqual(self.source.url_finish(override["token"])["uri"], "https://override.example/public-user")

    def test_preview_masks_nested_protected_references_conversions_and_totp_without_mutation(self):
        self.source.set_attribute(self.entry(), "Protected", "public protected secret", True)
        self.source.set_attribute(self.entry(), "Nested", "{PASSWORD}", False)
        self.source.set_totp(self.entry(), "otpauth://totp/Public?secret=JBSWY3DPEHPK3PXP")
        self.source.save_entry(self.source.snapshot.root, "Referenced", "public", "", "", "public referenced secret")
        other = next(entry for entry in self.source.snapshot.entries if entry.title == "Referenced")
        self.url(self.command('"{S:Protected}" "{S:Nested}" "{REF:P@I:' + other.uuid.replace("-", "")
                              + '}" "{T-CONV:/{PASSWORD}/BASE64/}" "otp={TOTP}"'))
        before = self.source.path.read_bytes()
        otp = self.source.attribute(self.entry(), totp=True)
        ticket = self.source.url_prepare(self.entry())
        display = ticket["display"]
        for secret in (MASTER, "public protected secret", "public referenced secret", base64.b64encode(MASTER.encode()).decode(), otp):
            self.assertNotIn(secret, display)
        self.assertIn("[Hidden]", display)
        self.assertEqual(self.source.path.read_bytes(), before)
        self.assertEqual(self.source.attribute(self.entry()), MASTER)
        self.source.url_cancel(ticket["token"])

    def test_approved_command_uses_qt_argv_without_shell_or_private_pipe_environment(self):
        self.source.set_attribute(self.entry(), "Token", "public protected token", True)
        self.url(self.command('"argument with spaces" "$NOT_EXPANDED" "semi;colon" "--password={PASSWORD}" "{S:Token}"'))
        ticket = self.source.url_prepare(self.entry())
        self.assertNotIn(MASTER, repr(ticket))
        result = self.source.url_finish(ticket["token"], approved=True)
        self.assertTrue(result["launched"])
        record = self.records()[0]
        self.assertEqual(record["args"], ["argument with spaces", "$NOT_EXPANDED", "semi;colon", "--password=" + MASTER, "public protected token"])
        self.assertEqual(record["private_env"], [])
        self.assertEqual(record["stdin"], "")
        self.assertEqual(self.source.attribute(self.entry()), MASTER)

    def test_cancel_denial_and_replay_do_not_execute(self):
        self.url(self.command())
        ticket = self.source.url_prepare(self.entry())
        self.source.url_cancel(ticket["token"])
        with self.assertRaises(VaultError):
            self.source.url_finish(ticket["token"], approved=True)
        ticket = self.source.url_prepare(self.entry())
        with self.assertRaises(VaultError):
            self.source.url_finish(ticket["token"])
        self.assertFalse(self.output.exists())
        ticket = self.source.url_prepare(self.entry())
        self.source.url_finish(ticket["token"], approved=True)
        self.records()
        with self.assertRaises(VaultError):
            self.source.url_finish(ticket["token"], approved=True)
        self.assertEqual(len(self.records()), 1)

    def test_remembered_command_approval_roundtrip_revocation_and_url_change(self):
        self.url(self.command('"first"'))
        ticket = self.source.url_prepare(self.entry())
        self.source.url_finish(ticket["token"], approved=True, remember=True)
        self.records()
        self.assertTrue(self.entry().command_approved)
        self.assertEqual(self.source.attribute_info(self.entry(), "_EXEC_CMD")["value"], "1")
        self.source.lock()
        self.source.unlock(self.directory / "Source.kdbx", "public source master")
        ticket = self.source.url_prepare(self.entry())
        self.assertTrue(ticket["remembered"])
        self.source.url_finish(ticket["token"])
        self.records(2)
        self.source.url_forget(self.entry())
        self.assertFalse(self.entry().command_approved)
        ticket = self.source.url_prepare(self.entry())
        self.assertFalse(ticket["remembered"])
        self.source.url_finish(ticket["token"], approved=True, remember=True)
        self.records(3)
        self.url(self.command('"changed"'))
        self.assertFalse(self.entry().command_approved)
        ticket = self.source.url_prepare(self.entry())
        self.assertFalse(ticket["remembered"])

    def test_override_approval_is_separate_and_bound_to_both_url_templates(self):
        self.url(self.command('"normal"'), override_url=self.command('"override"'))
        ticket = self.source.url_prepare(self.entry())
        self.source.url_finish(ticket["token"], approved=True, remember=True)
        self.records()
        ticket = self.source.url_prepare(self.entry(), True)
        self.assertFalse(ticket["remembered"])
        self.source.url_finish(ticket["token"], approved=True, remember=True)
        self.records(2)
        ticket = self.source.url_prepare(self.entry(), True)
        self.assertTrue(ticket["remembered"])
        self.source.url_cancel(ticket["token"])
        self.url(self.command('"normal changed"'))
        ticket = self.source.url_prepare(self.entry(), True)
        self.assertFalse(ticket["remembered"])

    def test_pending_launch_is_invalid_after_edit_refresh_or_lock(self):
        self.url(self.command())
        ticket = self.source.url_prepare(self.entry())
        self.source.set_attribute(self.entry(), "Changed", "public value")
        with self.assertRaises(VaultError):
            self.source.url_finish(ticket["token"], approved=True)
        ticket = self.source.url_prepare(self.entry())
        self.source.refresh()
        with self.assertRaises(VaultError):
            self.source.url_finish(ticket["token"], approved=True)
        ticket = self.source.url_prepare(self.entry())
        self.source.lock()
        with self.assertRaises(VaultError):
            self.source.url_finish(ticket["token"], approved=True)
        self.assertIsNone(self.source._process)
        self.assertFalse(self.output.exists())

    def test_invalid_command_and_remember_save_failure_never_launch(self):
        self.url("cmd:///definitely/not/a/public-fixture-program")
        ticket = self.source.url_prepare(self.entry())
        result = self.source.url_finish(ticket["token"], approved=True, remember=True)
        self.assertFalse(result["launched"])
        self.assertTrue(result["error"])
        self.assertTrue(self.entry().command_approved)
        self.url(self.command())
        ticket = self.source.url_prepare(self.entry())
        before = self.source.path.read_bytes()
        try:
            self.directory.chmod(0o500)
            with self.assertRaises(VaultError):
                self.source.url_finish(ticket["token"], approved=True, remember=True)
        finally:
            self.directory.chmod(0o700)
        self.assertEqual(self.source.path.read_bytes(), before)
        self.assertFalse(self.output.exists())

    def test_linked_vault_credentials_are_opaque_and_files_are_unchanged(self):
        ticket = self.linked()
        before_source, before_target = self.source.path.read_bytes(), self.target_path.read_bytes()
        offer, envelope = self.handoff(ticket)
        self.assertNotIn(MASTER, repr(ticket) + repr(offer) + repr(envelope))
        self.assertNotIn("password", envelope)
        self.assertEqual(self.target.attribute(self.target.snapshot.entries[0]), "public target secret")
        self.assertEqual(self.target.path, self.target_path)
        self.assertEqual(self.source.path.read_bytes(), before_source)
        self.assertEqual(self.target_path.read_bytes(), before_target)

    def test_linked_key_file_only_and_composite_credentials_use_relative_paths(self):
        keyfile = self.directory / "Public.keyx"
        self.source.generate_keyfile(keyfile)
        for no_password in (True, False):
            self.target_path = self.directory / ("Key-only.kdbx" if no_password else "Composite.kdbx")
            self.target.create(self.target_path, "" if no_password else MASTER, keyfile=str(keyfile), no_password=no_password)
            self.target.lock()
            ticket = self.linked("kdbx://" + self.target_path.name, username=keyfile.name, password="" if no_password else MASTER)
            self.assertEqual(ticket["keyfile"], str(keyfile))
            self.handoff(ticket)
            self.assertTrue(self.target.settings()["file_key"])
            self.assertEqual(self.target.settings()["password_key"], not no_password)
            self.target.lock()

    def test_missing_username_key_file_matches_upstream_empty_canonical_path(self):
        ticket = self.linked(username="does-not-exist.key")
        self.assertEqual(ticket["keyfile"], "")
        self.handoff(ticket)
        self.assertTrue(self.target.unlocked)

    def test_empty_password_key_retries_after_empty_composite_key(self):
        self.target_path = self.directory / "Empty-password.kdbx"
        # The creation UI refuses empty passwords; this legacy fixture exercises the native reader retry.
        self.target.path = self.target_path
        self.target._start()
        self.target._snapshot_call("create", path=str(self.target_path), password="", keyfile="", yubikey="", no_password=False)
        self.target.lock()
        self.handoff(self.linked("kdbx://" + self.target_path.name, password=""))
        self.assertTrue(self.target.unlocked)
        self.assertTrue(self.target.settings()["password_key"])

    def test_linked_wrong_password_tampering_replay_and_wrong_recipient_are_rejected(self):
        ticket = self.linked(password="public wrong password")
        offer = self.target.url_offer(ticket)
        envelope = self.source.url_finish(ticket["token"], destination=offer)
        with self.assertRaises(VaultError):
            self.target.url_accept(envelope)
        self.assertFalse(self.target.unlocked)
        ticket = self.linked()
        offer = self.target.url_offer(ticket)
        envelope = self.source.url_finish(ticket["token"], destination=offer)
        encoded = bytearray(base64.b64decode(envelope["message"]))
        encoded[-1] ^= 1
        with self.assertRaises(VaultError):
            self.target.url_accept(envelope | {"message": base64.b64encode(encoded).decode()})
        with self.assertRaises(VaultError):
            self.target.url_accept(envelope)
        other = Vault(ENGINE)
        try:
            ticket = self.linked()
            offer = self.target.url_offer(ticket)
            other.url_offer(ticket)
            envelope = self.source.url_finish(ticket["token"], destination=offer)
            with self.assertRaises(VaultError):
                other.url_accept(envelope)
            self.target.url_accept(envelope)
            self.assertTrue(self.target.unlocked)
        finally:
            other.lock()

    def test_changed_target_and_key_file_invalidate_sealed_credentials(self):
        ticket = self.linked()
        offer = self.target.url_offer(ticket)
        envelope = self.source.url_finish(ticket["token"], destination=offer)
        before = self.target_path.read_bytes()
        self.target_path.write_bytes(before + b"public change")
        with self.assertRaises(VaultError):
            self.target.url_accept(envelope)
        self.target_path.write_bytes(before)
        keyfile = self.directory / "Public.keyx"
        self.source.generate_keyfile(keyfile)
        self.target_path = self.directory / "With-key.kdbx"
        self.target.create(self.target_path, MASTER, keyfile=str(keyfile))
        self.target.lock()
        ticket = self.linked("kdbx://" + self.target_path.name, username=keyfile.name)
        offer = self.target.url_offer(ticket)
        envelope = self.source.url_finish(ticket["token"], destination=offer)
        keyfile.write_bytes(b"public changed keyfile")
        with self.assertRaises(VaultError):
            self.target.url_accept(envelope)
        self.assertFalse(self.target.unlocked)

    def test_recipient_cannot_replace_an_unlocked_vault_or_accept_after_cancel(self):
        ticket = self.linked()
        self.handoff(ticket)
        before = self.target.snapshot
        with self.assertRaises(VaultError):
            self.target.url_offer(ticket)
        self.assertIs(self.target.snapshot, before)
        self.target.lock()
        ticket = self.linked()
        offer = self.target.url_offer(ticket)
        self.target.url_cancel(offer["token"])
        envelope = self.source.url_finish(ticket["token"], destination=offer)
        with self.assertRaises(VaultError):
            self.target.url_accept(envelope)

    def test_oversized_link_credential_is_rejected_before_upstream_crypto(self):
        ticket = self.linked(password="public" * 12000)
        offer = self.target.url_offer(ticket)
        with self.assertRaises(VaultError):
            self.source.url_finish(ticket["token"], destination=offer)
        self.assertFalse(self.target.unlocked)
