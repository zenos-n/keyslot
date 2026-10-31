"""Upstream .passkey interchange, native private-key IO and non-destructive management."""
import json
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import unittest

from keyslot.backend import VaultError
from keyslot.core_backend import Vault, EngineError
import test_passkeys as fixtures

ENGINE, OPENSSL, assertion = fixtures.ENGINE, fixtures.OPENSSL, fixtures.assertion


@unittest.skipUnless(ENGINE and OPENSSL, "Build the passkey helper and supply OpenSSL")
class PasskeyTransferTests(unittest.TestCase):
    setUp = fixtures.NativePasskeyTests.setUp
    prepare = fixtures.NativePasskeyTests.prepare
    register = fixtures.NativePasskeyTests.register

    def entry(self, uuid=None):
        return next(e for e in self.vault.snapshot.entries if e.uuid == uuid) if uuid else self.vault.snapshot.entries[0]

    def exported(self, algorithm=-7):
        registered = self.register(algorithm)
        file = self.root / "public.passkey"
        self.vault.export_passkey(self.entry(), file)
        return registered, file

    def test_upstream_export_roundtrip_protected_storage_and_imported_signature(self):
        for algorithm in (-7, -257, -8):
            with self.subTest(algorithm=algorithm):
                registered = self.register(algorithm)
                entry = self.vault.snapshot.entries[-1]
                file = self.root / (str(algorithm) + ".passkey")
                before = self.path.read_bytes()
                self.vault.export_passkey(entry, file)
                self.assertEqual(self.path.read_bytes(), before)
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
                data = json.loads(file.read_text())
                self.assertEqual(set(data), {"relyingParty", "url", "username", "credentialId", "userHandle", "privateKey"})
                self.assertEqual(data["credentialId"], registered["id"])
                self.assertEqual(data["relyingParty"], "example.org")
                self.assertIn("PRIVATE KEY", data["privateKey"])
                target = Vault(ENGINE)
                self.addCleanup(target.lock)
                target.create(self.root / (str(algorithm) + ".kdbx"), "public destination master")
                target.browser_associate("browser", self.key)
                reviewed = target.inspect_passkey(file)
                self.assertNotIn("privateKey", reviewed)
                self.assertNotIn("PRIVATE KEY", json.dumps(reviewed))
                target.import_passkey(file, reviewed["source_fingerprint"])
                imported = target.snapshot.entries[0]
                self.assertTrue(imported.passkey)
                self.assertEqual(imported.history_count, 0)
                self.assertTrue(imported.group_path.endswith("/Imported Passkeys"))
                self.assertEqual(target.attribute(imported, "KPEX_PASSKEY_PRIVATE_KEY_PEM"), data["privateKey"])
                self.assertTrue(target.attribute_info(imported, "KPEX_PASSKEY_PRIVATE_KEY_PEM")["protected"])
                review = target.browser_prepare_passkey("browser", self.key, "get", assertion(registered["id"]), "https://login.example.org")
                self.assertEqual(len(review["entries"]), 1)
                signed = target.browser_finish_passkey(review["token"], approved=True, entry=imported.uuid.replace("-", ""))
                self.assertEqual(signed["id"], registered["id"])
                public_der, public_pem = self.root / "public.der", self.root / "public.pem"
                public_der.write_bytes(fixtures.decode(registered["response"]["publicKey"]))
                subprocess.run([OPENSSL, "pkey", "-pubin", "-inform", "DER", "-in", str(public_der), "-out", str(public_pem)],
                               check=True, capture_output=True)
                message, signature = self.root / "message", self.root / "signature"
                response = signed["response"]
                message.write_bytes(fixtures.decode(response["authenticatorData"]) +
                                    hashlib.sha256(fixtures.decode(response["clientDataJSON"])).digest())
                signature.write_bytes(fixtures.decode(response["signature"]))
                command = ([OPENSSL, "pkeyutl", "-verify", "-pubin", "-inkey", str(public_pem), "-sigfile", str(signature),
                            "-rawin", "-in", str(message)] if algorithm == -8 else
                           [OPENSSL, "dgst", "-sha256", "-verify", str(public_pem), "-signature", str(signature), str(message)])
                self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
                message.write_bytes(message.read_bytes() + b"tampered")
                self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
                target.lock()
                target.unlock(target.path, "public destination master")
                self.assertTrue(target.snapshot.entries[0].passkey)

    def test_removal_preserves_entry_fields_history_and_recoverable_passkey(self):
        self.vault.save_entry(self.vault.snapshot.root, "Existing login", "bob", "https://example.org", "Notes", "Password")
        entry = self.entry()
        self.register(entry=entry.uuid.replace("-", ""))
        entry = self.entry()
        old_history = entry.history_count
        self.vault.remove_passkey(entry)
        clean = self.entry()
        self.assertFalse(clean.passkey)
        self.assertEqual((clean.title, clean.username, clean.notes), ("Existing login", "bob", "Notes"))
        self.assertEqual(self.vault.attribute(clean), "Password")
        self.assertEqual(clean.history_count, old_history + 1)
        with self.assertRaises(EngineError):
            self.vault.passkey_info(clean)
        self.vault.restore_history(clean, clean.history_count - 1, self.vault.history(clean)[-1]["revision"])
        self.assertTrue(self.entry().passkey)
        self.vault.delete_entry(self.entry())
        with self.assertRaises(EngineError):
            self.vault.remove_passkey(self.entry())

    def test_import_attachment_replacement_requires_review_and_preserves_other_fields(self):
        _, file = self.exported()
        source_entry = self.entry()
        self.vault.save_entry(self.vault.snapshot.root, "Normal login", "bob", "https://example.org", "Keep notes", "Keep password")
        entry = next(e for e in self.vault.snapshot.entries if not e.passkey)
        reviewed = self.vault.inspect_passkey(file)
        self.vault.import_passkey(file, reviewed["source_fingerprint"], entry=entry)
        attached = self.entry(entry.uuid)
        self.assertEqual((attached.username, attached.notes), ("bob", "Keep notes"))
        self.assertEqual(self.vault.attribute(attached), "Keep password")
        metadata = next(info for item, info in self.vault.passkey_list() if item.uuid == attached.uuid)
        self.assertEqual(metadata["username"], "alice")
        self.assertNotIn("privateKey", metadata)
        self.assertEqual(attached.history_count, entry.history_count + 1)
        before = self.path.read_bytes()
        with self.assertRaises(EngineError):
            self.vault.import_passkey(file, reviewed["source_fingerprint"], entry=attached)
        self.assertEqual(self.path.read_bytes(), before)
        self.register()
        replacement = next(e for e in self.vault.snapshot.entries if e.uuid not in {entry.uuid, source_entry.uuid})
        self.vault.export_passkey(replacement, file, overwrite=True)
        reviewed = self.vault.inspect_passkey(file)
        attached = self.entry(entry.uuid)
        self.vault.import_passkey(file, reviewed["source_fingerprint"], entry=attached, replace=True)
        self.assertEqual(self.entry(entry.uuid).history_count, attached.history_count + 1)
        previous = {e.uuid for e in self.vault.snapshot.entries}
        self.vault.import_passkey(file, reviewed["source_fingerprint"], group=self.vault.snapshot.root)
        created = next(e for e in self.vault.snapshot.entries if e.uuid not in previous)
        self.assertEqual(created.group, self.vault.snapshot.root)

    def test_import_review_rejects_changed_malformed_oversized_and_special_sources(self):
        _, file = self.exported()
        reviewed = self.vault.inspect_passkey(file)
        original = file.read_bytes()
        before = self.path.read_bytes()
        file.write_bytes(original + b"\n")
        with self.assertRaises(EngineError):
            self.vault.import_passkey(file, reviewed["source_fingerprint"])
        data = json.loads(original)
        data["unrelatedSecret"] = "must not be returned by review"
        file.write_text(json.dumps(data))
        self.assertNotIn("unrelatedSecret", self.vault.inspect_passkey(file))
        invalid = [b"invalid", b"[]", b"{}", json.dumps({**data, "privateKey": "broken"}).encode(),
                   json.dumps({**data, "privateKey": "-----BEGIN PRIVATE KEY-----\nbroken\n-----END PRIVATE KEY-----"}).encode(),
                   json.dumps({**data, "credentialId": 123}).encode(), b" " * (1024 * 1024 + 1)]
        for value in invalid:
            file.write_bytes(value)
            with self.assertRaises(EngineError):
                self.vault.inspect_passkey(file)
            self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaises(EngineError):
            self.vault.inspect_passkey(self.root)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(EngineError):
            self.vault.inspect_passkey(fifo)
        file.write_bytes(original)
        self.path.write_bytes(before + b"changed")
        with self.assertRaises(EngineError):
            self.vault.import_passkey(file, reviewed["source_fingerprint"])
        self.assertEqual(self.path.read_bytes(), before + b"changed")

    def test_export_no_clobber_bulk_duplicate_names_permissions_and_cross_vault_ownership(self):
        _, file = self.exported()
        entry = self.entry()
        with self.assertRaises(FileExistsError):
            self.vault.export_passkey(entry, file)
        with self.assertRaises(VaultError):
            self.vault.export_passkey(entry, self.path, overwrite=True)
        with self.assertRaises(EngineError):
            self.vault._rpc("passkey.export", entry=entry.uuid, path=str(self.path))
        with self.assertRaises(EngineError):
            self.vault._rpc("passkey.export", entry=entry.uuid, path=str(file))
        self.register()
        folder = self.root / "exports"
        folder.mkdir()
        plan = self.vault.plan_passkey_exports(self.vault.snapshot.entries, folder)
        self.assertEqual(len({path.name for _, path in plan}), 2)
        self.assertTrue(all(path.parent == folder and path.suffix == ".passkey" for _, path in plan))
        self.assertEqual(self.vault.export_passkeys(plan), 2)
        for _, path in plan:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        before = [path.read_bytes() for _, path in plan]
        with self.assertRaises(VaultError):
            self.vault.export_passkeys(plan)
        self.assertEqual([path.read_bytes() for _, path in plan], before)
        self.assertEqual(self.vault.export_passkeys(plan, overwrite=True), 2)
        other = Vault(ENGINE)
        self.addCleanup(other.lock)
        other.unlock(self.path, self.master)
        with self.assertRaises(VaultError):
            other.passkey_info(entry)
        with self.assertRaises(VaultError):
            self.vault.export_passkeys([])

    def test_bulk_partial_failure_reports_completed_files_and_recycled_import_is_rejected(self):
        _, source = self.exported()
        first = self.entry()
        self.register()
        second = next(e for e in self.vault.snapshot.entries if e.uuid != first.uuid)
        before = self.path.read_bytes()
        plan = [(first, self.root / "first.passkey"), (second, self.root / "missing-folder/second.passkey")]
        with self.assertRaisesRegex(VaultError, "Exported 1 of 2"):
            self.vault.export_passkeys(plan)
        self.assertTrue(plan[0][1].is_file())
        self.assertFalse(plan[1][1].exists())
        self.assertEqual(self.path.read_bytes(), before)
        reviewed = self.vault.inspect_passkey(source)
        self.vault.delete_entry(second)
        recycled = self.entry(second.uuid)
        before = self.path.read_bytes()
        with self.assertRaises(EngineError):
            self.vault.import_passkey(source, reviewed["source_fingerprint"], entry=recycled, replace=True)
        with self.assertRaises(EngineError):
            self.vault.import_passkey(source, reviewed["source_fingerprint"], group=recycled.group)
        self.assertEqual(self.path.read_bytes(), before)
