"""Real native history reads, protection, revision guards and saved restoration."""
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
import xml.etree.ElementTree as ET

from keyslot.backend import VaultError
from keyslot.core_backend import Vault, EngineError

ENGINE = os.environ.get("KEYSLOT_ENGINE") or shutil.which("keyslot-engine")


@unittest.skipUnless(ENGINE, "native engine required")
class History(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="keyslot-history-")
        self.directory = Path(self.temporary.name)
        self.path = self.directory / "History.kdbx"
        self.vault = Vault(ENGINE)
        self.vault.create(self.path, "public fixture master")
        self.vault.save_entry(self.vault.snapshot.root, "Old <Title>", "old-user", "https://example.org/old",
                              "Old notes\nSecond line\n{PASSWORD}", "public old secret")
        self.uuid = self.live().uuid
        self.vault.set_attribute(self.live(), "Protected", "public protected secret", True)
        self.vault.set_attribute(self.live(), "Unprotected Custom", "public unflagged custom secret", False)
        self.vault.set_attribute(self.live(), "Empty", "", False)
        self.file = self.directory / "Attachment.bin"
        self.file.write_bytes(b"public old attachment\x00\xff")
        self.vault.import_attachment(self.live(), self.file)
        self.old_index = self.live().history_count
        self.save(title="New Title", username="new-user", password="public new secret", notes="New notes ☃",
                  tags="history;fixture", icon=12, foreground="#aabbcc", override_url="cmd://example {PASSWORD}",
                  exclude_reports=True, expires=True, expiry="2029-01-01T00:00:00Z")

    def tearDown(self):
        self.vault.lock()
        self.temporary.cleanup()

    def live(self):
        return next(entry for entry in self.vault.snapshot.entries if not hasattr(self, "uuid") or entry.uuid == self.uuid)

    def save(self, **options):
        entry = self.live()
        self.vault.save_entry(entry.group, options.pop("title", entry.title), options.pop("username", entry.username),
            options.pop("url", entry.url), options.pop("notes", entry.notes), entry=entry, **options)

    def revision(self):
        return self.vault.history(self.live())[0]["revision"]

    def comparison(self, left=None, right=-1):
        return self.vault.compare_history(self.live(), self.old_index if left is None else left, right, self.revision())

    def rows(self, data, section):
        return {row["key"]: row for group in data["sections"] if group["section"] == section for row in group["rows"]}

    def value(self, index, section, key):
        return self.vault.history_value(self.live(), index, self.revision(), section, key)

    def test_full_comparison_masks_secrets_and_does_not_write(self):
        before = self.path.read_bytes()
        data = self.comparison()
        fields = self.rows(data, "attributes")
        self.assertEqual(fields["Title"]["left"]["value"], "Old <Title>")
        self.assertTrue(fields["Title"]["changed"])
        self.assertEqual(fields["Notes"]["left"]["value"], "Old notes\nSecond line\n{PASSWORD}")
        for name in ("Password", "Protected", "Unprotected Custom", "Empty"):
            self.assertNotIn("value", fields[name]["left"])
            self.assertTrue(fields[name]["left"]["protected"])
        wire = json.dumps(data)
        for secret in ("public old secret", "public new secret", "public protected secret", "public unflagged custom secret"):
            self.assertNotIn(secret, wire)
        properties = self.rows(data, "properties")
        self.assertTrue(properties["Icon"]["changed"])
        self.assertTrue(properties["Tags"]["changed"])
        self.assertTrue(properties["Expires"]["changed"])
        self.assertTrue(properties["URL Override"]["right"]["protected"])
        self.assertNotIn("value", properties["URL Override"]["right"])
        self.assertEqual({group["section"] for group in data["sections"]}, {"attributes", "properties", "autotype", "data", "attachments"})
        self.assertGreater(data["changed"], 7)
        self.assertEqual(self.path.read_bytes(), before)

    def test_explicit_reveal_is_version_specific_and_literals_are_not_resolved(self):
        self.assertEqual(self.value(self.old_index, "attributes", "Password"), "public old secret")
        self.assertEqual(self.value(-1, "attributes", "Password"), "public new secret")
        self.assertEqual(self.value(self.old_index, "attributes", "Empty"), "")
        self.assertEqual(self.value(-1, "properties", "URL Override"), "cmd://example {PASSWORD}")
        self.assertEqual(self.value(self.old_index, "attributes", "Protected"), "public protected secret")
        with self.assertRaises(EngineError):
            self.value(-1, "attributes", "Missing")
        with self.assertRaises(EngineError):
            self.value(-1, "not-a-section", "Password")

    def test_compare_identical_and_two_historical_versions(self):
        self.assertEqual(self.comparison(self.old_index, self.old_index)["changed"], 0)
        self.assertEqual(self.comparison(-1, -1)["changed"], 0)
        self.file.write_bytes(b"new bytes with identical filename")
        self.vault.import_attachment(self.live(), self.file, replace=True)
        latest = self.live().history_count - 1
        data = self.comparison(self.old_index, latest)
        self.assertTrue(self.rows(data, "attributes")["Password"]["changed"])
        self.assertFalse(self.rows(data, "attachments")[self.file.name]["changed"])
        self.assertTrue(self.rows(self.comparison(latest), "attachments")[self.file.name]["changed"])

    def test_added_removed_empty_and_protection_only_fields_are_distinct(self):
        self.vault.remove_attribute(self.live(), "Empty")
        self.vault.set_attribute(self.live(), "Added", "", True)
        self.vault.set_attribute(self.live(), "Unprotected Custom", "public unflagged custom secret", True)
        rows = self.rows(self.comparison(), "attributes")
        self.assertTrue(rows["Empty"]["left"]["present"])
        self.assertFalse(rows["Empty"]["right"]["present"])
        self.assertFalse(rows["Added"]["left"]["present"])
        self.assertTrue(rows["Added"]["right"]["present"])
        self.assertTrue(rows["Unprotected Custom"]["changed"])
        self.assertFalse(rows["Unprotected Custom"]["left"]["storage_protected"])
        self.assertTrue(rows["Unprotected Custom"]["right"]["storage_protected"])

    def test_attachment_metadata_and_version_export_no_clobber_or_vault_write(self):
        old = self.file.read_bytes()
        self.file.write_bytes(b"new attachment")
        self.vault.import_attachment(self.live(), self.file, replace=True)
        rows = self.rows(self.comparison(), "attachments")
        self.assertTrue(rows[self.file.name]["changed"])
        self.assertNotIn("public old attachment", json.dumps(rows))
        target = self.directory / "export.bin"
        before = self.path.read_bytes()
        self.vault.export_history_attachment(self.live(), self.old_index, self.revision(), self.file.name, target)
        self.assertEqual(target.read_bytes(), old)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            self.vault.export_history_attachment(self.live(), -1, self.revision(), self.file.name, target)
        with self.assertRaises(VaultError):
            self.vault.export_history_attachment(self.live(), -1, self.revision(), self.file.name, self.path)
        self.assertEqual(target.read_bytes(), old)
        self.assertEqual(self.path.read_bytes(), before)

    def test_stale_revision_refuses_read_reveal_export_restore_remove_and_clear(self):
        revision = self.revision()
        self.vault.set_attribute(self.live(), "More", "value")
        before = self.path.read_bytes()
        operations = [
            lambda: self.vault.compare_history(self.live(), self.old_index, -1, revision),
            lambda: self.vault.history_value(self.live(), self.old_index, revision, "attributes", "Password"),
            lambda: self.vault.export_history_attachment(self.live(), self.old_index, revision, self.file.name, self.directory / "bad.bin"),
            lambda: self.vault.restore_history(self.live(), self.old_index, revision),
            lambda: self.vault.remove_history(self.live(), self.old_index, revision),
            lambda: self.vault.clear_history(self.live(), revision)]
        for operation in operations:
            with self.assertRaises(EngineError) as error:
                operation()
            self.assertEqual(error.exception.code, "conflict")
        self.assertFalse((self.directory / "bad.bin").exists())
        self.assertEqual(self.path.read_bytes(), before)

    def test_invalid_native_requests_and_foreign_entry_are_rejected(self):
        for index in (True, -2, .5, "0", 10**8):
            with self.assertRaises(EngineError):
                self.vault._rpc("history.compare", entry=self.uuid, left=index, right=-1, revision=self.revision())
        for method in ("history.restore", "history.remove"):
            with self.assertRaises(EngineError):
                self.vault._rpc(method, entry=self.uuid, index=-1, revision=self.revision())
        with self.assertRaises(EngineError):
            self.vault._rpc("history.clear", entry=self.uuid)
        with self.assertRaises(EngineError):
            self.vault._rpc("history.compare", entry="00000000-0000-0000-0000-000000000001", left=0, right=-1, revision=self.revision())

    def test_restore_keeps_current_version_and_roundtrips_full_selected_entry(self):
        self.vault.restore_history(self.live(), self.old_index, self.revision())
        entry = self.live()
        self.assertEqual(entry.title, "Old <Title>")
        self.assertEqual(entry.uuid, self.uuid)
        self.assertEqual(self.vault.attribute(entry), "public old secret")
        self.assertFalse(entry.exclude_reports)
        self.assertNotEqual(entry.icon, 12)
        self.assertIn("Attachment.bin", entry.attachments)
        revision = self.revision()
        secrets = [self.vault.history_value(entry, item["index"], revision, "attributes", "Password")
                   for item in self.vault.history(entry)]
        self.assertIn("public new secret", secrets)
        self.vault.lock()
        self.vault.unlock(self.path, "public fixture master")
        self.assertEqual(self.live().title, "Old <Title>")
        self.assertEqual(self.vault.attribute(self.live()), "public old secret")
        self.assertEqual(self.value(-1, "attributes", "Protected"), "public protected secret")

    def test_delete_and_clear_preserve_current_and_reject_old_indices(self):
        revision = self.revision()
        count = self.live().history_count
        self.vault.remove_history(self.live(), self.old_index, revision)
        self.assertEqual(self.live().history_count, count - 1)
        with self.assertRaises(EngineError):
            self.vault.remove_history(self.live(), self.old_index, revision)
        self.vault.clear_history(self.live(), self.revision())
        self.assertEqual(self.vault.history(self.live()), [])
        self.assertEqual(self.vault.attribute(self.live()), "public new secret")
        self.vault.lock()
        self.vault.unlock(self.path, "public fixture master")
        self.assertEqual(self.live().history_count, 0)

    def test_external_changes_and_readonly_failure_keep_data(self):
        self.path.chmod(0o400)
        before = self.path.read_bytes()
        with self.assertRaises(EngineError):
            self.vault.clear_history(self.live(), self.revision())
        self.assertEqual(self.path.read_bytes(), before)
        self.assertGreater(self.live().history_count, 0)
        self.path.chmod(0o600)
        revision = self.revision()
        with self.path.open("ab") as stream:
            stream.write(b"external fixture change")
        with self.assertRaises(EngineError):
            self.vault.history(self.live())
        with self.assertRaises(EngineError):
            self.vault.compare_history(self.live(), 0, -1, revision)
        self.assertTrue(self.vault.unlocked)
        entry = self.live()
        self.vault.lock()
        with self.assertRaises(VaultError):
            self.vault.compare_history(entry, 0, -1, revision)

    def test_totp_autotype_and_imported_custom_data_stay_hidden_until_requested(self):
        uri = "otpauth://totp/Fixture?secret=JBSWY3DPEHPK3PXP&issuer=Fixture"
        self.vault.set_totp(self.live(), uri)
        self.vault.save_autotype_settings(entry=self.live(), enabled=True,
            sequence="public literal autotype secret{ENTER}", associations=[{"window":"Fixture", "sequence":"{USERNAME}"}])
        source = self.directory / "Fixture.xml"
        self.vault.export_database(source)
        root = ET.parse(source)
        current = root.find(".//Root/Group/Entry")
        data = current.find("CustomData")
        if data is None:
            data = ET.SubElement(current, "CustomData")
        item = ET.SubElement(data, "Item")
        ET.SubElement(item, "Key").text = "Private Integration State"
        ET.SubElement(item, "Value").text = "public customdata secret"
        for version in [current] + current.findall("History/Entry"):
            for string in version.findall("String"):
                if string.findtext("Key") in {"Title", "UserName", "URL", "Notes"}:
                    string.find("Value").set("ProtectInMemory", "True")
        root.write(source, encoding="utf-8", xml_declaration=True)
        self.vault.lock()
        self.vault.import_database(self.directory / "Imported.kdbx", source, "xml", "public imported master")
        listing = self.vault.history(self.live())
        self.assertTrue(all(not item["title"] and not item["username"] for item in listing))
        result = self.comparison()
        wire = json.dumps(result)
        for secret in ("JBSWY3DPEHPK3PXP", "public literal autotype secret", "public customdata secret", "old-user", "New notes"):
            self.assertNotIn(secret, wire)
        for name in ("Title", "UserName", "URL", "Notes"):
            self.assertTrue(self.rows(result, "attributes")[name]["right"]["protected"])
        self.assertIn("JBSWY3DPEHPK3PXP", self.value(-1, "properties", "One-Time Password Settings"))
        self.assertIn("public literal autotype secret", self.value(-1, "autotype", "Default Sequence"))
        self.assertIn("public customdata secret", self.value(-1, "data", "Private Integration State"))

    def test_plain_xml_with_encrypted_marker_is_rejected_without_crashing_helper(self):
        source = self.directory / "Malformed.xml"
        self.vault.export_database(source)
        root = ET.parse(source)
        value = next(string.find("Value") for string in root.findall(".//Root/Group/Entry/String")
                     if string.findtext("Key") == "Password")
        value.set("Protected", "True")
        root.write(source, encoding="utf-8", xml_declaration=True)
        before = source.read_bytes()
        with self.assertRaises(EngineError) as error:
            self.vault.inspect_import(source, "xml")
        self.assertEqual(error.exception.code, "import_error")
        self.assertTrue(self.vault.unlocked)
        self.assertEqual(self.vault.attribute(self.live()), "public new secret")
        self.assertEqual(source.read_bytes(), before)
