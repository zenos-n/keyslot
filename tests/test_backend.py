import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

from keyslot.backend import Vault, VaultError, fingerprint, parse_snapshot, cli_token


class ParserTests(unittest.TestCase):
    def test_duplicates_and_protected_values(self):
        xml = b'''<KeePassFile><Meta/><Root><Group><Name>Root</Name>
        <Entry><UUID>1</UUID><String><Key>Title</Key><Value>Same</Value></String>
        <String><Key>Password</Key><Value Protected="True">secret</Value></String>
        <String><Key>UserName</Key><Value Protected="True">private</Value></String></Entry>
        <Entry><UUID>2</UUID><String><Key>Title</Key><Value>Same</Value></String></Entry>
        </Group></Root></KeePassFile>'''
        snapshot = parse_snapshot(xml)
        self.assertFalse(snapshot.entries[0].addressable)
        self.assertEqual(snapshot.entries[0].username, "")
        self.assertNotIn("secret", repr(snapshot))
        with self.assertRaises(VaultError):
            cli_token("entry\nrm /Other")


@unittest.skipUnless(shutil.which("keepassxc-cli"), "KeePassXC is required")
class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "vault.kdbx"
        self.vault = Vault()
        self.vault.create(self.path, "master-test-password")

    def tearDown(self):
        self.vault.lock()
        self.tmp.cleanup()

    def test_crud_quotes_backup_and_preservation(self):
        self.vault.add_group("/", 'A "quoted" group')
        group = '/A "quoted" group/'
        title = 'A "title" \\ with spaces'
        password = 'p@ss \\" ; rm /never'
        self.vault.save_entry(group, title, 'a "user"', "https://example.org", "A 'note' \\ text", password)
        entry = next(e for e in self.vault.snapshot.entries if e.title == title)
        self.assertEqual(self.vault.attribute(entry), password)
        self.assertEqual(entry.username, 'a "user"')
        with self.assertRaises(VaultError):
            self.vault.save_entry(group, title, "", entry.url, entry.notes, None, entry)
        self.vault.save_entry(group, title, "new user", entry.url, "A multiline\nnote", None, entry)
        entry = next(e for e in self.vault.snapshot.entries if e.title == title)
        self.assertEqual(entry.username, "new user")
        self.assertEqual(entry.notes, "A multiline\nnote")
        self.assertEqual(self.vault.attribute(entry), password)
        self.assertGreater(entry.history_count, 0)
        self.vault.save_entry(group, title, entry.username, entry.url, entry.notes, "changed-password", entry)
        entry = next(e for e in self.vault.snapshot.entries if e.title == title)
        self.assertEqual(self.vault.attribute(entry), "changed-password")
        backup = Path(str(self.path) + ".keyslot.bak")
        self.assertTrue(backup.is_file())
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        original = self.tmp.name + "/hello.txt"
        Path(original).write_bytes(b"attachment data")
        self.vault.import_attachment(entry, original)
        entry = next(e for e in self.vault.snapshot.entries if e.title == title)
        self.assertIn("hello.txt", entry.attachments)
        output = Path(self.tmp.name) / "export.txt"
        self.vault.export_attachment(entry, "hello.txt", output)
        self.assertEqual(output.read_bytes(), b"attachment data")
        self.vault.delete_entry(entry)
        self.assertTrue(any(e.recycled and e.title == title for e in self.vault.snapshot.entries))

    def test_external_changes_refused_and_locked_secrets(self):
        self.vault.save_entry("/", "Example", "u", "", "", "secret")
        entry = self.vault.snapshot.entries[0]
        subprocess.run(["keepassxc-cli", "mkdir", "-q", str(self.path), "External"],
                       input=b"master-test-password\n", check=True, capture_output=True)
        before = fingerprint(self.path)
        with self.assertRaises(VaultError):
            self.vault.save_entry("/", "Example", "new", "", "", None, entry)
        self.assertEqual(before, fingerprint(self.path))
        self.vault.lock()
        with self.assertRaises(VaultError):
            self.vault.attribute(entry)
        self.assertEqual(self.vault._password, bytearray())

    def test_wrong_password_no_overwrite_and_generator(self):
        second = Vault()
        with self.assertRaises(VaultError):
            second.unlock(self.path, "wrong")
        self.assertFalse(second.unlocked)
        self.assertEqual(second._password, bytearray())
        before = fingerprint(self.path)
        with self.assertRaises(VaultError):
            second.create(self.path, "different")
        self.assertEqual(before, fingerprint(self.path))
        self.assertEqual(len(self.vault.generate(32)), 32)
        self.assertEqual(len(self.vault.generate(6, passphrase=True).split()), 6)

    def test_keyfile_only_and_move(self):
        keyfile = Path(self.tmp.name) / "key"
        keyfile.write_bytes(os.urandom(64))
        path = Path(self.tmp.name) / "keyfile.kdbx"
        subprocess.run(["keepassxc-cli", "db-create", "-q", "--set-key-file", str(keyfile), str(path)],
                       check=True, capture_output=True)
        self.vault.unlock(path, "", keyfile=str(keyfile), no_password=True)
        self.vault.save_entry("/", "Entry", "user", "", "", "secret")
        self.vault.add_group("/", "Destination")
        self.vault.move_entry(self.vault.snapshot.entries[0], "/Destination/")
        self.assertEqual(self.vault.snapshot.entries[0].group, "/Destination/")

    def test_failed_transaction_does_not_replace_database(self):
        before = fingerprint(self.path)
        with self.assertRaises(VaultError):
            self.vault._mutate(["edit", "--username=changed", "--", "/Not Present"])
        self.assertEqual(before, fingerprint(self.path))
        self.assertFalse(Path(str(self.path) + ".keyslot.bak").exists())

    def test_totp_custom_attributes_and_metadata_survive_edit(self):
        self.vault.save_entry("/", "OTP Login", "user", "", "", "secret")
        xml = self.vault._run(["export", "-q", str(self.path)], b"master-test-password\n")
        root = ET.fromstring(xml)
        node = root.find("Root/Group/Entry")
        for name, value in [("otp", "otpauth://totp/Demo?secret=JBSWY3DPEHPK3PXP&issuer=Demo"),
                            ("API Token", "private-custom-value")]:
            field = ET.SubElement(node, "String")
            ET.SubElement(field, "Key").text = name
            ET.SubElement(field, "Value", ProtectInMemory="True").text = value
        root.find("Meta/RecycleBinEnabled").text = "False"
        fixture = Path(self.tmp.name) / "public-test-fixture.xml"
        fixture.write_bytes(ET.tostring(root, encoding="utf-8", xml_declaration=True))
        imported = Path(self.tmp.name) / "imported.kdbx"
        subprocess.run(["keepassxc-cli", "import", "-q", "-p", str(fixture), str(imported)],
                       input=b"master-test-password\nmaster-test-password\n", check=True, capture_output=True)
        self.vault.unlock(imported, "master-test-password")
        entry = self.vault.snapshot.entries[0]
        self.assertTrue(entry.totp)
        self.assertNotIn("private-custom-value", repr(self.vault.snapshot))
        self.assertRegex(self.vault.attribute(entry, totp=True), r"^\d{6}$")
        self.assertEqual(self.vault.attribute(entry, "API Token"), "private-custom-value")
        self.vault.save_entry("/", entry.title, "changed", "", "", None, entry)
        entry = self.vault.snapshot.entries[0]
        self.assertEqual(self.vault.attribute(entry, "API Token"), "private-custom-value")
        before = fingerprint(imported)
        with self.assertRaises(VaultError):
            self.vault.delete_entry(entry)
        self.assertEqual(before, fingerprint(imported))


if __name__ == "__main__":
    unittest.main()
