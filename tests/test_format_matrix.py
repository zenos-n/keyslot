"""Release acceptance for real encrypted format/cipher/KDF round trips."""
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest

from keyslot.core_backend import Vault

ENGINE = os.environ.get("KEYSLOT_ENGINE") or shutil.which("keyslot-engine")
FIXTURES = os.environ.get("KEYSLOT_UPSTREAM_TEST_DATA")
if os.environ.get("KEYSLOT_REQUIRE_ENGINE") == "1" and not (ENGINE and FIXTURES):
    raise RuntimeError("Format acceptance requires the real engine and upstream fixtures.")


@unittest.skipUnless(ENGINE and FIXTURES, "native engine and upstream fixtures required")
class FormatMatrix(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="keyslot-formats-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.vault = Vault(ENGINE)
        self.addCleanup(self.vault.lock)

    def contents(self):
        return sorted((entry.uuid, entry.group, entry.title, entry.username, entry.url, entry.notes,
                       entry.history_count, entry.icon, entry.tags, self.vault.attribute(entry),
                       tuple((name, self.vault.attribute_info(entry, name)["value"],
                              self.vault.attribute_info(entry, name)["protected"])
                             for name in sorted(entry.attributes)), tuple(sorted(entry.attachments)))
                      for entry in self.vault.snapshot.entries)

    def test_every_advertised_cipher_kdf_and_compression_combination(self):
        path = self.directory / "Matrix.kdbx"
        self.vault.create(path, "public fixture master")
        defaults = self.vault.settings()
        self.assertGreaterEqual(defaults["format"] >> 16, 4)
        self.assertEqual(defaults["kdf"], "9e298b19-56db-4773-b23d-fc3ec6f0a1e6")
        self.assertEqual(defaults["memory_kib"], 65536)
        self.assertEqual(defaults["rounds"], 10)
        self.vault.save_entry(self.vault.snapshot.root, "Fixture ☃", "alice", "https://example.org", "Notes\nSecond line", "public old password")
        entry = self.vault.snapshot.entries[0]
        self.vault.set_attribute(entry, "Protected fixture", "public protected value", True)
        entry = self.vault.snapshot.entries[0]
        attachment = self.directory / "Fixture.bin"
        attachment.write_bytes(b"public binary fixture\x00\xff")
        self.vault.import_attachment(entry, attachment)
        entry = self.vault.snapshot.entries[0]
        self.vault.save_entry(entry.group, entry.title, entry.username, entry.url, entry.notes,
                              "public new password ☃", entry, tags="fixture;matrix", icon=12)
        expected = self.contents()
        settings = self.vault.settings()
        self.assertEqual(len(settings["ciphers"]), 3)
        self.assertEqual(len(settings["kdfs"]), 3)
        for cipher in settings["ciphers"]:
            for kdf in settings["kdfs"]:
                for compression in (False, True):
                    with self.subTest(cipher=cipher["name"], kdf=kdf["name"], compression=compression):
                        parameters = {"cipher": cipher["id"], "kdf": kdf["id"], "compression": compression,
                                      "rounds": 2 if kdf["supports_memory"] else 1000}
                        if kdf["supports_memory"]:
                            parameters.update(memory_kib=8192, parallelism=1)
                        self.vault.save_settings(**parameters)
                        self.vault.lock()
                        self.vault.unlock(path, "public fixture master")
                        reopened = self.vault.settings()
                        for field, value in parameters.items():
                            self.assertEqual(reopened[field], value)
                        self.assertEqual(self.contents(), expected)
                        exported = self.directory / "Restored.bin"
                        self.vault.export_attachment(self.vault.snapshot.entries[0], attachment.name, exported)
                        self.assertEqual(exported.read_bytes(), attachment.read_bytes())
                        exported.unlink()

    def test_upstream_kdbx3_and_kdbx4_fixtures_keep_format_and_content_in_encrypted_copies(self):
        for name, password, major in (("Format300.kdbx", "a", 3), ("Format400.kdbx", "t", 4)):
            with self.subTest(format=major):
                source = Path(FIXTURES) / name
                original = source.read_bytes()
                path = self.directory / name
                path.write_bytes(original)
                self.vault.unlock(path, password)
                expected = self.contents()
                self.assertTrue(expected)
                copy = self.directory / ("Copy-" + name)
                self.vault.save_copy(copy)
                self.vault.lock()
                self.assertEqual(struct.unpack_from("<I", copy.read_bytes(), 8)[0] >> 16, major)
                self.vault.unlock(copy, password)
                self.assertEqual(self.contents(), expected)
                self.assertEqual(path.read_bytes(), original)
                self.assertEqual(source.read_bytes(), original)
                self.vault.lock()
