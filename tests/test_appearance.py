"""Native KDBX icon and advanced-metadata interoperability and rollback."""
import hashlib
import base64
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
import uuid
import xml.etree.ElementTree as ET
import zlib
from keyslot.core_backend import Vault, EngineError
from keyslot.backend import VaultError

ENGINE = os.environ.get("KEYSLOT_ENGINE") or shutil.which("keyslot-engine")


def png(width=8, height=4):
    def chunk(kind, data):
        return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data) & 0xffffffff)
    rows = (b"\0" + bytes((30, 160, 220, 255)) * width) * height
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack("!IIBBBBB", width, height, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")


@unittest.skipUnless(ENGINE, "native engine required")
class Appearance(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="keyslot-appearance-")
        self.directory = Path(self.temporary.name)
        self.path = self.directory / "vault.kdbx"
        self.vault = Vault(ENGINE)
        self.vault.create(self.path, "public fixture master")
        self.vault.add_group(self.vault.snapshot.root, "Group")
        self.group = next(g.uuid for g in self.vault.snapshot.groups if g.name == "Group")
        self.vault.save_entry(self.group, "Fixture Entry", "public user", "https://example.org", "public notes", "public fixture password")
        self.identifier = self.entry().uuid
        self.image = self.directory / "Blue.png"
        self.image.write_bytes(png())

    def tearDown(self):
        self.vault.lock()
        self.temporary.cleanup()

    def entry(self):
        return next(entry for entry in self.vault.snapshot.entries if entry.title == "Fixture Entry")

    def save(self, **options):
        entry = self.entry()
        return self.vault.save_entry(entry.group, entry.title, entry.username, entry.url, entry.notes, entry=entry, **options)

    def test_all_standard_icons_are_real_distinct_bounded_png_assets(self):
        catalogue = self.vault.icons()
        self.assertEqual([item["icon"] for item in catalogue["standard"]], list(range(69)))
        hashes = set()
        for number in range(69):
            raw = self.vault.icon(number)
            self.assertTrue(raw.startswith(b"\x89PNG\r\n\x1a\n"))
            self.assertLessEqual(max(struct.unpack("!II", raw[16:24])), 128)
            hashes.add(hashlib.sha256(raw).digest())
        self.assertGreater(len(hashes), 60)

    def test_import_deduplicates_preserves_small_images_and_exports_without_clobber(self):
        icon = self.vault.import_icon(self.image)
        self.assertEqual(self.vault.import_icon(self.image), icon)
        self.assertEqual(self.vault.icons()["total"], 1)
        self.assertEqual(self.vault.icons()["custom"][0]["name"], "Blue")
        self.assertEqual(struct.unpack("!II", self.vault.icon(custom_icon=icon)[16:24]), (8, 4))
        target = self.directory / "Export.png"
        self.vault.export_icon(icon, target)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        original = target.read_bytes()
        with self.assertRaises(FileExistsError):
            self.vault.export_icon(icon, target)
        self.assertEqual(target.read_bytes(), original)
        with self.assertRaises(VaultError):
            self.vault.export_icon(icon, self.path, overwrite=True)
        self.assertTrue(self.vault.unlocked)

    def test_svg_import_has_no_base_uri_and_scales_to_upstream_icon_size(self):
        source = self.directory / "Vector.svg"
        source.write_text('<svg xmlns="http://www.w3.org/2000/svg" width="512" height="256"><rect width="512" height="256" fill="red"/><text x="8" y="30">Fixture</text></svg>')
        icon = self.vault.import_icon(source)
        self.assertEqual(struct.unpack("!II", self.vault.icon(custom_icon=icon)[16:24]), (128, 64))
        self.assertEqual(self.vault.icons()["custom"][0]["name"], "Vector")

    def test_entry_appearance_and_advanced_fields_roundtrip_and_preserve_credentials_history(self):
        icon = self.vault.import_icon(self.image)
        self.save(icon=12, custom_icon=icon, foreground="#abcd12", background="#80445566",
                  override_url="https://example.org/{USERNAME}", exclude_reports=True)
        entry = self.entry()
        self.assertEqual((entry.icon, entry.custom_icon, entry.foreground, entry.background), (0, icon, "#abcd12", "#80445566"))
        self.assertTrue(entry.exclude_reports)
        self.assertTrue(self.vault.history(entry))
        self.assertEqual(self.vault.attribute(entry), "public fixture password")
        self.assertNotIn(entry.uuid, [item["uuid"] for item in self.vault.report()["health"]])
        self.vault.lock()
        self.vault.unlock(self.path, "public fixture master")
        entry = self.entry()
        self.assertEqual(entry.override_url, "https://example.org/{USERNAME}")
        self.assertEqual(entry.custom_icon, icon)
        self.save(icon=25, custom_icon="", foreground="", background="", exclude_reports=False)
        self.assertEqual((self.entry().icon, self.entry().custom_icon), (25, ""))

    def test_group_settings_inheritance_search_and_expiry(self):
        icon = self.vault.import_icon(self.image)
        self.vault.save_group(self.group, "Group", "Notes", custom_icon=icon, tags="a;b", searching=2,
                              expires=True, expiry="2020-01-01T00:00:00Z")
        group = next(g for g in self.vault.snapshot.groups if g.uuid == self.group)
        self.assertEqual((group.custom_icon, group.tags, group.searching), (icon, "a;b", 2))
        self.assertTrue(group.expired)
        self.assertEqual(self.vault.search("Fixture Entry"), [])
        self.vault.save_entry(self.group, "Inherited", "", "", "", "public inherited password")
        self.assertEqual(next(e for e in self.vault.snapshot.entries if e.title == "Inherited").custom_icon, icon)
        self.vault.save_group(self.group, "Group", "Notes", searching=1, expires=False)
        self.assertIn(self.entry().uuid, self.vault.search("Fixture Entry"))
        self.vault.lock()
        self.vault.unlock(self.path, "public fixture master")
        group = next(g for g in self.vault.snapshot.groups if g.uuid == self.group)
        self.assertEqual(group.searching, 1)
        self.assertEqual(group.tags, "a;b")
        self.assertFalse(group.expires)

    def test_removing_used_icon_repairs_current_and_history_references(self):
        icon = self.vault.import_icon(self.image)
        self.save(custom_icon=icon)
        self.save(tags="another version")
        self.vault.save_group(self.group, "Group", "Notes", custom_icon=icon)
        before = len(self.vault.history(self.entry()))
        self.assertGreaterEqual(self.vault.icons()["custom"][0]["uses"], 3)
        self.vault.remove_icon(icon)
        self.assertEqual(self.vault.icons()["total"], 0)
        self.assertEqual(self.entry().custom_icon, "")
        self.assertGreaterEqual(len(self.vault.history(self.entry())), before)
        exported = self.directory / "Review.xml"
        self.vault.export_database(exported)
        xml = ET.fromstring(exported.read_bytes())
        encoded = base64.b64encode(uuid.UUID(icon).bytes).decode()
        self.assertNotIn(encoded, [node.text for node in xml.iter("CustomIconUUID")])
        self.assertEqual(self.vault.attribute(self.entry()), "public fixture password")
        self.vault.lock()
        self.vault.unlock(self.path, "public fixture master")
        self.assertFalse(any(entry.custom_icon for entry in self.vault.snapshot.entries))

    def test_invalid_decorations_roll_back_all_fields_and_leave_vault_usable(self):
        for values in ({"icon": -1}, {"icon": 69}, {"custom_icon": "not-a-uuid"},
                       {"foreground": "not-a-color"}, {"background": "x; color:red"}):
            before = self.path.read_bytes()
            with self.subTest(values=values), self.assertRaises(EngineError):
                self.save(**values)
            self.assertEqual(self.path.read_bytes(), before)
            self.assertEqual(self.vault.attribute(self.entry()), "public fixture password")
        for options in ({"searching": 3}, {"expiry": "not-a-date"}):
            before = self.path.read_bytes()
            with self.subTest(options=options), self.assertRaises(EngineError):
                self.vault.save_group(self.group, "Changed", "Changed", **options)
            self.assertEqual(self.path.read_bytes(), before)

    def test_malformed_or_oversized_images_do_not_change_database(self):
        before = self.path.read_bytes()
        for name, data in (("broken.png", b"not an image"), ("huge.png", png(5000, 1))):
            source = self.directory / name
            source.write_bytes(data)
            with self.subTest(name=name), self.assertRaises(EngineError):
                self.vault.import_icon(source)
            self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(self.vault.unlocked)
