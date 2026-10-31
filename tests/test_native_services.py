"""Auto-type compatibility and KeeShare interoperability with disposable encrypted vaults."""
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest
import zipfile

from keyslot.core_backend import Vault, EngineError

ENGINE = os.environ.get("KEYSLOT_ENGINE") or shutil.which("keyslot-engine")
if os.environ.get("KEYSLOT_REQUIRE_ENGINE") and not ENGINE:
    raise RuntimeError("The native engine is required for these release checks.")


@unittest.skipUnless(ENGINE, "native KeePassXC engine required")
class NativeServices(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="keyslot-services-")
        self.directory = Path(self.temporary.name)
        self.path = self.directory / "main.kdbx"
        self.vault = Vault(ENGINE)
        self.vault.create(self.path, "public fixture master")
        self.vault.add_group(self.vault.snapshot.root, "Shared")
        self.group = next(g.uuid for g in self.vault.snapshot.groups if g.name == "Shared")
        self.vault.save_entry(self.group, "Example", "fixture-user", "https://example.org", "public notes", "aBc123")
        self.identifier = self.vault.snapshot.entries[0].uuid
        self.others = []

    def tearDown(self):
        for vault in self.others:
            vault.lock()
        self.vault.lock()
        self.temporary.cleanup()

    def entry(self):
        return next(e for e in self.vault.snapshot.entries if e.uuid == self.identifier)

    def other(self, path=None, password="public share password"):
        vault = Vault(ENGINE)
        if path:
            vault.unlock(path, password)
        else:
            vault.create(self.directory / f"other-{len(self.others)}.kdbx", password)
        self.others.append(vault)
        return vault

    def plan(self, sequence, pick=()):
        before = self.vault.autotype_prepare(self.entry(),
            dict(backend="portal", target="public-fixture-target", title="Fixture Target"), sequence, delay=0, start_delay=100)
        return before, self.vault.autotype_finish(before["token"], pick, approved=True)

    def test_autotype_settings_inheritance_matching_and_preservation(self):
        self.vault.save_autotype_settings(group=self.group, enabled=1, sequence="{USERNAME}{TAB}{PASSWORD}")
        associations = [dict(window="*Authentication*", sequence="{PASSWORD}{ENTER}"),
                        dict(window="//^Example [0-9]+$//", sequence="{USERNAME}"),
                        dict(window="", sequence="{PASSWORD}")]
        self.vault.save_autotype_settings(entry=self.entry(), enabled=True, sequence="", associations=associations)
        self.vault.lock()
        self.vault.unlock(self.path, "public fixture master")
        entry = self.entry()
        data = self.vault.autotype_settings(entry)
        self.assertEqual(data["associations"], associations)
        self.assertEqual(data["effective_sequence"], "{USERNAME}{TAB}{PASSWORD}")
        matches = self.vault.autotype_matches("Fixture Authentication", match_title=False, match_url=False)
        self.assertEqual([m["sequence"] for m in matches], ["{PASSWORD}{ENTER}", "{PASSWORD}"])
        self.assertEqual(self.vault.autotype_matches("Example 42", False, False)[0]["sequence"], "{USERNAME}")
        self.assertTrue(self.vault.autotype_matches("example.org account", False, True))
        self.assertFalse(self.vault.autotype_matches("No match", False, False))
        self.assertEqual(self.vault.attribute(entry), "aBc123")
        self.vault.save_autotype_settings(group=self.group, enabled=2, sequence="")
        self.assertFalse(self.vault.autotype_matches("Example"))
        with self.assertRaises(EngineError):
            self.plan("{PASSWORD}")

    def test_autotype_native_parser_pickchars_delays_modifiers_and_unicode(self):
        self.vault.set_attribute(self.entry(), "Custom", "SeCrEt", True)
        before, result = self.plan("{{}{}}^a{DELAY=0}{USERNAME}{TAB}{PICKCHARS}{ENTER}{PICKCHARS:Custom}",
            [dict(positions=[2, 4, 6], tab=True), dict(positions=[6, 1], tab=False)])
        self.assertEqual(before["pick"], [dict(attribute="Password", length=6), dict(attribute="Custom", length=6)])
        self.assertNotIn("aBc123", repr(before))
        keys = [(a["keysym"], a["modifiers"]) for a in result["plan"] if a["type"] == "key"]
        self.assertEqual(keys[:3], [(ord("{"), 0), (ord("}"), 0), (ord("a"), 0x04000000)])
        self.assertEqual([k for k, _ in keys[-9:]], [0xFF09, ord("B"), 0xFF09, ord("1"), 0xFF09, ord("3"), 0xFF0D, ord("t"), ord("S")])
        self.vault.save_entry(self.group, "Example", "", "", "", "😀", self.entry())
        _, unicode_plan = self.plan("{PASSWORD}")
        self.assertEqual([a["keysym"] for a in unicode_plan["plan"] if a["type"] == "key"], [0x0101F600])

    def test_autotype_approval_is_single_use_and_bound_to_unchanged_file(self):
        token, _ = self.plan("{PASSWORD}")
        with self.assertRaises(EngineError):
            self.vault.autotype_finish(token["token"], approved=True)
        prepared = self.vault.autotype_prepare(self.entry(), dict(backend="portal", target="fixture", title="Fixture"))
        self.vault.set_attribute(self.entry(), "Change", "new", False)
        with self.assertRaises(EngineError):
            self.vault.autotype_finish(prepared["token"], approved=True)
        prepared = self.vault.autotype_prepare(self.entry(), dict(backend="portal", target="fixture", title="Fixture"))
        self.assertEqual(self.vault.autotype_finish(prepared["token"], approved=False), {"typed": False})
        with self.assertRaises(EngineError):
            self.vault.autotype_finish(prepared["token"], approved=True)

    def test_autotype_invalid_sequences_and_positions_do_not_write_the_vault(self):
        before = self.path.read_bytes()
        for sequence in ("{PASSWORD", "{TAB 101}", "{DELAY 10001}", "{UNKNOWN}"):
            with self.subTest(sequence=sequence), self.assertRaises(EngineError):
                self.plan(sequence)
        with self.assertRaises(EngineError):
            self.plan("{PICKCHARS}", [dict(positions=[0], tab=False)])
        with self.assertRaises(EngineError):
            self.plan("{DELAY 10000}" * 7)
        with self.assertRaises(EngineError):
            self.vault.save_autotype_settings(entry=self.entry(), enabled=True, sequence="", associations=[dict(window="//[//", sequence="")])
        self.assertEqual(before, self.path.read_bytes())

    def configure(self, incoming=True, outgoing=True):
        self.vault.keeshare_configure(self.directory / "config", {"import": incoming, "export": outgoing})

    def reference(self, path, mode=2, **options):
        self.vault.save_keeshare_settings(self.group, mode=mode, path=str(path), keep_groups=options.pop("keep_groups", True),
                                         password="public share password", **options)

    def test_keeshare_encrypted_export_upstream_open_subgroups_and_noop_poll(self):
        self.vault.add_group(self.group, "Child")
        child = next(g for g in self.vault.snapshot.groups if g.name == "Child")
        self.vault.save_entry(child.uuid, "Nested", "nested", "", "", "nested fixture password")
        self.configure()
        output = self.directory / "share.kdbx"
        self.reference(output)
        result = self.vault.keeshare_sync()
        self.assertEqual((result["imports"], result["exports"], result["warnings"]), (0, 1, []))
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        shared = self.other(output)
        self.assertEqual({e.title for e in shared.snapshot.entries}, {"Example", "Nested"})
        self.assertEqual(shared.attribute(next(e for e in shared.snapshot.entries if e.title == "Example")), "aBc123")
        saved = output.read_bytes()
        self.assertEqual(self.vault.keeshare_sync()["exports"], 0)
        self.assertEqual(output.read_bytes(), saved)
        self.reference(output, keep_groups=False)
        self.vault.keeshare_sync()
        shared.refresh()
        self.assertEqual([e.title for e in shared.snapshot.entries], ["Example"])

    def test_keeshare_bidirectional_import_preserves_history_and_poll_does_not_loop(self):
        self.configure()
        output = self.directory / "shared.kdbx"
        self.reference(output, mode=3)
        self.assertFalse(self.vault.keeshare_sync()["warnings"])
        shared = self.other(output)
        entry = shared.snapshot.entries[0]
        # The upstream merger deliberately compares whole-second KDBX timestamps.
        time.sleep(1.05)
        shared.save_entry(entry.group, "Example", "changed-user", "", "", "changed fixture password", entry)
        result = self.vault.keeshare_sync()
        self.assertEqual((result["imports"], result["exports"], result["warnings"]), (1, 1, []))
        self.assertEqual(self.vault.attribute(self.entry()), "changed fixture password")
        self.assertTrue(self.vault.history(self.entry()))
        saved = output.read_bytes(), self.path.read_bytes()
        self.assertEqual(self.vault.keeshare_sync(), {"imports": 0, "exports": 0, "warnings": []})
        self.assertEqual((output.read_bytes(), self.path.read_bytes()), saved)

    def test_keeshare_wrong_password_rolls_back_and_never_overwrites_source(self):
        source = self.other()
        source.save_entry(source.snapshot.root, "Source", "", "", "", "public source secret")
        self.configure()
        self.reference(source.path, mode=3)
        self.vault.save_keeshare_settings(self.group, mode=3, path=str(source.path), keep_groups=True, password="wrong password")
        before = self.path.read_bytes(), source.path.read_bytes()
        result = self.vault.keeshare_sync()
        self.assertTrue(result["warnings"])
        self.assertEqual(result["exports"], 0)
        self.assertEqual((self.path.read_bytes(), source.path.read_bytes()), before)
        self.assertEqual(self.vault.attribute(self.entry()), "aBc123")

    def test_keeshare_master_alias_duplicate_targets_and_global_permissions(self):
        self.configure(incoming=False, outgoing=False)
        output = self.directory / "share.kdbx"
        self.reference(output)
        self.assertEqual(self.vault.keeshare_sync(), {"imports": 0, "exports": 0, "warnings": []})
        self.assertFalse(output.exists())
        alias = self.directory / "alias.kdbx"
        os.link(self.path, alias)
        before = self.path.read_bytes()
        with self.assertRaises(EngineError):
            self.reference(alias)
        self.assertEqual(self.path.read_bytes(), before)
        self.vault.add_group(self.vault.snapshot.root, "Other")
        other = next(g.uuid for g in self.vault.snapshot.groups if g.name == "Other")
        with self.assertRaises(EngineError):
            self.vault.save_keeshare_settings(other, mode=2, path=str(output), keep_groups=True, password="fixture")
        self.reference(output, mode=3)
        self.configure(incoming=False, outgoing=True)
        self.assertTrue(self.vault.keeshare_sync()["warnings"])
        self.assertFalse(output.exists())

    def test_keeshare_legacy_container_and_identity_survive_helper_restart(self):
        self.configure()
        output = self.directory / "żółć.kdbx.share"
        self.reference(output)
        self.assertFalse(self.vault.keeshare_sync()["warnings"])
        identity = self.directory / "config/keyslot/keeshare-identity.xml"
        private = identity.read_bytes()
        self.assertEqual(identity.stat().st_mode & 0o777, 0o600)
        with zipfile.ZipFile(output) as archive:
            names = archive.namelist()
            self.assertTrue(any("sign" in name.lower() for name in names))
            encrypted = next(archive.read(name) for name in names if name.endswith(".kdbx"))
        extracted = self.directory / "extracted.kdbx"
        extracted.write_bytes(encrypted)
        opened = self.other(extracted)
        self.assertEqual(opened.snapshot.entries[0].title, "Example")
        self.assertEqual(opened.attribute(opened.snapshot.entries[0]), "aBc123")
        self.vault.lock()
        self.vault.unlock(self.path, "public fixture master")
        self.configure()
        self.assertFalse(self.vault.keeshare_sync(force=True)["warnings"])
        self.assertEqual(identity.read_bytes(), private)
        self.assertTrue(self.vault.keeshare_settings(self.group)["has_password"])
        self.assertNotIn("public share password", repr(self.vault.keeshare_settings(self.group)))

    def test_keeshare_missing_import_and_external_vault_change_leave_files_intact(self):
        self.configure()
        output = self.directory / "missing.kdbx"
        self.reference(output, mode=1)
        self.assertTrue(self.vault.keeshare_sync()["warnings"])
        self.assertFalse(output.exists())
        self.reference(output, mode=2)
        external = self.other(self.path, "public fixture master")
        external.save_entry(external.snapshot.root, "Concurrent", "", "", "", "fixture")
        before = hashlib.sha256(self.path.read_bytes()).digest()
        with self.assertRaises(EngineError):
            self.vault.keeshare_sync()
        self.assertFalse(output.exists())
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)
