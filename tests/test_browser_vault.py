"""Browser associations use KeePassXC's encrypted metadata, not a separate registry."""
import base64
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET

from keyslot.core_backend import Vault, EngineError
from keyslot.backend import VaultError


ENGINE = shutil.which(os.environ.get("KEYSLOT_ENGINE", "keyslot-engine"))
if os.environ.get("KEYSLOT_REQUIRE_ENGINE") == "1" and not ENGINE:
    raise RuntimeError("Browser vault integration requires the native engine.")


@unittest.skipUnless(ENGINE, "native KeePassXC core helper is not built")
class BrowserVaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "browser.kdbx"
        self.vault = Vault(ENGINE)
        self.addCleanup(self.vault.lock)
        self.vault.create(self.path, "public test master")
        self.key = base64.b64encode(bytes(range(32))).decode()
        self.other_key = base64.b64encode(bytes(reversed(range(32)))).decode()

    def xml(self):
        cli = Path(ENGINE).parent.parent / "bin/keepassxc-cli"
        result = subprocess.run([str(cli), "export", "--format", "xml", str(self.vault.path)],
                                input="public test master\n", text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return ET.fromstring(result.stdout)

    def login(self, title="Example", url="https://example.org"):
        self.vault.save_entry(self.vault.snapshot.root, title, "alice", url, "", "public browser password")
        return next(e for e in self.vault.snapshot.entries if e.title == title)

    def lookup(self, **options):
        return self.vault.browser_lookup("browser", self.key, "https://example.org/login", **options)

    def prepare_save(self, **options):
        return self.vault.browser_prepare_save("browser", self.key, "https://example.org/login", "alice",
                                              "new public browser password", **options)

    def test_browser_cannot_inject_references_or_placeholders(self):
        self.vault.browser_associate("browser", self.key)
        existing = self.login("Private credential")
        before = self.path.read_bytes()
        expressions = ["{REF:P@T:Private credential}", "{ref:p@t:Private credential}",
                       "{USERNAME}", "{PASSWORD}", "{S:Private}", "{DB_DIR}",
                       "{T-CONV:/{PASSWORD}/BASE64/}", r"\{PASSWORD\}",
                       "{" * 64 + "{REF:P@T:Private credential}" + "}" * 64]
        for expression in expressions:
            for field in ("username", "password"):
                for entry in ("", existing.uuid.replace("-", "")):
                    with self.subTest(expression=expression, field=field, update=bool(entry)):
                        values = {"username": "alice", "password": "public replacement"}
                        values[field] = expression
                        with self.assertRaises(EngineError) as caught:
                            self.vault.browser_prepare_save("browser", self.key, "https://example.org/login",
                                                            values["username"], values["password"], entry=entry)
                        self.assertEqual(caught.exception.code, "references_not_allowed")
                        self.assertNotIn(expression, str(caught.exception))
                        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.vault.attribute(existing), "public browser password")

    def test_browser_accepts_literal_braces_without_interpreting_them(self):
        self.vault.browser_associate("browser", self.key)
        password = "literal {unknown} {a:b} braces"
        prepared = self.vault.browser_prepare_save("browser", self.key, "https://example.org", "literal {unknown}", password)
        self.assertTrue(self.vault.browser_save(prepared["token"], approved=True))
        entry = self.vault.snapshot.entries[0]
        self.assertEqual(entry.username, "literal {unknown}")
        self.assertEqual(self.vault.attribute(entry), password)

    def test_browser_deletion_requires_single_use_consent_and_preserves_recycled_history(self):
        self.vault.browser_associate("browser", self.key)
        entry = self.login()
        self.vault.save_entry(entry.group, entry.title, entry.username, entry.url, "Preserved notes", "changed password", entry)
        entry = self.vault.snapshot.entries[0]
        uuid = entry.uuid.replace("-", "")
        before = self.path.read_bytes()
        review = self.vault.browser_prepare_delete("browser", self.key, uuid)
        self.assertTrue(review["found"])
        self.assertFalse(review["permanent"])
        self.assertNotIn("changed password", str(review))
        self.assertFalse(self.vault.browser_delete(review["token"]))
        self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaises(EngineError):
            self.vault.browser_delete(review["token"], approved=True)
        review = self.vault.browser_prepare_delete("browser", self.key, uuid)
        self.assertTrue(self.vault.browser_delete(review["token"], approved=True))
        recycled = self.vault.snapshot.entries[0]
        self.assertTrue(recycled.recycled)
        self.assertEqual(recycled.uuid, entry.uuid)
        self.assertEqual(recycled.notes, "Preserved notes")
        self.assertEqual(recycled.history_count, entry.history_count)
        self.assertEqual(self.vault.attribute(recycled), "changed password")
        before = self.path.read_bytes()
        review = self.vault.browser_prepare_delete("browser", self.key, uuid)
        self.assertTrue(self.vault.browser_delete(review["token"], approved=True))
        self.assertEqual(self.path.read_bytes(), before)

    def test_browser_permanent_deletion_is_explicit_and_cannot_reuse_a_recycle_approval(self):
        self.vault.browser_associate("browser", self.key)
        entry = self.login()
        uuid = entry.uuid.replace("-", "")
        recycle = self.vault.browser_prepare_delete("browser", self.key, uuid)
        self.vault.save_settings(recycle_bin=False)
        before = self.path.read_bytes()
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_delete(recycle["token"], approved=True)
        self.assertEqual(caught.exception.code, "conflict")
        review = self.vault.browser_prepare_delete("browser", self.key, uuid)
        self.assertTrue(review["permanent"])
        self.assertFalse(self.vault.browser_delete(review["token"]))
        self.assertEqual(self.path.read_bytes(), before)
        review = self.vault.browser_prepare_delete("browser", self.key, uuid)
        self.assertTrue(self.vault.browser_delete(review["token"], approved=True))
        self.assertEqual(self.vault.snapshot.entries, [])
        self.assertEqual(self.vault.browser_prepare_delete("browser", self.key, uuid), {"found": False})
        self.assertIsNone(self.xml().find('.//Entry'))

    def test_browser_deletion_validates_identity_authentication_and_external_writes(self):
        self.vault.browser_associate("browser", self.key)
        entry = self.login()
        uuid = entry.uuid.replace("-", "")
        before = self.path.read_bytes()
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_prepare_delete("browser", self.key, "invalid")
        self.assertEqual(caught.exception.code, "invalid_uuid")
        with self.assertRaises(EngineError):
            self.vault.browser_prepare_delete("browser", self.other_key, uuid)
        self.assertEqual(self.path.read_bytes(), before)
        review = self.vault.browser_prepare_delete("browser", self.key, uuid)
        self.vault.refresh()
        with self.assertRaises(EngineError):
            self.vault.browser_delete(review["token"], approved=True)
        review = self.vault.browser_prepare_delete("browser", self.key, uuid)
        other = Vault(ENGINE)
        self.addCleanup(other.lock)
        other.unlock(self.path, "public test master")
        other.browser_revoke("browser")
        external = self.path.read_bytes()
        with self.assertRaises(EngineError):
            self.vault.browser_delete(review["token"], approved=True)
        self.assertEqual(self.path.read_bytes(), external)

    def test_browser_totp_uses_upstream_codes_and_visibility_restrictions(self):
        self.vault.browser_associate("browser", self.key)
        visible = self.login("Visible OTP")
        empty = self.login("No OTP")
        hidden = self.login("Hidden OTP")
        recycled = self.login("Recycled OTP")
        self.vault.add_group(self.vault.snapshot.root, "Restricted")
        restricted_group = next(g for g in self.vault.snapshot.groups if g.name == "Restricted")
        self.vault.save_entry(restricted_group.uuid, "Restricted OTP", "alice", "https://example.org", "", "public")
        restricted = next(e for e in self.vault.snapshot.entries if e.title == "Restricted OTP")
        uri = "otpauth://totp/Fixture?secret=JBSWY3DPEHPK3PXP&issuer=Fixture"
        for entry in (visible, hidden, recycled, restricted):
            self.vault.set_totp(entry, uri)
        recycled = next(e for e in self.vault.snapshot.entries if e.uuid == recycled.uuid)
        self.vault.delete_entry(recycled)
        xml = self.xml()
        for node in xml.findall('.//Entry'):
            if node.findtext('String[Key="Title"]/Value') == hidden.title:
                data = node.find("CustomData")
                if data is None:
                    data = ET.SubElement(node, "CustomData")
                item = ET.SubElement(data, "Item")
                ET.SubElement(item, "Key").text = "BrowserHideEntry"
                ET.SubElement(item, "Value").text = "true"
        node = next(g for g in xml.findall('.//Group') if g.findtext('Name') == "Restricted")
        data = node.find("CustomData")
        if data is None:
            data = ET.SubElement(node, "CustomData")
        item = ET.SubElement(data, "Item")
        ET.SubElement(item, "Key").text = "BrowserRestrictKey"
        ET.SubElement(item, "Value").text = "another browser"
        source = self.root / "otp-policies.xml"
        ET.ElementTree(xml).write(source, encoding="utf-8", xml_declaration=True)
        self.vault.import_database(self.root / "otp-policies.kdbx", source, "xml", "public test master")
        visible = next(e for e in self.vault.snapshot.entries if e.title == visible.title)
        before = self.vault.path.read_bytes()
        first = self.vault.attribute(visible, totp=True)
        code = self.vault.browser_totp("browser", self.key, visible.uuid.replace("-", ""))
        last = self.vault.attribute(visible, totp=True)
        self.assertIn(code, {first, last})
        self.assertRegex(code, r"^\d{6}$")
        for entry in (empty, hidden, recycled, restricted):
            self.assertEqual(self.vault.browser_totp("browser", self.key, entry.uuid.replace("-", "")), "")
        self.assertEqual(self.vault.browser_totp("browser", self.key, "1" * 32), "")
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_totp("browser", self.key, "invalid")
        self.assertEqual(caught.exception.code, "invalid_uuid")
        with self.assertRaises(EngineError):
            self.vault.browser_totp("browser", self.other_key, visible.uuid.replace("-", ""))
        self.assertEqual(self.vault.path.read_bytes(), before)

    def test_browser_groups_and_nested_creation_preserve_existing_groups(self):
        self.vault.browser_associate("browser", self.key)
        entry = self.login()
        self.vault.delete_entry(entry)
        self.vault.add_group(self.vault.snapshot.root, "Web")
        web_group = next(g for g in self.vault.snapshot.groups if g.name == "Web")
        self.vault.save_group(web_group.uuid, "Web", "Preserved group notes")
        before = self.path.read_bytes()
        result = self.vault.browser_groups("browser", self.key)
        self.assertEqual(result["groups"][0]["uuid"], self.vault.snapshot.root.replace("-", ""))
        self.assertFalse(any(g["uuid"] in {r.uuid.replace("-", "") for r in self.vault.snapshot.groups if r.recycled}
                             for g in result["groups"][0]["children"]))
        review = self.vault.browser_prepare_group("browser", self.key, "Web/Accounts")
        self.assertFalse(review["exists"])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.vault.browser_create_group(review["token"]), {})
        self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaises(EngineError):
            self.vault.browser_create_group(review["token"], approved=True)
        review = self.vault.browser_prepare_group("browser", self.key, "Web/Accounts")
        created = self.vault.browser_create_group(review["token"], approved=True)
        self.assertEqual(created["name"], "Accounts")
        self.assertEqual(len(created["uuid"]), 32)
        web = next(g for g in self.vault.browser_groups("browser", self.key)["groups"][0]["children"] if g["name"] == "Web")
        self.assertEqual(web["uuid"], web_group.uuid.replace("-", ""))
        xml_group = next(g for g in self.xml().findall('.//Group') if g.findtext('Name') == "Web")
        self.assertEqual(xml_group.findtext('Notes'), "Preserved group notes")
        self.assertEqual(web["children"], [{"name": "Accounts", "uuid": created["uuid"], "children": []}])
        before = self.path.read_bytes()
        existing = self.vault.browser_prepare_group("browser", self.key, "/Web/Accounts/")
        self.assertTrue(existing["exists"])
        self.assertEqual(existing["uuid"], created["uuid"])
        self.assertEqual(self.path.read_bytes(), before)

    def test_browser_group_confirmation_cannot_cross_changes_or_target_recycle_bin(self):
        self.vault.browser_associate("browser", self.key)
        before = self.path.read_bytes()
        for name in ("", "/", "Web//Empty", "a/" * 129):
            with self.subTest(name=name), self.assertRaises(EngineError):
                self.vault.browser_prepare_group("browser", self.key, name)
        self.assertEqual(self.path.read_bytes(), before)
        review = self.vault.browser_prepare_group("browser", self.key, "Web/New")
        entry = self.login()
        self.vault.delete_entry(entry)
        before = self.path.read_bytes()
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_create_group(review["token"], approved=True)
        self.assertEqual(caught.exception.code, "conflict")
        self.assertEqual(self.path.read_bytes(), before)
        recycled = next(g for g in self.vault.snapshot.groups if g.recycled)
        with self.assertRaises(EngineError):
            self.vault.browser_prepare_group("browser", self.key, recycled.name + "/Nested")
        with self.assertRaises(EngineError):
            self.vault.browser_groups("browser", self.other_key)
        review = self.vault.browser_prepare_group("browser", self.key, "Web/New")
        self.vault.refresh()
        with self.assertRaises(EngineError):
            self.vault.browser_create_group(review["token"], approved=True)
        self.assertEqual(self.path.read_bytes(), before)

    def test_browser_save_is_metadata_only_and_requires_single_use_confirmation(self):
        self.vault.browser_associate("browser", self.key)
        before = self.path.read_bytes()
        request = self.prepare_save()
        self.assertNotIn("new public browser password", str(request))
        self.assertFalse(request["update"])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(self.vault.browser_save(request["token"]))
        self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaises(EngineError):
            self.vault.browser_save(request["token"], approved=True)
        request = self.prepare_save()
        self.assertTrue(self.vault.browser_save(request["token"], approved=True))
        entry = self.vault.snapshot.entries[0]
        self.assertEqual(entry.title, "example.org")
        self.assertIn("KeePassXC-Browser Passwords", entry.group_path)
        self.assertEqual(self.vault.attribute(entry), "new public browser password")
        self.assertEqual(entry.history_count, 0)
        self.assertEqual(self.xml().findtext('.//Entry/String[Key="Password"]/Value'), "new public browser password")
        with self.assertRaises(EngineError):
            self.vault.browser_save(request["token"], approved=True)

    def test_browser_save_group_selection_stale_confirmation_and_authentication(self):
        self.vault.browser_associate("browser", self.key)
        with self.assertRaises(EngineError):
            self.vault.browser_prepare_save("browser", self.other_key, "https://example.org", "alice", "test")
        before = self.path.read_bytes()
        request = self.prepare_save()
        with self.assertRaises(EngineError):
            self.vault.browser_save(request["token"], approved=True, group="0" * 32)
        self.assertEqual(self.path.read_bytes(), before)
        request = self.prepare_save()
        self.login("Unrelated edit")
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_save(request["token"], approved=True)
        self.assertEqual(caught.exception.code, "conflict")
        request = self.prepare_save()
        root = next(g["uuid"] for g in request["groups"] if g["uuid"] == self.vault.snapshot.root.replace("-", ""))
        self.assertTrue(self.vault.browser_save(request["token"], approved=True, group=root))
        saved = next(e for e in self.vault.snapshot.entries if e.title == "example.org")
        self.assertEqual(saved.group, self.vault.snapshot.root)
        missing = self.prepare_save(entry="1" * 32)
        self.assertFalse(missing["update"])
        self.assertTrue(self.vault.browser_save(missing["token"], approved=True, group=root))
        request = self.prepare_save()
        self.vault.refresh()
        with self.assertRaises(EngineError):
            self.vault.browser_save(request["token"], approved=True)

    def test_browser_update_preserves_other_fields_and_history(self):
        self.vault.browser_associate("browser", self.key)
        entry = self.login("Existing title", "https://example.net/keep-url")
        self.vault.set_attribute(entry, "custom preserved", "public custom", protected=True)
        entry = self.vault.snapshot.entries[0]
        history = entry.history_count
        request = self.prepare_save(entry=entry.uuid.replace("-", ""))
        self.assertTrue(request["update"])
        self.assertEqual(request["title"], "Existing title")
        self.assertEqual(request["entry_url"], "https://example.net/keep-url")
        self.assertTrue(self.vault.browser_save(request["token"], approved=True))
        updated = self.vault.snapshot.entries[0]
        self.assertEqual(updated.title, entry.title)
        self.assertEqual(updated.url, entry.url)
        self.assertEqual(updated.group, entry.group)
        self.assertEqual(updated.history_count, history + 1)
        self.assertEqual(self.vault.attribute(updated, "custom preserved"), "public custom")
        self.assertEqual(self.vault.attribute(updated), "new public browser password")
        before = self.path.read_bytes()
        unchanged = self.prepare_save(entry=entry.uuid.replace("-", ""))
        self.assertFalse(unchanged["changed"])
        self.assertFalse(self.vault.browser_save(unchanged["token"], approved=True))
        self.assertEqual(self.path.read_bytes(), before)

    def test_browser_update_follows_password_reference_but_rejects_cycles(self):
        self.vault.browser_associate("browser", self.key)
        target = self.login("Original")
        source = self.login("Reference")
        self.vault.save_entry(source.group, source.title, source.username, source.url, source.notes,
                              "{REF:P@I:" + target.uuid.replace("-", "") + "}", source)
        before = self.path.read_bytes()
        request = self.prepare_save(entry=source.uuid.replace("-", ""))
        self.assertTrue(request["reference"])
        self.assertEqual(request["title"], "Original")
        self.assertEqual(self.path.read_bytes(), before)
        self.vault.browser_save(request["token"], approved=True)
        target = next(e for e in self.vault.snapshot.entries if e.title == "Original")
        source = next(e for e in self.vault.snapshot.entries if e.title == "Reference")
        self.assertEqual(self.vault.attribute(target), "new public browser password")
        self.assertEqual(self.vault.attribute(source), "new public browser password")
        username_reference = "{REF:U@I:" + source.uuid.replace("-", "") + "}"
        self.vault.save_entry(target.group, target.title, username_reference, target.url, target.notes,
                              "old public password", target)
        request = self.prepare_save(entry=source.uuid.replace("-", ""))
        self.vault.browser_save(request["token"], approved=True)
        target = next(e for e in self.vault.snapshot.entries if e.title == "Original")
        self.assertEqual(self.vault.editable_fields(target)["UserName"], username_reference)
        self.vault.save_entry(target.group, target.title, target.username, target.url, target.notes,
                              "{REF:P@I:" + source.uuid.replace("-", "") + "}", target)
        before = self.path.read_bytes()
        with self.assertRaises(EngineError):
            self.prepare_save(entry=source.uuid.replace("-", ""))
        self.assertEqual(self.path.read_bytes(), before)

    def test_browser_save_rejects_invalid_fields_and_preserves_external_writes(self):
        self.vault.browser_associate("browser", self.key)
        before = self.path.read_bytes()
        for options in ({"entry": "invalid"}, {"entry": 7}, {"login": None}, {"password": "has\0null"}):
            with self.subTest(options=options), self.assertRaises(EngineError):
                self.vault._rpc("browser.prepare_save", id="browser", key=self.key, url="https://example.org",
                                **{"login": "alice", "password": "public", **options})
        self.assertEqual(self.path.read_bytes(), before)
        request = self.prepare_save()
        other = Vault(ENGINE)
        self.addCleanup(other.lock)
        other.unlock(self.path, "public test master")
        other.browser_revoke("browser")
        external = self.path.read_bytes()
        with self.assertRaises(EngineError):
            self.vault.browser_save(request["token"], approved=True)
        self.assertEqual(self.path.read_bytes(), external)

    def test_lookup_is_metadata_only_and_credentials_require_single_use_consent(self):
        self.vault.browser_associate("browser", self.key)
        self.login()
        self.login("Other site", "https://other.example.net")
        with self.assertRaises(EngineError):
            self.vault.browser_lookup("browser", self.other_key, "https://example.org")
        request = self.lookup()
        self.assertEqual([e["title"] for e in request["entries"]], ["Example"])
        self.assertNotIn("public browser password", str(request))
        self.assertFalse(request["entries"][0]["allowed"])
        selected = [request["entries"][0]["uuid"]]
        with self.assertRaises(EngineError):
            self.vault.browser_release(request["token"], selected)
        request = self.lookup()
        result = self.vault.browser_release(request["token"], selected, approved=True)
        self.assertEqual(result[0]["password"], "public browser password")
        self.assertEqual(result[0]["login"], "alice")
        with self.assertRaises(EngineError):
            self.vault.browser_release(request["token"], selected, approved=True)

    def test_remembered_site_permissions_survive_reopen_but_http_auth_still_prompts(self):
        self.vault.browser_associate("browser", self.key)
        self.login()
        request = self.lookup()
        selected = [e["uuid"] for e in request["entries"]]
        self.vault.browser_release(request["token"], selected, approved=True, remember=True)
        self.vault.lock()
        self.vault.unlock(self.path, "public test master")
        request = self.lookup()
        self.assertTrue(request["entries"][0]["allowed"])
        self.assertEqual(self.vault.browser_release(request["token"], selected)[0]["login"], "alice")
        request = self.lookup(http_auth=True)
        self.assertFalse(request["entries"][0]["allowed"])
        with self.assertRaises(EngineError):
            self.vault.browser_release(request["token"], selected)

    def test_remembered_denial_never_returns_credentials_and_survives_reopen(self):
        self.vault.browser_associate("browser", self.key)
        self.login()
        request = self.lookup()
        selected = [e["uuid"] for e in request["entries"]]
        before = self.path.read_bytes()
        self.assertEqual(self.vault.browser_deny(request["token"], selected), [])
        self.assertEqual(self.path.read_bytes(), before)
        request = self.lookup()
        self.assertEqual(self.vault.browser_deny(request["token"], selected, remember=True), [])
        self.vault.lock()
        self.vault.unlock(self.path, "public test master")
        self.assertEqual(self.lookup()["entries"], [])
        self.assertEqual(self.vault.attribute(self.vault.snapshot.entries[0]), "public browser password")

    def test_browser_confirmation_cannot_cross_edits_refresh_or_requested_entries(self):
        self.vault.browser_associate("browser", self.key)
        entry = self.login()
        request = self.lookup()
        with self.assertRaises(EngineError):
            self.vault.browser_release(request["token"], ["0" * 32], approved=True)
        request = self.lookup()
        selected = [e["uuid"] for e in request["entries"]]
        self.vault.save_entry(entry.group, entry.title, "alice", "https://example.org", "", "changed test password", entry)
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_release(request["token"], selected, approved=True)
        self.assertEqual(caught.exception.code, "conflict")
        request = self.lookup()
        self.vault.refresh()
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_release(request["token"], selected, approved=True)
        self.assertEqual(caught.exception.code, "conflict")

    def test_upstream_url_matching_and_request_options_are_isolated(self):
        self.vault.browser_associate("browser", self.key)
        entry = self.login()
        self.vault.set_attribute(entry, "KPH: public-custom", "public custom value")
        self.login("HTTP", "http://example.org")
        self.login("Wrong domain", "https://notexample.org")
        self.login("Other domain", "https://example.net")
        request = self.lookup(custom_fields=False)
        self.assertEqual([e["title"] for e in request["entries"]], ["Example"])
        # A second client's options cannot turn on protected custom fields for the first request.
        self.lookup(custom_fields=True, match_scheme=False)
        result = self.vault.browser_release(request["token"], [request["entries"][0]["uuid"]], approved=True)
        self.assertNotIn("stringFields", result[0])
        request = self.lookup(custom_fields=True, match_scheme=False)
        self.assertEqual({e["title"] for e in request["entries"]}, {"Example", "HTTP"})
        result = self.vault.browser_release(request["token"], [e["uuid"] for e in request["entries"]], approved=True)
        example = next(e for e in result if e["name"] == "Example")
        self.assertEqual(example["stringFields"], [{"KPH: public-custom": "public custom value"}])
        child = self.vault.browser_lookup("browser", self.key, "https://sub.example.org/login")
        self.assertEqual([e["title"] for e in child["entries"]], ["Example"])

    def test_confirmation_expires_without_releasing_credentials(self):
        self.vault.browser_associate("browser", self.key)
        self.login()
        request = self.lookup()
        save = self.prepare_save()
        group = self.vault.browser_prepare_group("browser", self.key, "Expired/New")
        deletion = self.vault.browser_prepare_delete("browser", self.key, request["entries"][0]["uuid"])
        time.sleep(30.1)
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_release(request["token"], [e["uuid"] for e in request["entries"]], approved=True)
        self.assertEqual(caught.exception.code, "conflict")
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_create_group(group["token"], approved=True)
        self.assertEqual(caught.exception.code, "conflict")
        self.assertNotIn("public browser password", str(caught.exception))
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_delete(deletion["token"], approved=True)
        self.assertEqual(caught.exception.code, "conflict")
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_save(save["token"], approved=True)
        self.assertEqual(caught.exception.code, "conflict")

    def test_pending_confirmations_are_bounded_and_consumption_frees_capacity(self):
        self.vault.browser_associate("browser", self.key)
        self.login()
        requests = [self.lookup() for _ in range(128)]
        with self.assertRaises(EngineError) as caught:
            self.lookup()
        self.assertEqual(caught.exception.code, "busy")
        self.vault.browser_deny(requests[0]["token"], [e["uuid"] for e in requests[0]["entries"]])
        self.assertTrue(self.lookup()["token"])
        saves = [self.prepare_save() for _ in range(128)]
        with self.assertRaises(EngineError) as caught:
            self.prepare_save()
        self.assertEqual(caught.exception.code, "busy")
        self.assertFalse(self.vault.browser_save(saves[0]["token"]))
        self.assertTrue(self.prepare_save()["token"])
        groups = [self.vault.browser_prepare_group("browser", self.key, "Pending" + str(i)) for i in range(128)]
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_prepare_group("browser", self.key, "Too many")
        self.assertEqual(caught.exception.code, "busy")
        self.assertEqual(self.vault.browser_create_group(groups[0]["token"]), {})
        self.assertTrue(self.vault.browser_prepare_group("browser", self.key, "One more")["token"])
        uuid = self.vault.snapshot.entries[0].uuid.replace("-", "")
        deletions = [self.vault.browser_prepare_delete("browser", self.key, uuid) for _ in range(128)]
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_prepare_delete("browser", self.key, uuid)
        self.assertEqual(caught.exception.code, "busy")
        self.assertFalse(self.vault.browser_delete(deletions[0]["token"]))
        self.assertTrue(self.vault.browser_prepare_delete("browser", self.key, uuid)["token"])

    def test_expired_top_match_does_not_hide_lower_permitted_entries(self):
        self.vault.browser_associate("browser", self.key)
        self.login()
        self.vault.save_entry(self.vault.snapshot.root, "Expired exact match", "expired", "https://example.org/login", "",
                              "expired test password", expires=True, expiry="2000-01-01T00:00:00Z")
        request = self.lookup(best_match=True)
        self.assertEqual([e["title"] for e in request["entries"]], ["Example"])
        result = self.vault.browser_release(request["token"], [e["uuid"] for e in request["entries"]], approved=True)
        self.assertEqual([e["name"] for e in result], ["Example"])

    def test_association_persists_in_upstream_metadata_and_hash_matches_root_uuid(self):
        info = self.vault.browser_info()
        self.vault.browser_associate("Firefox · laptop", self.key)
        xml = self.xml()
        root_uuid = base64.b64decode(xml.findtext("Root/Group/UUID")).hex()
        self.assertEqual(info["hash"], hashlib.sha256(root_uuid.encode()).hexdigest())
        metadata = {i.findtext("Key"): i.findtext("Value") for i in xml.findall("Meta/CustomData/Item")}
        self.assertEqual(metadata["KPXC_BROWSER_Firefox · laptop"], self.key)
        self.assertTrue(metadata["_CREATED_Firefox · laptop"])
        self.assertNotIn(self.key, str(self.vault.browser_associations()))
        self.assertNotIn(self.key, str(self.vault.browser_info()))
        self.vault.lock()
        self.vault.unlock(self.path, "public test master")
        self.assertTrue(self.vault.browser_authenticate("Firefox · laptop", self.key)["authenticated"])
        self.assertFalse(self.vault.browser_authenticate("Firefox · laptop", self.other_key)["authenticated"])

    def test_duplicate_pairing_requires_explicit_replace_and_revocation_survives_reopen(self):
        self.vault.browser_associate("browser", self.key)
        before = self.path.read_bytes()
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_associate("browser", self.other_key)
        self.assertEqual(caught.exception.code, "already_exists")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(self.vault.browser_authenticate("browser", self.key)["authenticated"])
        self.vault.browser_associate("browser", self.other_key, replace=True)
        self.assertFalse(self.vault.browser_authenticate("browser", self.key)["authenticated"])
        self.vault.browser_revoke("browser")
        self.vault.lock()
        self.vault.unlock(self.path, "public test master")
        self.assertEqual(self.vault.browser_associations(), [])
        self.assertFalse(self.vault.browser_authenticate("browser", self.other_key)["authenticated"])
        self.assertNotIn("KPXC_BROWSER_browser", ET.tostring(self.xml(), encoding="unicode"))
        with self.assertRaises(EngineError):
            self.vault.browser_revoke("missing")

    def test_invalid_keys_and_locked_calls_never_write(self):
        before = self.path.read_bytes()
        for key in ["", "!" * 44, base64.b64encode(b"short").decode(), self.key + "\n", self.key.rstrip("=")]:
            with self.subTest(key=key), self.assertRaises(EngineError):
                self.vault.browser_associate("browser", key)
            self.assertEqual(self.path.read_bytes(), before)
        self.vault.lock()
        with self.assertRaises(VaultError):
            self.vault.browser_info()

    def test_external_revocation_is_not_authorized_from_stale_memory(self):
        self.vault.browser_associate("browser", self.key)
        other = Vault(ENGINE)
        self.addCleanup(other.lock)
        other.unlock(self.path, "public test master")
        other.browser_revoke("browser")
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_authenticate("browser", self.key)
        self.assertEqual(caught.exception.code, "conflict")
        self.assertTrue(self.vault.unlocked)
        self.vault.refresh()
        self.assertFalse(self.vault.browser_authenticate("browser", self.key)["authenticated"])

    def test_existing_upstream_association_and_unrelated_metadata_are_preserved(self):
        xml = self.xml()
        metadata = xml.find("Meta/CustomData")
        if metadata is None:
            metadata = ET.SubElement(xml.find("Meta"), "CustomData")
        for name, value in [("KPXC_BROWSER_existing", self.key), ("_CREATED_existing", "existing timestamp"),
                            ("other-plugin", "unrelated data")]:
            item = ET.SubElement(metadata, "Item")
            ET.SubElement(item, "Key").text = name
            ET.SubElement(item, "Value").text = value
        source = self.root / "stock-export.xml"
        ET.ElementTree(xml).write(source, encoding="utf-8", xml_declaration=True)
        before = source.read_bytes()
        target = self.root / "imported.kdbx"
        self.vault.import_database(target, source, "xml", "public test master")
        self.assertTrue(self.vault.browser_authenticate("existing", self.key)["authenticated"])
        self.assertEqual(self.vault.browser_associations(), [{"id": "existing", "created": "existing timestamp"}])
        self.vault.browser_associate("new", self.other_key)
        self.vault.browser_revoke("existing")
        saved = {i.findtext("Key"): i.findtext("Value") for i in self.xml().findall("Meta/CustomData/Item")}
        self.assertEqual(saved["other-plugin"], "unrelated data")
        self.assertEqual(saved["KPXC_BROWSER_new"], self.other_key)
        self.assertNotIn("KPXC_BROWSER_existing", saved)
        self.assertNotIn("_CREATED_existing", saved)
        self.assertEqual(source.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
