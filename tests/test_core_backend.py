"""Pipe-boundary tests use a mock; file-format tests below require the real core."""
import csv
import hashlib
import json
import os
import queue
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from keyslot.core_backend import Vault, EngineError
from keyslot.backend import VaultError
from keyslot.session import SessionJobs

MOCK = '''
import json, sys, time
from pathlib import Path
snapshot={"name":"Demo","root":"root-id","recycle_bin_enabled":True,
 "groups":[{"uuid":"root-id","path":"/","name":"Root","depth":0},
           {"uuid":"group-a","parent":"root-id","path":"/Same/","name":"Same","depth":1},
           {"uuid":"group-b","parent":"root-id","path":"/Same/","name":"Same","depth":1}],
 "entries":[{"uuid":"entry-a","group":"group-a","group_path":"/Same/","path":"/Same/Same","title":"Same"},
            {"uuid":"entry-b","group":"group-b","group_path":"/Same/","path":"/Same/Same","title":"Same"}]}
values={"entry-a":{"Password":"first","UserName":"a","URL":"","Notes":""},
        "entry-b":{"Password":"second","UserName":"b","URL":"","Notes":""}}
opened=False
settings={"name":"Demo","cipher":"unchanged-cipher","password_key":True,"file_key":True}
for line in sys.stdin.buffer:
 request=json.loads(line)
 method=request["method"]; p=request["params"]; result=True; error=None
 if method=="hello":result={"protocol":1,"engine":"keepassxc-core","upstream":"2.7.12","capabilities":["generator-options"]}
 elif method in ("open","create"):opened=True;result=snapshot
 elif method=="import.create":opened=True;settings["last_import"]=p;result=snapshot
 elif method=="import.csv.inspect":
  settings["last_csv_inspection"]=p
  result={"rows":2,"columns":2,"headers":["Title","Password"],"mapping":{"title":0,"password":1},
          "preview":[["public","public mock secret"]] if p["reveal"] else [],
          "source_fingerprint":"a"*64,"skip_rows":1,"row_start":1,"column_start":0,
          "preview_headers":["Title","Password"],"shortened":False,"codecs":["UTF-8"]}
 elif method=="import.inspect":
  settings["last_import_inspection"]=p
  result={"entries":1,"groups":1,"row_start":p["row_start"],"preview":[{"title":"Public","username":"user","group":"Root"}],"source_fingerprint":"a"*64}
 elif method=="attribute":result=values[p["entry"]][p["name"]]
 elif method=="entry.save":
  values[p["entry"]].update(p["fields"]);result=snapshot
 elif method=="group.save":result=snapshot
 elif method=="refresh":result=snapshot
 elif method=="database.settings":result=settings
 elif method=="database.settings.save":settings.update(p);result=snapshot
 elif method=="database.kdf.benchmark":result={"rounds":123}
 elif method=="database.key.change":settings["last_key_change"]=p;result=snapshot
 elif method=="database.merge":settings["last_merge"]=p;result=snapshot
 elif method=="database.report":result={"entries":2,"health":[]}
 elif method=="attachment.import":
  settings["last_attachment"]=p;settings["attachment_size"]=Path(p["source"]).stat().st_size;result=snapshot
 elif method=="attachment.export":Path(p["path"]).write_bytes(b"public mock attachment");result=True
 elif method in ("database.export","database.copy","keyfile.generate"):
  target=Path(p["path"])
  target.write_bytes(b"public mock output")
  if p.get("format")=="unconfirmed":result=False
  if p.get("format")=="slow":
   nested=target.parent/"helper-stage";nested.mkdir();(nested/"plaintext").write_bytes(b"public mock output")
   time.sleep(20)
 elif method=="search":result=["entry-b"]
 elif method=="generate":
  settings["last_generate"]=p
  if p["length"]==99:time.sleep(20)
  elif p["length"]==98:
   print(json.dumps({"id":request["id"]+1,"result":"wrong-id-secret"}),flush=True);continue
  else:result="a"*p["length"]
 elif method=="attribute.remove":error={"code":"not_found","message":"The attribute does not exist."}
 response={"id":request["id"],"unlocked":opened}
 response["error" if error else "result"]=error if error else result
 print(json.dumps(response),flush=True)
'''


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        executable = self.directory / "mock-engine"
        executable.write_text("#!" + sys.executable + "\n" + MOCK)
        executable.chmod(0o755)
        self.vault = Vault(executable, timeout=2)
        self.database = self.directory / "fixture.kdbx"
        self.database.write_bytes(b"public mock fixture, not a KDBX")
        self.vault.unlock(self.database, "master\nwith NUL\0and quotes\"")

    def tearDown(self):
        self.vault.lock()
        self.temporary.cleanup()

    def test_uuid_addressing_with_duplicate_paths(self):
        a, b = self.vault.snapshot.entries
        self.assertEqual(a.path, b.path)
        self.assertEqual(self.vault.attribute(a), "first")
        self.assertEqual(self.vault.attribute(b), "second")
        self.assertEqual(self.vault.snapshot.groups[1].identity, "group-a")
        self.assertEqual(self.vault.snapshot.groups[2].identity, "group-b")
        self.assertFalse(hasattr(self.vault, "_password"))

    def test_empty_multiline_backslash_unicode_and_nul_fields(self):
        a = self.vault.snapshot.entries[0]
        secret = "密碼\n\0 \\\""
        note = "line 1\nline 2\\n literal"
        self.vault.save_entry(a.group, "title/with/slashes", "", "", note, secret, a)
        a = self.vault.snapshot.entries[0]
        self.assertEqual(self.vault.attribute(a), secret)
        self.assertEqual(self.vault.editable_fields(a), {"UserName":"", "URL":"", "Notes":note})

    def test_errors_do_not_desynchronize_protocol(self):
        a = self.vault.snapshot.entries[0]
        with self.assertRaises(EngineError) as caught:
            self.vault.remove_attribute(a, "missing")
        self.assertEqual(caught.exception.code, "not_found")
        self.assertEqual(self.vault.attribute(a), "first")
        self.assertEqual(self.vault.search("title:Same"), ["entry-b"])

    def test_mismatched_response_fails_closed(self):
        with self.assertRaises(VaultError) as caught:
            self.vault.generate(98)
        self.assertNotIn("secret", str(caught.exception))
        self.assertFalse(self.vault.unlocked)
        self.assertIsNone(self.vault._process)

    def test_cancel_interrupts_inflight_request(self):
        runtime = Path(self.vault._runtime.name)
        failures = []
        def run():
            try:
                self.vault.generate(99)
            except VaultError as exc:
                failures.append(exc)
        worker = threading.Thread(target=run)
        worker.start()
        time.sleep(0.05)
        self.vault.cancel()
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertTrue(failures)
        self.vault.lock()
        self.assertFalse(self.vault.unlocked)
        self.assertIsNone(self.vault._runtime)
        self.assertFalse(runtime.exists(), "Parent must remove helper settings even after killing it")

    def test_cancelled_operation_cannot_restart_engine_or_reuse_old_entries(self):
        entry = self.vault.snapshot.entries[0]
        generation = self.vault.generation
        self.vault.cancel()
        with self.vault.operation(generation), self.assertRaises(VaultError):
            self.vault.unlock(self.database, "master")
        self.assertIsNone(self.vault._process)
        self.assertFalse(self.vault.unlocked)
        self.vault.finish_lock()
        generation = self.vault.generation
        with self.vault.operation(generation):
            self.vault.unlock(self.database, "master")
        self.assertTrue(self.vault.unlocked)
        with self.assertRaises(VaultError):
            self.vault.attribute(entry)
        callbacks, errors, results = queue.Queue(), [], []
        jobs = SessionJobs(self.vault, callbacks.put, lambda: None, lambda: None, errors.append)
        try:
            jobs.lock()
            self.assertTrue(jobs.run(lambda: self.vault.unlock(self.database, "master"), results.append))
            callbacks.get(timeout=2)()
            self.assertEqual(errors, [])
            self.assertEqual(len(results), 1)
            self.assertTrue(self.vault.unlocked)
        finally:
            jobs.close()

    def test_private_helpers_and_entry_ownership_are_isolated_between_sessions(self):
        other = Vault(self.vault.executable, timeout=2)
        try:
            other.unlock(self.database, "master")
            first, second = self.vault.snapshot.entries[0], other.snapshot.entries[0]
            self.assertEqual(first.uuid, second.uuid)
            self.assertNotEqual(self.vault._process.pid, other._process.pid)
            with self.assertRaises(VaultError):
                other.attribute(first)
            self.vault.save_entry(first.group, first.title, "", "", "", "first database only", first)
            self.assertEqual(other.attribute(second), "first")
            self.vault.lock()
            self.assertTrue(other.unlocked)
            self.assertEqual(other.attribute(second), "first")
        finally:
            other.lock()

    def test_generator_options_are_forwarded_and_require_engine_support(self):
        self.vault.generate(12, lowercase=False, uppercase=False, numbers=True, symbols=False, excluded="01")
        request = self.vault.settings()["last_generate"]
        self.assertEqual(request["excluded"], "01")
        self.assertFalse(request["symbols"])
        self.vault.capabilities = frozenset()
        with self.assertRaises(VaultError):
            self.vault.generate(12, symbols=False)

    def test_settings_and_key_updates_preserve_unspecified_components(self):
        self.vault.save_settings(name="")
        self.assertEqual(self.vault.settings()["name"], "")
        self.assertEqual(self.vault.settings()["cipher"], "unchanged-cipher")
        self.assertEqual(self.vault.benchmark_kdf(100), {"rounds":123})
        self.vault.change_key(password="new\nmaster\0")
        self.assertEqual(self.vault.settings()["last_key_change"], {"password":"new\nmaster\0"})
        self.assertFalse(hasattr(self.vault, "_password"))
        self.assertEqual(self.vault.report(), {"entries":2,"health":[]})
        source = self.directory / "source.kdbx"
        source.write_bytes(b"public mock database")
        self.vault.merge(source, same_credentials=True)
        self.assertTrue(self.vault.settings()["last_merge"]["same_credentials"])

    def test_export_and_keyfile_output_permissions_no_clobber_and_confirmation(self):
        destination = self.directory / "export.xml"
        self.vault.export_database(destination)
        self.assertEqual(destination.read_bytes(), b"public mock output")
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        destination.write_bytes(b"keep existing file")
        with self.assertRaises(FileExistsError):
            self.vault.export_database(destination)
        self.assertEqual(destination.read_bytes(), b"keep existing file")
        self.vault.export_database(destination, overwrite=True)
        self.assertEqual(destination.read_bytes(), b"public mock output")
        with self.assertRaises(VaultError):
            self.vault.export_database(self.database, overwrite=True)
        self.assertEqual(self.database.read_bytes(), b"public mock fixture, not a KDBX")
        key = self.directory / "generated.keyx"
        self.vault.generate_keyfile(key)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(VaultError):
            self.vault.export_database(self.directory / "unconfirmed.xml", "unconfirmed")
        self.assertFalse((self.directory / "unconfirmed.xml").exists())
        self.assertFalse(list(self.directory.glob(".keyslot-output-*")))

    def test_cancelled_export_cleans_parent_and_helper_plaintext_staging(self):
        failures = []
        destination = self.directory / "cancelled.xml"
        def export():
            try:
                self.vault.export_database(destination, "slow")
            except VaultError as exc:
                failures.append(exc)
        worker = threading.Thread(target=export)
        worker.start()
        deadline = time.monotonic() + 1
        while not list(self.directory.glob(".keyslot-output-*/helper-stage/plaintext")) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(list(self.directory.glob(".keyslot-output-*/helper-stage/plaintext")))
        self.vault.cancel()
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertTrue(failures)
        self.assertFalse(destination.exists())
        self.assertFalse(list(self.directory.glob(".keyslot-output-*")))

    def test_encrypted_copy_no_clobber_and_original_path_guard(self):
        destination = self.directory / "copy.kdbx"
        original = self.database.read_bytes()
        self.vault.save_copy(destination)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        destination.write_bytes(b"keep existing copy")
        with self.assertRaises(FileExistsError):
            self.vault.save_copy(destination)
        self.assertEqual(destination.read_bytes(), b"keep existing copy")
        self.vault.save_copy(destination, overwrite=True)
        alias = self.directory / "alias.kdbx"
        alias.symlink_to(self.database)
        for path in (self.database, alias):
            with self.assertRaises(VaultError):
                self.vault.save_copy(path, overwrite=True)
        self.assertEqual(original, self.database.read_bytes())
        self.assertEqual(self.vault.path, self.database)
        self.assertEqual(self.vault.attribute(self.vault.snapshot.entries[0]), "first")
        self.vault.lock()
        with self.assertRaises(VaultError):
            self.vault.save_copy(self.directory / "locked.kdbx")

    def test_import_framing_source_types_and_existing_destination_guard(self):
        source = self.directory / "source.json"
        source.write_text("public mock import fixture")
        destination = self.directory / "imported.kdbx"
        with self.assertRaises(VaultError):
            self.vault.import_database(self.database, source, "bitwarden", "new master")
        dangling = self.directory / "dangling.kdbx"
        absent = self.directory / "absent.kdbx"
        dangling.symlink_to(absent)
        with self.assertRaises(VaultError):
            self.vault.import_database(dangling, source, "bitwarden", "new master")
        self.assertFalse(absent.exists())
        self.assertTrue(dangling.is_symlink())
        self.assertEqual(self.vault.attribute(self.vault.snapshot.entries[0]), "first")
        for format in ("unsupported", "opvault"):
            with self.assertRaises(VaultError):
                self.vault.import_database(destination, source, format, "new master")
            self.assertTrue(self.vault.unlocked)
        source_secret = "source\npassword\0with Unicode 密碼"
        target_secret = "different\nnew password\0"
        self.vault.import_database(destination, source, "bitwarden", target_secret, source_password=source_secret)
        request = self.vault.settings()["last_import"]
        self.assertEqual(request["source_password"], source_secret)
        self.assertEqual(request["password"], target_secret)
        self.assertEqual(request["source"], str(source))
        self.assertEqual(self.vault.path, destination)
        self.assertEqual(source.read_text(), "public mock import fixture")
        folder = self.directory / "source.opvault"
        folder.mkdir()
        self.vault.import_database(self.directory / "folder.kdbx", folder, "opvault", "", no_password=True, keyfile="public.keyx")
        self.assertTrue(self.vault.settings()["last_import"]["no_password"])

    def test_attachment_transfer_uses_files_above_old_frame_limit(self):
        source = self.directory / "large-attachment.bin"
        with source.open("wb") as stream:
            stream.truncate(42 * 1024 * 1024)
        self.vault.import_attachment(self.vault.snapshot.entries[0], source)
        settings = self.vault.settings()
        self.assertEqual(settings["attachment_size"], 42 * 1024 * 1024)
        self.assertNotIn("data", settings["last_attachment"])
        alias = self.directory / "selected-name.bin"
        alias.symlink_to(source)
        self.vault.import_attachment(self.vault.snapshot.entries[0], alias, replace=True)
        self.assertEqual(self.vault.settings()["last_attachment"]["name"], alias.name)
        self.assertTrue(self.vault.settings()["last_attachment"]["replace"])
        output = self.directory / "exported-attachment.bin"
        self.vault.export_attachment(self.vault.snapshot.entries[0], source.name, output)
        self.assertEqual(output.read_bytes(), b"public mock attachment")
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.directory.glob(".keyslot-output-*")))

    def test_csv_inspection_review_and_import_options_use_private_protocol(self):
        source = self.directory / "source.csv"
        source.write_text('Title,Password\nPublic,public mock secret\n')
        options = {"separator": ",", "qualifier": '"', "has_header": True, "skip_rows": 1,
                   "mapping": {"title": 0, "password": 1}, "backslash": False}
        data = self.vault.inspect_csv(source, options)
        self.assertEqual(data["preview"], [])
        self.assertFalse(self.vault.settings()["last_csv_inspection"]["reveal"])
        self.assertTrue(self.vault.unlocked)
        self.assertEqual(self.vault.attribute(self.vault.snapshot.entries[0]), "first")
        data = self.vault.inspect_csv(source, options, 1, 0, True, "a" * 64)
        self.assertTrue(data["preview"])
        inspection = self.vault.settings()["last_csv_inspection"]
        self.assertEqual(inspection["source_fingerprint"], "a" * 64)
        self.assertEqual(inspection["row_start"], 1)
        self.assertEqual(inspection["csv_options"], options)
        review = self.vault.inspect_import(source, "csv", csv_options=options, source_fingerprint="a" * 64, row_start=200)
        self.assertEqual(review["row_start"], 200)
        self.assertEqual(self.vault.settings()["last_import_inspection"]["csv_options"], options)
        self.vault.import_database(self.directory / "from-csv.kdbx", source, "csv", "new master",
                                   csv_options=options, source_fingerprint=review["source_fingerprint"])
        request = self.vault.settings()["last_import"]
        self.assertEqual(request["csv_options"], options)
        self.assertEqual(request["source_fingerprint"], "a" * 64)
        self.assertEqual(source.read_text(), 'Title,Password\nPublic,public mock secret\n')


ENGINE = shutil.which(os.environ.get("KEYSLOT_ENGINE", "keyslot-engine"))
if os.environ.get("KEYSLOT_REQUIRE_ENGINE") == "1" and not ENGINE:
    raise RuntimeError("Native engine integration is required for the package build.")


@unittest.skipUnless(ENGINE, "native KeePassXC core helper is not built")
class CoreIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.path = self.directory / "vault.kdbx"
        self.vault = Vault(ENGINE)
        self.vault.create(self.path, "master password")

    def tearDown(self):
        self.vault.lock()
        self.temporary.cleanup()

    def test_edit_clear_duplicate_names_history_and_custom_attributes(self):
        root = self.vault.snapshot.root
        self.vault.add_group(root, "Same/Group")
        self.vault.add_group(root, "Same/Group")
        groups = [g for g in self.vault.snapshot.groups if g.name == "Same/Group"]
        self.assertEqual(len(groups), 2)
        for group, password in zip(groups, ["first\npassword\0", "second"]):
            self.vault.save_entry(group.uuid, "Same/Title", "user", "https://example.org", "line\nnotes", password)
        a, b = self.vault.snapshot.entries
        self.assertEqual(self.vault.attribute(a), "first\npassword\0")
        self.assertEqual(self.vault.attribute(b), "second")
        self.vault.save_entry(a.group, a.title, "", "", "", "", a, expires=True, expiry="2030-01-02T03:04:05+02:00")
        a = next(e for e in self.vault.snapshot.entries if e.uuid == a.uuid)
        self.assertEqual(a.expiry, "2030-01-02T01:04:05Z")
        self.assertEqual(self.vault.attribute(a), "")
        self.assertEqual(self.vault.attribute(a, "UserName"), "")
        self.assertEqual(self.vault.attribute(a, "URL"), "")
        self.assertEqual(self.vault.attribute(a, "Notes"), "")
        history = self.vault.history(a)
        self.assertTrue(history)
        self.vault.restore_history(a, history[0]["index"])
        a = next(e for e in self.vault.snapshot.entries if e.uuid == a.uuid)
        self.assertEqual(self.vault.attribute(a), "first\npassword\0")
        self.vault.set_attribute(a, "API token", "private\nvalue", True)
        a = next(e for e in self.vault.snapshot.entries if e.uuid == a.uuid)
        self.assertEqual(self.vault.attribute_info(a, "API token"), {"value":"private\nvalue", "protected":True})
        self.assertNotIn("private\nvalue", repr(self.vault.snapshot))
        self.vault.remove_attribute(a, "API token")

    def test_totp_attachment_group_move_and_restore(self):
        root = self.vault.snapshot.root
        self.assertEqual(len(self.vault.generate(32)), 32)
        self.assertEqual(len(self.vault.generate(6, passphrase=True).split()), 6)
        self.vault.save_entry(root, "Login", "user", "", "", "password")
        entry = self.vault.snapshot.entries[0]
        self.vault.set_totp(entry, "otpauth://totp/Demo?secret=JBSWY3DPEHPK3PXP&issuer=Demo")
        entry = self.vault.snapshot.entries[0]
        self.assertRegex(self.vault.attribute(entry, totp=True), r"^\d{6}$")
        source = self.directory / "attachment.txt"
        source.write_bytes(b"public test attachment")
        self.vault.import_attachment(entry, source)
        entry = self.vault.snapshot.entries[0]
        exported = self.directory / "exported.txt"
        self.vault.export_attachment(entry, source.name, exported)
        self.assertEqual(source.read_bytes(), exported.read_bytes())
        source.write_bytes(b"updated public attachment")
        with self.assertRaises(EngineError):
            self.vault.import_attachment(entry, source)
        self.vault.import_attachment(entry, source, replace=True)
        entry = self.vault.snapshot.entries[0]
        second_export = self.directory / "replacement.txt"
        self.vault.export_attachment(entry, source.name, second_export)
        self.assertEqual(second_export.read_bytes(), b"updated public attachment")
        self.vault.remove_attachment(entry, source.name)
        entry = self.vault.snapshot.entries[0]
        self.assertFalse(entry.attachments)
        self.vault.delete_entry(entry)
        entry = next(e for e in self.vault.snapshot.entries if e.uuid == entry.uuid)
        self.assertTrue(entry.recycled)
        self.vault.move_entry(entry, root)
        self.assertFalse(next(e for e in self.vault.snapshot.entries if e.uuid == entry.uuid).recycled)
        self.assertTrue(Path(str(self.path) + ".keyslot.bak").is_file())

    def test_conflict_and_invalid_mutation_preserve_file(self):
        root = self.vault.snapshot.root
        before = self.path.read_bytes()
        with self.assertRaises(EngineError):
            self.vault.save_entry(root, "Invalid", "", "", "", "p", expires=True, expiry="invalid timestamp")
        self.assertEqual(before, self.path.read_bytes())
        self.vault.save_entry(root, "Valid", "", "", "", "p")
        entry = self.vault.snapshot.entries[0]
        subprocess.run(["keepassxc-cli", "mkdir", "-q", str(self.path), "External"],
                       input=b"master password\n", check=True, capture_output=True)
        before = self.path.read_bytes()
        with self.assertRaises(EngineError) as caught:
            self.vault.save_entry(root, entry.title, "changed", "", "", None, entry)
        self.assertEqual(caught.exception.code, "conflict")
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(self.vault.attribute(entry), "p")

    def test_two_open_database_copies_keep_keys_entries_and_locks_isolated(self):
        self.vault.save_entry(self.vault.snapshot.root, "Same", "user", "", "", "first fixture password")
        first = self.vault.snapshot.entries[0]
        other_path = self.directory / "other.kdbx"
        shutil.copyfile(self.path, other_path)
        other = Vault(ENGINE)
        try:
            other.unlock(other_path, "master password")
            second = other.snapshot.entries[0]
            self.assertEqual(first.uuid, second.uuid)
            with self.assertRaises(VaultError):
                other.attribute(first)
            other.change_key(password="second master")
            second = other.snapshot.entries[0]
            other.save_entry(second.group, second.title, "user", "", "", "second fixture password", second)
            self.assertEqual(self.vault.attribute(first), "first fixture password")
            self.vault.lock()
            self.assertEqual(other.attribute(other.snapshot.entries[0]), "second fixture password")
            other.lock()

            self.vault.unlock(self.path, "master password")
            other.unlock(other_path, "second master")
            self.assertEqual(self.vault.attribute(self.vault.snapshot.entries[0]), "first fixture password")
            self.assertEqual(other.attribute(other.snapshot.entries[0]), "second fixture password")
        finally:
            other.lock()


    def test_generator_character_groups_and_exclusions(self):
        disabled = {"lowercase": False, "uppercase": False, "numbers": False, "symbols": False}
        for key, pattern in [("lowercase", r"[a-z]{32}"), ("uppercase", r"[A-Z]{32}"), ("numbers", r"[0-9]{32}")]:
            value = self.vault.generate(32, **{**disabled, key: True})
            self.assertRegex(value, "^" + pattern + "$")
        self.assertRegex(self.vault.generate(1, **{**disabled, "numbers": True}), r"^[0-9]$")
        value = self.vault.generate(64, **disabled, additional="xyz", excluded="x")
        self.assertEqual(len(value), 64)
        self.assertTrue(set(value) <= {"y", "z"})
        value = self.vault.generate(64, **{**disabled, "numbers": True}, exclude_lookalike=True)
        self.assertFalse(set(value) & set("0168"))
        value = self.vault.generate(32, **{**disabled, "symbols": True}, braces=True, punctuation=False,
                                    quotes=False, dashes=False, math=False, logograms=False)
        self.assertTrue(set(value) <= set("()[]{}"))
        with self.assertRaises(EngineError):
            self.vault.generate(24, **disabled)
        with self.assertRaises(EngineError):
            self.vault.generate(24, **disabled, additional="x", excluded="x")

    def test_database_settings_and_key_rotation_rollback(self):
        root = self.vault.snapshot.root
        self.vault.save_entry(root, "Entry", "user", "", "", "test-only-password")
        settings = self.vault.settings()
        before_benchmark = self.path.read_bytes()
        self.assertGreaterEqual(self.vault.benchmark_kdf(100)["rounds"], 1)
        self.assertEqual(before_benchmark, self.path.read_bytes())
        alternative_cipher = next(item["id"] for item in settings["ciphers"] if item["id"] != settings["cipher"])
        self.vault.save_settings(name="資料庫", description="first line\nsecond line", default_username="default user",
                                 history_items=3, compression=False, cipher=alternative_cipher)
        settings = self.vault.settings()
        self.assertEqual(settings["name"], "資料庫")
        self.assertEqual(settings["description"], "first line\nsecond line")
        self.assertEqual(self.vault.snapshot.default_username, "default user")
        self.assertFalse(settings["compression"])
        self.assertEqual(settings["cipher"], alternative_cipher)
        before = self.path.read_bytes()
        with self.assertRaises(EngineError):
            self.vault.save_settings(rounds=0)
        self.assertEqual(before, self.path.read_bytes())
        backup = Path(str(self.path) + ".keyslot.bak")
        backup.unlink()
        backup.mkdir()
        with self.assertRaises(EngineError):
            self.vault.change_key(password="new master")
        self.assertTrue(self.vault.unlocked)
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(self.vault.attribute(self.vault.snapshot.entries[0]), "test-only-password")
        backup.rmdir()
        self.vault.change_key(password="new master")
        self.vault.lock()
        with self.assertRaises(EngineError):
            self.vault.unlock(self.path, "master password")
        self.vault.unlock(self.path, "new master")
        self.assertEqual(self.vault.attribute(self.vault.snapshot.entries[0]), "test-only-password")
        previous = Vault(ENGINE)
        try:
            previous.unlock(backup, "master password")
            self.assertEqual(previous.attribute(previous.snapshot.entries[0]), "test-only-password")
        finally:
            previous.lock()

    def test_failed_refresh_preserves_open_data_for_encrypted_copy(self):
        self.vault.save_entry(self.vault.snapshot.root, "Recovery", "user", "", "", "public-fixture-secret")
        entry_id = self.vault.snapshot.entries[0].uuid
        original = self.path.read_bytes()
        self.path.write_bytes(b"public corrupt fixture")
        with self.assertRaises(EngineError):
            self.vault.refresh()
        self.assertTrue(self.vault.unlocked)
        entry = next(e for e in self.vault.snapshot.entries if e.uuid == entry_id)
        self.assertEqual(self.vault.attribute(entry), "public-fixture-secret")
        self.path.unlink()
        with self.assertRaises(EngineError):
            self.vault.refresh()
        self.assertTrue(self.vault.unlocked)
        destination = self.directory / "recovered.kdbx"
        self.vault.save_copy(destination)
        export = self.directory / "recovered.xml"
        self.vault.export_database(export)
        self.assertIn(b"public-fixture-secret", export.read_bytes())
        self.assertFalse(self.path.exists())
        self.assertEqual(self.vault.path, self.path)
        recovered = Vault(ENGINE)
        try:
            recovered.unlock(destination, "master password")
            self.assertEqual(recovered.snapshot.entries[0].uuid, entry_id)
            self.assertEqual(recovered.attribute(recovered.snapshot.entries[0]), "public-fixture-secret")
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        finally:
            recovered.lock()
        self.path.write_bytes(original)
        self.vault.refresh()
        self.vault.save_entry(self.vault.snapshot.root, "After Recovery", "", "", "", "p")

    def test_short_password_seals_credentials_and_reopens_original_vault(self):
        import base64
        credentials = {"password": "master password", "keyfile": "", "yubikey": "", "no_password": False}
        self.vault.save_entry(self.vault.snapshot.root, "Quick fixture", "", "", "", "public entry secret")
        original = self.path.read_bytes()
        with self.assertRaises(EngineError):
            self.vault.seal_quick_unlock({**credentials, "password": "wrong password"}, "1234")
        with self.assertRaises(EngineError):
            self.vault.seal_quick_unlock(credentials, "123")
        blob = self.vault.seal_quick_unlock(credentials, "1234")
        encrypted = base64.b64decode(blob)
        self.assertNotIn(b'master password', encrypted)
        self.assertNotIn(str(self.path).encode(), encrypted)
        self.assertEqual(self.path.read_bytes(), original)
        self.vault.lock()
        with self.assertRaises(EngineError) as error:
            self.vault.quick_unlock(self.path, blob, "wrong PIN")
        self.assertEqual(error.exception.code, "quick_password")
        self.assertFalse(self.vault.unlocked)
        other = self.directory / "other.kdbx"
        other.write_bytes(original)
        with self.assertRaises(EngineError):
            self.vault.quick_unlock(other, blob, "1234")
        self.vault.quick_unlock(self.path, blob, "1234")
        self.assertEqual(self.vault.attribute(self.vault.snapshot.entries[0]), "public entry secret")
        self.assertEqual(self.path.read_bytes(), original)

    def test_verifying_login_credential_preserves_current_database(self):
        self.vault.save_entry(self.vault.snapshot.root, "Login fixture", "", "", "", "public fixture secret")
        before = self.path.read_bytes()
        self.vault.verify_credentials("master password")
        with self.assertRaises(EngineError):
            self.vault.verify_credentials("wrong fixture password")
        self.assertTrue(self.vault.unlocked)
        self.assertEqual(self.vault.path, self.path)
        self.assertEqual(self.vault.attribute(self.vault.snapshot.entries[0]), "public fixture secret")
        self.assertEqual(self.path.read_bytes(), before)
        keyfile = self.directory / 'login.keyx'
        self.vault.generate_keyfile(keyfile)
        for password, key_only in [('Żółw 密碼 🔐 spaced ', False), ('', True)]:
            with self.subTest(key_only=key_only):
                candidate = Vault(ENGINE)
                try:
                    target = self.directory / ('key-only.kdbx' if key_only else 'composite.kdbx')
                    credentials = dict(password=password, keyfile=str(keyfile), no_password=key_only, yubikey='')
                    candidate.create(target, **credentials)
                    original = target.read_bytes()
                    candidate.verify_credentials(**credentials)
                    with self.assertRaises(EngineError):
                        candidate.verify_credentials(password, no_password=key_only)
                    self.assertTrue(candidate.unlocked)
                    blob = candidate.seal_quick_unlock(credentials, '1234')
                    candidate.lock()
                    candidate.quick_unlock(target, blob, '1234')
                    self.assertTrue(candidate.unlocked)
                    self.assertEqual(target.read_bytes(), original)
                finally:
                    candidate.lock()

    def test_import_xml_preserves_values_history_attachments_and_source(self):
        self.vault.save_entry(self.vault.snapshot.root, "XML fixture", "user", "https://example.org", "Unicode 密碼\nnotes", "old fixture password")
        entry = self.vault.snapshot.entries[0]
        self.vault.set_attribute(entry, "API Token", "public fixture token", True)
        entry = self.vault.snapshot.entries[0]
        self.vault.save_entry(entry.group, entry.title, "user", entry.url, entry.notes, "new fixture password", entry)
        entry = self.vault.snapshot.entries[0]
        self.vault.set_totp(entry, "otpauth://totp/Demo?secret=JBSWY3DPEHPK3PXP&issuer=Demo")
        attachment = self.directory / "attached.txt"
        attachment.write_bytes(b"public import attachment fixture")
        self.vault.import_attachment(self.vault.snapshot.entries[0], attachment)
        original_entry = self.vault.snapshot.entries[0]
        source = self.directory / "source.xml"
        self.vault.export_database(source)
        source_bytes, original_bytes = source.read_bytes(), self.path.read_bytes()
        imported = Vault(ENGINE)
        destination = self.directory / "from-xml.kdbx"
        try:
            imported.import_database(destination, source, "xml", "import master")
            result = imported.snapshot.entries[0]
            self.assertEqual(result.uuid, original_entry.uuid)
            self.assertEqual(result.notes, "Unicode 密碼\nnotes")
            self.assertEqual(result.history_count, original_entry.history_count)
            self.assertEqual(imported.attribute(result), "new fixture password")
            self.assertEqual(imported.attribute_info(result, "API Token"), {"value":"public fixture token", "protected":True})
            self.assertTrue(result.totp)
            output = self.directory / "imported-attachment.txt"
            imported.export_attachment(result, attachment.name, output)
            self.assertEqual(output.read_bytes(), attachment.read_bytes())
            imported.lock()
            imported.unlock(destination, "import master")
            self.assertEqual(imported.attribute(imported.snapshot.entries[0]), "new fixture password")
            self.assertEqual(source.read_bytes(), source_bytes)
            self.assertEqual(self.path.read_bytes(), original_bytes)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        finally:
            imported.lock()

    def test_csv_import_mapping_preview_and_roundtrip(self):
        source = self.directory / "source.csv"
        secret = "public-csv-fixture-secret"
        long_secret = "public long fixture " * 40
        with source.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream, delimiter=";")
            writer.writerow(["Group", "Title", "Username", "Password", "URL", "Tags", "Notes", "TOTP", "Icon", "Last Modified", "Created"])
            writer.writerow(["Root/Work", 'Login, "密碼"', "alice", secret, "https://example.org", "one;two", "first\nsecond",
                             "JBSWY3DPEHPK3PXP", "5", "2024-01-02T03:04:05+02:00", "1700000000"])
            writer.writerow(["Root/Work", 'Login, "密碼"', "bob", long_secret, "", "", "", "", "", "", ""])
        before = source.read_bytes()
        options = {"separator": ";"}
        data = self.vault.inspect_csv(source, options)
        self.assertEqual((data["rows"], data["columns"], data["skip_rows"]), (3, 11, 1))
        self.assertEqual(data["mapping"]["password"], 3)
        self.assertEqual(data["preview"], [])
        self.assertNotIn(secret, json.dumps(data))
        shown = self.vault.inspect_csv(source, options, reveal=True, source_fingerprint=data["source_fingerprint"])
        self.assertEqual(shown["preview"][0][3], secret)
        self.assertEqual(shown["preview"][1][3], long_secret[:256])
        self.assertTrue(shown["shortened"])
        review = self.vault.inspect_import(source, "csv", csv_options=options, source_fingerprint=data["source_fingerprint"])
        self.assertEqual(review["entries"], 2)
        self.assertEqual(review["groups"], 2)
        self.assertNotIn(secret, json.dumps(review))
        self.assertNotIn(long_secret, json.dumps(review))
        target = self.directory / "csv-import.kdbx"
        imported = Vault(ENGINE)
        try:
            imported.import_database(target, source, "csv", "import master", csv_options=options,
                                     source_fingerprint=review["source_fingerprint"])
            for reopened in (False, True):
                if reopened:
                    imported.lock()
                    imported.unlock(target, "import master")
                entries = imported.snapshot.entries
                self.assertEqual(len({e.uuid for e in entries}), 2)
                alice = next(e for e in entries if e.username == "alice")
                self.assertEqual(imported.attribute(alice), secret)
                self.assertEqual(alice.notes, "first\nsecond")
                self.assertEqual(alice.icon, 5)
                self.assertEqual(alice.modified, "2024-01-02T01:04:05Z")
                self.assertEqual(alice.created, "2023-11-14T22:13:20Z")
                self.assertTrue(alice.totp)
                self.assertEqual(imported.attribute(next(e for e in entries if e.username == "bob")), long_secret)
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        finally:
            imported.lock()

    def test_csv_legacy_encoding_no_header_and_manual_mapping(self):
        source = self.directory / "legacy.tsv"
        source.write_bytes('ignored row\nMünchen\t"public \\"quoted\\" fixture"\t1700000000000\n'.encode("cp1252"))
        options = {"codec": "Windows-1252", "separator": "\t", "backslash": True,
                   "has_header": False, "skip_rows": 1, "comment": "",
                   "mapping": {"title": 0, "password": 1, "created": 2}}
        target = self.directory / "legacy.kdbx"
        imported = Vault(ENGINE)
        try:
            imported.import_database(target, source, "csv", "master", csv_options=options)
            entry = imported.snapshot.entries[0]
            self.assertEqual(entry.title, "München")
            self.assertEqual(imported.attribute(entry), 'public "quoted" fixture')
            self.assertEqual(entry.created, "2023-11-14T22:13:20Z")
        finally:
            imported.lock()

    def test_csv_invalid_options_and_titleless_confirmation(self):
        source = self.directory / "source.csv"
        source.write_text('Title,Password\nPublic,public-fixture-secret\n')
        before = source.read_bytes()
        for invalid in ({"separator": "xx"}, {"codec": "not-an-encoding"}, {"skip_rows": -1},
                        {"skip_rows": True}, {"mapping": {"password": 9}}, {"mapping": {"password": 0.5}},
                        {"mapping": {"unknown_field": 0}}, {"backslash": "false"}):
            with self.subTest(invalid=invalid), self.assertRaises(EngineError) as caught:
                self.vault.inspect_csv(source, invalid)
            self.assertNotIn("public-fixture-secret", str(caught.exception))
        target = self.directory / "untitled.kdbx"
        options = {"mapping": {"title": -1}}
        with self.assertRaises(EngineError):
            self.vault._rpc("import.create", path=str(target), source=str(source), source_format="csv", csv_options=options, password="master")
        self.assertFalse(target.exists())
        self.assertTrue(self.vault.unlocked)
        imported = Vault(ENGINE)
        try:
            imported.import_database(target, source, "csv", "master", csv_options={**options, "allow_empty_title": True})
            self.assertEqual(imported.snapshot.entries[0].title, "")
            self.assertEqual(imported.attribute(imported.snapshot.entries[0]), "public-fixture-secret")
        finally:
            imported.lock()
        self.assertEqual(source.read_bytes(), before)

    def test_import_review_source_change_guard_and_live_database_preservation(self):
        self.vault.save_entry(self.vault.snapshot.root, "Original", "", "", "", "public original fixture")
        source = self.directory / "review.csv"
        source.write_text('Title,Password\nFirst,public CSV fixture\n')
        original = self.path.read_bytes()
        root = self.vault.snapshot.root
        review = self.vault.inspect_import(source, "csv")
        self.assertEqual(review["entries"], 1)
        self.assertEqual(self.vault.snapshot.root, root)
        self.assertEqual(self.vault.attribute(self.vault.snapshot.entries[0]), "public original fixture")
        fingerprint = review["source_fingerprint"]
        self.assertEqual(fingerprint, hashlib.sha256(source.read_bytes()).hexdigest())
        source.write_text('Title,Password\nChanged,another public fixture\n')
        target = self.directory / "stale-import.kdbx"
        for operation in (lambda: self.vault.inspect_csv(source, source_fingerprint=fingerprint),
                          lambda: self.vault.inspect_import(source, "csv", source_fingerprint=fingerprint),
                          lambda: self.vault._rpc("import.create", path=str(target), source=str(source), source_format="csv",
                                                 password="master", source_fingerprint=fingerprint)):
            with self.assertRaises(EngineError) as caught:
                operation()
            self.assertEqual(caught.exception.code, "conflict")
        self.assertFalse(target.exists())
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(self.vault.attribute(self.vault.snapshot.entries[0]), "public original fixture")

    def test_invalid_import_keeps_live_database_and_creates_no_target(self):
        self.vault.save_entry(self.vault.snapshot.root, "Existing", "", "", "", "public original password")
        source = self.directory / "invalid.xml"
        source.write_bytes(b"public invalid XML fixture")
        target = self.directory / "failed.kdbx"
        original = self.path.read_bytes()
        with self.assertRaises(EngineError):
            self.vault._rpc("import.create", path=str(target), source=str(source), source_format="xml", password="new master")
        self.assertTrue(self.vault.unlocked)
        self.assertEqual(self.vault.attribute(self.vault.snapshot.entries[0]), "public original password")
        self.assertEqual(self.path.read_bytes(), original)
        self.assertFalse(target.exists())
        target.write_bytes(b"keep existing file")
        with self.assertRaises(EngineError):
            self.vault._rpc("import.create", path=str(target), source=str(source), source_format="xml", password="new master")
        self.assertEqual(target.read_bytes(), b"keep existing file")

    def test_upstream_import_fixtures(self):
        fixtures = os.environ.get("KEYSLOT_UPSTREAM_TEST_DATA")
        self.assertTrue(fixtures, "Set KEYSLOT_UPSTREAM_TEST_DATA to the pinned KeePassXC source's tests/data directory.")
        fixtures = Path(fixtures)
        cases = [("keepass1", "basic.kdb", "masterpw", "Test entry", "secretpassword"),
                 ("bitwarden", "bitwarden_export.json", "", "Login Name", "mypassword"),
                 ("bitwarden", "bitwarden_encrypted_export.json", "a", None, None),
                 ("bitwarden", "bitwarden_encrypted_argon2id_export.json", "a", None, None),
                 ("1pux", "1PasswordExport.1pux", "", "Login", "password"),
                 ("opvault", "keepassxc.opvault", "a", "KeePassXC", "opvault"),
                 ("protonpass", "protonpass_export.json", "", "Test Login", "Password")]
        for index, (format, filename, password, title, value) in enumerate(cases):
            with self.subTest(format=format, filename=filename):
                source = fixtures / filename
                sources = sorted(source.rglob("*")) if source.is_dir() else [source]
                before = {path: path.read_bytes() for path in sources if path.is_file()}
                self.assertTrue(before, "The upstream import fixture is missing.")
                target = self.directory / f"import-{index}.kdbx"
                imported = Vault(ENGINE)
                try:
                    if password:
                        with self.assertRaises(EngineError):
                            imported.import_database(target, source, format, "new import master", source_password="wrong source password")
                        self.assertFalse(target.exists())
                    imported.import_database(target, source, format, "new import master", source_password=password)
                    self.assertTrue(imported.snapshot.entries)
                    result = next(entry for entry in imported.snapshot.entries if entry.title == title) if title else imported.snapshot.entries[0]
                    result_id = result.uuid
                    if title is None:
                        value = imported.attribute(result)
                    self.assertEqual(imported.attribute(result), value)
                    imported.lock()
                    imported.unlock(target, "new import master")
                    result = next(entry for entry in imported.snapshot.entries if entry.uuid == result_id)
                    self.assertEqual(imported.attribute(result), value)
                    with self.assertRaises(VaultError):
                        imported.import_database(target, source, format, "replacement master", source_password=password)
                    if format == "opvault":
                        self.assertTrue(result.totp)
                        self.assertEqual(len(result.attachments), 1)
                        output = self.directory / "opvault-attachment.txt"
                        imported.export_attachment(result, result.attachments[0], output)
                        self.assertEqual(output.read_bytes(), b"attachment")
                    self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(before, {path: path.read_bytes() for path in before})
                finally:
                    imported.lock()

    def test_keyfile_only_creation_merge_export_and_reports(self):
        root = self.vault.snapshot.root
        for title in ["First", "Second"]:
            self.vault.save_entry(root, title, "user", "https://example.org", "", "weak-test-value")
        report = self.vault.report()
        self.assertGreaterEqual(report["entries"], 2)
        self.assertGreaterEqual(report["reused"], 1)
        self.assertNotIn("weak-test-value", json.dumps(report))
        keyfile = self.directory / "generated.keyx"
        self.vault.generate_keyfile(keyfile)
        self.assertEqual(keyfile.stat().st_mode & 0o777, 0o600)
        key_bytes = keyfile.read_bytes()
        with self.assertRaises(FileExistsError):
            self.vault.generate_keyfile(keyfile)
        self.assertEqual(keyfile.read_bytes(), key_bytes)
        other_path = self.directory / "other.kdbx"
        other = Vault(ENGINE)
        try:
            other.create(other_path, "", keyfile=str(keyfile), no_password=True)
            self.assertFalse(other.settings()["password_key"])
            self.assertTrue(other.settings()["file_key"])
            other.save_entry(other.snapshot.root, "Imported", "source user", "", "", "source-test-password")
        finally:
            other.lock()
        source_bytes = other_path.read_bytes()
        self.vault.merge(other_path, keyfile=str(keyfile), no_password=True)
        self.assertEqual(other_path.read_bytes(), source_bytes)
        self.assertTrue(any(entry.title == "Imported" for entry in self.vault.snapshot.entries))
        before = self.path.read_bytes()
        for format in ["xml", "csv", "html"]:
            destination = self.directory / ("export." + format)
            self.vault.export_database(destination, format)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertIn(b"weak-test-value", destination.read_bytes())
            with self.assertRaises(FileExistsError):
                self.vault.export_database(destination, format)
            self.vault.export_database(destination, format, overwrite=True)
        self.assertEqual(before, self.path.read_bytes())
        with self.assertRaises(VaultError):
            self.vault.export_database(self.path, overwrite=True)
        self.assertEqual(before, self.path.read_bytes())
        self.assertFalse(list(self.directory.glob(".keyslot-output-*")))

    def test_large_attachment_above_former_40_mib_limit(self):
        import hashlib
        root = self.vault.snapshot.root
        self.vault.save_entry(root, "Large Attachment", "", "", "", "test password")
        source = self.directory / "large.bin"
        with source.open("wb") as stream:
            stream.truncate(42 * 1024 * 1024)
        self.vault.import_attachment(self.vault.snapshot.entries[0], source)
        output = self.directory / "roundtrip.bin"
        self.vault.export_attachment(self.vault.snapshot.entries[0], source.name, output)
        self.assertEqual(output.stat().st_size, source.stat().st_size)
        with source.open("rb") as a, output.open("rb") as b:
            self.assertEqual(hashlib.file_digest(a, "sha256").digest(), hashlib.file_digest(b, "sha256").digest())


if __name__ == "__main__":
    unittest.main()
