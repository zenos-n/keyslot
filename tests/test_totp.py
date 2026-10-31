"""Native TOTP RFC vectors, storage/retention, safe setup and independently decoded QR output."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from urllib.parse import parse_qs, urlparse

from keyslot.backend import VaultError
from keyslot.core_backend import Vault, EngineError

ENGINE = os.environ.get("KEYSLOT_ENGINE") or shutil.which("keyslot-engine")
KEY = "JBSWY3DPEHPK3PXP"


def reference(key, at, period=30, digits=6, algorithm="sha1", steam=False):
    digest = hmac.new(base64.b32decode(key + '=' * (-len(key) % 8)), struct.pack('>Q', at // period), algorithm).digest()
    offset = digest[-1] & 15
    value = int.from_bytes(digest[offset:offset + 4], 'big') & 0x7fffffff
    if not steam:
        return str(value % 10 ** digits).zfill(digits)
    alphabet = "23456789BCDFGHJKMNPQRTVWXY"
    result = ""
    for _ in range(5):
        result += alphabet[value % len(alphabet)]
        value //= len(alphabet)
    return result


@unittest.skipUnless(ENGINE, "native engine required")
class Totp(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="keyslot-totp-")
        self.directory = Path(self.temporary.name)
        self.path = self.directory / "TOTP.kdbx"
        self.vault = Vault(ENGINE)
        self.vault.create(self.path, "public fixture master")
        self.vault.save_entry(self.vault.snapshot.root, "Example <Account> ☃", "fixture@example.org", "https://example.org",
                              "public notes", "public password")

    def tearDown(self):
        self.vault.lock()
        self.temporary.cleanup()

    def entry(self):
        return self.vault.snapshot.entries[0]

    def config(self):
        return self.vault.totp_config(self.entry())

    def save(self, **settings):
        return self.vault.save_totp(self.entry(), self.config()["revision"], **settings)

    def test_standard_secret_sanitization_and_secret_free_samples(self):
        self.assertFalse(self.config()["configured"])
        self.save(key="  jbsw y3dp ehpk 3pxp==  ")
        config = self.config()
        self.assertTrue(config["valid"])
        self.assertEqual((config["key"], config["mode"], config["period"], config["digits"]), (KEY, "standard", 30, 6))
        before = self.path.read_bytes()
        result = self.vault.totp_sample(self.entry(), 1234567890)
        self.assertEqual(result["code"], reference(KEY, 1234567890))
        self.assertNotIn(KEY, json.dumps(result))
        self.assertNotIn("otpauth", json.dumps(result))
        self.assertEqual(self.path.read_bytes(), before)
        self.vault.lock()
        self.vault.unlock(self.path, "public fixture master")
        self.assertEqual(self.config()["key"], KEY)

    def test_rfc6238_all_six_times_and_three_hashes(self):
        # RFC 6238 Appendix B: https://www.rfc-editor.org/rfc/rfc6238#appendix-B
        times = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]
        values = {
            "SHA-1": (b"12345678901234567890", ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"]),
            "SHA-256": (b"12345678901234567890123456789012", ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"]),
            "SHA-512": (b"1234567890123456789012345678901234567890123456789012345678901234", ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"]),
        }
        for algorithm, (secret, codes) in values.items():
            self.save(key=base64.b32encode(secret).decode(), mode="custom", digits=8, algorithm=algorithm)
            for at, expected in zip(times, codes):
                with self.subTest(algorithm=algorithm, at=at):
                    self.assertEqual(self.vault.totp_sample(self.entry(), at)["code"], expected)

    def test_clock_edges_custom_period_and_ten_digit_integer_modulus(self):
        self.save(key=KEY, mode="custom", digits=10, period=45, algorithm="SHA-512")
        for at in (1, 44, 45, 46, 89, 90, 1234567890, 20000000000):
            sample = self.vault.totp_sample(self.entry(), at)
            self.assertEqual(sample["code"], reference(KEY, at, 45, 10, "sha512"))
            self.assertEqual(sample["remaining_ms"], (45 - at % 45) * 1000)
            self.assertEqual(sample["period"], 45)
        self.save(key=base64.b32encode(b"12345678901234567890").decode(), mode="custom", digits=10)
        self.assertEqual(self.vault.totp_sample(self.entry(), 1234567890)["code"],
                         reference(base64.b32encode(b"12345678901234567890").decode(), 1234567890, digits=10))

    def test_steam_codes_and_setup_roundtrip(self):
        self.save(key=KEY, mode="steam")
        config = self.config()
        self.assertEqual((config["mode"], config["digits"], config["period"], config["algorithm"]), ("steam", 5, 30, "SHA-1"))
        for at in (1, 29, 30, 59, 60, 1234567890):
            self.assertEqual(self.vault.totp_sample(self.entry(), at)["code"], reference(KEY, at, steam=True))
        self.assertIn("encoder=steam", config["uri"])
        self.save(uri=config["uri"])
        self.assertEqual(self.config()["mode"], "steam")

    def test_setup_link_custom_settings_and_current_copy_is_not_a_cached_sample(self):
        self.save(uri=f"otpauth://totp/Example?secret={KEY}&period=60&digits=8&algorithm=SHA256")
        self.assertEqual((self.config()["period"], self.config()["digits"], self.config()["algorithm"]), (60, 8, "SHA-256"))
        self.vault.totp_sample(self.entry(), 59)
        before = int(time.time())
        result = self.vault.copy_totp(self.entry())
        after = int(time.time())
        self.assertIn(result, {reference(KEY, at, 60, 8, "sha256") for at in (before, after)})
        combined = self.vault.copy_totp(self.entry(), combined=True)
        self.assertTrue(combined.startswith("public password"))
        self.assertIn(combined[len("public password"):], {reference(KEY, at, 60, 8, "sha256") for at in (before, int(time.time()))})

    def test_combined_copy_resolves_password_references(self):
        original = self.entry()
        identifier = original.uuid.replace("-", "")
        self.vault.save_entry(original.group, "Reference", "user", "", "", "{REF:P@I:" + identifier + "}")
        entry = next(entry for entry in self.vault.snapshot.entries if entry.title == "Reference")
        revision = self.vault.totp_config(entry)["revision"]
        self.vault.save_totp(entry, revision, key=KEY)
        entry = next(entry for entry in self.vault.snapshot.entries if entry.title == "Reference")
        self.assertTrue(self.vault.copy_totp(entry, True).startswith("public password"))

    def test_invalid_structured_keys_settings_and_timestamps_never_write(self):
        for key in ("", "!!!!", "ABC!DEF", "A☃BC", "1234"):
            before = self.path.read_bytes()
            with self.assertRaises(EngineError):
                self.save(key=key)
            self.assertEqual(self.path.read_bytes(), before)
        for options in ({"digits":0}, {"digits":11}, {"period":0}, {"period":True}, {"digits":1.5},
                        {"algorithm":"MD5"}, {"mode":"unknown"}, {"period":4294967296}):
            before = self.path.read_bytes()
            with self.assertRaises(EngineError):
                self.save(key=KEY, **({"mode": "custom"} | options))
            self.assertEqual(self.path.read_bytes(), before)
        self.save(key=KEY)
        for at in (True, 0, -1, .5, "30", 9007199254741):
            with self.assertRaises(EngineError):
                self.vault.totp_sample(self.entry(), at)

    def test_invalid_uris_and_old_setter_are_bounded(self):
        for uri in ("", "https://example.org", f"otpauth://hotp/X?secret={KEY}",
                    "otpauth://totp/X?secret=", "otpauth://totp/X?secret=!!!!"):
            with self.assertRaises(EngineError):
                self.save(uri=uri)
        with self.assertRaises(EngineError):
            self.vault.set_totp(self.entry(), "otpauth://totp/X?secret=")
        for length in (11, 4294967295):
            self.vault.set_totp(self.entry(), f"otpauth://totp/X?secret={KEY}&digits={length}")
            self.assertEqual(self.config()["digits"], 10)
            self.assertEqual(len(self.vault.totp_sample(self.entry(), 59)["code"]), 10)
        self.assertTrue(self.vault.unlocked)

    def test_stale_setup_qr_uri_and_removal_reject_changed_review(self):
        self.save(key=KEY)
        revision = self.config()["revision"]
        self.vault.set_attribute(self.entry(), "Other", "value")
        for action in (lambda: self.vault.save_totp(self.entry(), revision, key=KEY, mode="steam"),
                       lambda: self.vault.remove_totp(self.entry(), revision),
                       lambda: self.vault.totp_settings(self.entry(), revision),
                       lambda: self.vault.export_totp_qr(self.entry(), revision, self.directory / "stale.svg")):
            with self.assertRaises(EngineError) as error:
                action()
            self.assertEqual(error.exception.code, "conflict")
        self.assertFalse((self.directory / "stale.svg").exists())

    def test_remove_preserves_history_and_unrelated_fields_with_saved_reopen(self):
        self.save(key=KEY)
        self.vault.remove_totp(self.entry(), self.config()["revision"])
        self.assertFalse(self.entry().totp)
        self.assertEqual(self.vault.attribute(self.entry()), "public password")
        entry = self.entry()
        history = self.vault.history(entry)
        self.assertTrue(any(KEY in self.vault.history_value(entry, old["index"], old["revision"], "properties", "One-Time Password Settings") for old in history))
        self.vault.lock()
        self.vault.unlock(self.path, "public fixture master")
        self.assertFalse(self.entry().totp)

    def test_legacy_format_preserved_and_custom_upgrade_is_native(self):
        self.vault.set_attribute(self.entry(), "TOTP Seed", KEY, True)
        self.vault.set_attribute(self.entry(), "TOTP Settings", "30;6", False)
        self.assertEqual(self.config()["key"], KEY)
        self.save(key=KEY, mode="steam")
        self.assertIn("TOTP Seed", self.entry().attributes)
        self.assertNotIn("otp", self.entry().attributes)
        self.save(key=KEY, mode="custom", algorithm="SHA-512", digits=8)
        self.assertNotIn("TOTP Seed", self.entry().attributes)
        self.assertIn("otp", self.entry().attributes)
        self.assertEqual(self.config()["algorithm"], "SHA-512")

    def test_keepass2_settings_are_removed_without_reappearing_on_reopen(self):
        self.vault.set_attribute(self.entry(), "TimeOtp-Secret-Base32", KEY, True)
        self.vault.set_attribute(self.entry(), "TimeOtp-Algorithm", "HMAC-SHA-256", False)
        self.vault.set_attribute(self.entry(), "TimeOtp-Length", "8", False)
        self.vault.set_attribute(self.entry(), "TimeOtp-Period", "60", False)
        self.assertTrue(self.entry().totp)
        self.vault.remove_totp(self.entry(), self.config()["revision"])
        self.vault.lock()
        self.vault.unlock(self.path, "public fixture master")
        self.assertFalse(self.entry().totp)
        self.assertFalse(any(key.startswith("TimeOtp-") for key in self.entry().attributes))

    def test_qr_png_decodes_to_the_exact_upstream_setup_link(self):
        decoder = os.environ.get("KEYSLOT_TEST_ZBAR")
        if not decoder:
            self.fail("An independent zbar decoder is required for the native QR check")
        self.save(key=KEY)
        before = self.path.read_bytes()
        value = self.vault.totp_qr(self.entry())
        self.assertFalse(value["custom"])
        png = value["png"]
        self.assertTrue(png.startswith(b'\x89PNG\r\n\x1a\n'))
        self.assertLessEqual(max(struct.unpack('!II', png[16:24])), 1024)
        image = self.directory / "QR.png"
        image.write_bytes(png)
        result = subprocess.run([decoder, '--quiet', '--raw', str(image)], capture_output=True, check=True, timeout=10)
        self.assertEqual(result.stdout.decode().strip(), self.vault.totp_settings(self.entry()))
        query = parse_qs(urlparse(result.stdout.decode().strip()).query)
        self.assertIn(KEY, query['secret'][0])
        self.assertEqual(self.path.read_bytes(), before)
        self.save(key=KEY, mode="steam")
        self.assertTrue(self.vault.totp_qr(self.entry())["custom"])

    def test_qr_svg_export_is_private_parseable_no_clobber_and_never_the_vault(self):
        self.save(key=KEY)
        target = self.directory / "QR.svg"
        self.vault.export_totp_qr(self.entry(), self.config()["revision"], target)
        self.assertTrue(ET.parse(target).getroot().tag.endswith('svg'))
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(KEY, target.read_text())
        old = target.read_bytes()
        with self.assertRaises(FileExistsError):
            self.vault.export_totp_qr(self.entry(), self.config()["revision"], target)
        with self.assertRaises(VaultError):
            self.vault.export_totp_qr(self.entry(), self.config()["revision"], self.path)
        self.assertEqual(target.read_bytes(), old)

    def test_readonly_failure_and_recycled_or_locked_entry_are_not_modified(self):
        self.save(key=KEY)
        self.path.chmod(0o400)
        before = self.path.read_bytes()
        with self.assertRaises(EngineError):
            self.vault.remove_totp(self.entry(), self.config()["revision"])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(self.entry().totp)
        self.path.chmod(0o600)
        self.vault.recycle_entries([self.entry()])
        with self.assertRaises(EngineError):
            self.vault.remove_totp(self.entry(), self.config()["revision"])
        entry = self.entry()
        self.vault.lock()
        with self.assertRaises(VaultError):
            self.vault.totp_sample(entry)
