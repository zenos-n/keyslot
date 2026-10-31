"""Native Secret Service boundaries, upstream item conventions and independent wire crypto."""
import base64
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import unittest

from keyslot.backend import VaultError
from keyslot.core_backend import Vault, EngineError
from keyslot.secret_cipher import SecretCipher, encoded, decoded

ENGINE = os.environ.get("KEYSLOT_ENGINE") or shutil.which("keyslot-engine")
OPENSSL = os.environ.get("KEYSLOT_TEST_OPENSSL") or shutil.which("openssl")
if os.environ.get("KEYSLOT_REQUIRE_ENGINE") and not ENGINE:
    raise RuntimeError("The native engine is required for Secret Service release checks.")


@unittest.skipUnless(ENGINE, "native engine required")
class SecretItems(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="keyslot-secrets-native-")
        self.directory = Path(self.temporary.name)
        self.path = self.directory / "fixture.kdbx"
        self.vault = Vault(ENGINE)
        self.vault.create(self.path, "public fixture master")
        self.vault.add_group(self.vault.snapshot.root, "Exposed")
        self.group = next(g.uuid for g in self.vault.snapshot.groups if g.name == "Exposed")
        self.vault.save_entry(self.group, "Public Entry", "fixture-user", "https://example.org", "", "fixture secret")
        self.entry = self.vault.snapshot.entries[0].uuid
        self.vault.save_entry(self.vault.snapshot.root, "Hidden Entry", "hidden-user", "", "", "hidden fixture secret")
        self.hidden = next(e.uuid for e in self.vault.snapshot.entries if e.title == "Hidden Entry")
        self.vault.save_secret_settings(self.group)
        self.peer = ":1.42"
        self.configure()

    def tearDown(self):
        self.vault.lock()
        self.temporary.cleanup()

    def configure(self, confirm=True, instance="fixture-provider"):
        self.vault.secret_request("configure", confirm_access=confirm, instance=instance)

    def request(self, operation, peer=None, **values):
        return self.vault.secret_request(operation, peer=peer or self.peer, **values)

    def authorize(self, entries=None, remember=False):
        pending = self.request("prepare", kind="authorize", entries=entries or [self.entry])
        return self.request("finish", token=pending["token"], approved=True, remember=remember)

    def get(self, entry=None, peer=None, skip_locked=False):
        return self.request("get", peer=peer, entries=[entry or self.entry], skip_locked=skip_locked)["secrets"]

    def live(self, identifier=None):
        return next(entry for entry in self.vault.snapshot.entries if entry.uuid == (identifier or self.entry))

    def test_exposed_group_roundtrip_and_protected_metadata_do_not_leak(self):
        self.vault.set_attribute(self.live(), "Private", "protected fixture token", True)
        self.vault.set_attribute(self.live(), "Public", "public fixture", False)
        self.vault.lock()
        self.vault.unlock(self.path, "public fixture master")
        self.configure()
        self.assertEqual(self.vault.snapshot.secret_group, self.group)
        self.assertEqual(self.vault.secret_settings()["group"], self.group)
        info = self.request("info", entry=self.entry)
        self.assertTrue(info["locked"])
        self.assertNotIn("Password", info["attributes"])
        self.assertNotIn("Private", info["attributes"])
        self.assertEqual(info["attributes"]["Public"], "public fixture")
        self.assertEqual(self.request("info")["items"], [self.entry])
        with self.assertRaises(EngineError):
            self.request("info", entry=self.hidden)

    def test_search_is_literal_bounded_and_cannot_probe_secrets_or_resolved_references(self):
        self.vault.set_attribute(self.live(), "Private", "protected fixture token", True)
        reference = "{REF:P@I:" + self.hidden.replace("-", "") + "}"
        self.vault.save_entry(self.group, "Public Entry", "fixture-user", reference, "", entry=self.live())
        self.assertEqual(self.request("search", attributes={})["locked"], [self.entry])
        for values in ({"Password": "fixture secret"}, {"Private": "protected fixture token"},
                       {"URL": "hidden fixture secret"}, {"Title": "Public.*"}):
            self.assertEqual(self.request("search", attributes=values)["all"], [])
        self.assertEqual(self.request("search", attributes={"URL": reference})["all"], [self.entry])
        self.assertEqual(self.request("info", entry=self.entry)["attributes"]["URL"], reference)
        self.assertEqual(self.request("search", attributes={"Uuid": self.entry.replace("-", "")})["all"], [self.entry])
        self.assertEqual(self.request("search", attributes={"Uuid": self.hidden.replace("-", "")})["all"], [])

    def test_one_shot_persistent_and_peer_bound_authorization(self):
        with self.assertRaises(EngineError):
            self.get()
        self.authorize()
        self.assertEqual(decoded(self.get()[0]["value"]), b"fixture secret")
        with self.assertRaises(EngineError):
            self.get()
        self.authorize(remember=True)
        self.assertEqual(decoded(self.get()[0]["value"]), b"fixture secret")
        self.assertEqual(decoded(self.get()[0]["value"]), b"fixture secret")
        with self.assertRaises(EngineError):
            self.get(peer=":1.43")
        self.request("drop-peer")
        with self.assertRaises(EngineError):
            self.get()

    def test_approval_is_single_use_peer_and_file_bound_and_cancel_does_not_grant(self):
        pending = self.request("prepare", kind="authorize", entries=[self.entry])
        with self.assertRaises(EngineError):
            self.request("finish", peer=":1.43", token=pending["token"], approved=True)
        self.request("finish", token=pending["token"], approved=False)
        for operation in (lambda: self.get(), lambda: self.request("finish", token=pending["token"], approved=True)):
            with self.assertRaises(EngineError):
                operation()
        pending = self.request("prepare", kind="authorize", entries=[self.entry])
        self.vault.set_attribute(self.live(), "Public", "changed", False)
        with self.assertRaises(EngineError):
            self.request("finish", token=pending["token"], approved=True)

    def test_provider_change_exposure_change_and_lock_revoke_grants(self):
        self.authorize(remember=True)
        self.configure(instance="new-provider")
        with self.assertRaises(EngineError):
            self.get()
        self.authorize(remember=True)
        self.vault.save_secret_settings("")
        self.assertEqual(self.vault.snapshot.secret_group, "")
        self.vault.save_secret_settings(self.group)
        with self.assertRaises(EngineError):
            self.get()
        self.authorize(remember=True)
        self.vault.lock()
        self.vault.unlock(self.path, "public fixture master")
        self.configure()
        with self.assertRaises(EngineError):
            self.get()
        self.configure(confirm=False)
        self.assertEqual(decoded(self.get()[0]["value"]), b"fixture secret")
        self.configure(confirm=True)
        with self.assertRaises(EngineError):
            self.get()

    def test_totp_and_password_have_independent_one_shot_reads(self):
        self.vault.set_totp(self.live(), "otpauth://totp/Fixture?secret=JBSWY3DPEHPK3PXP&issuer=Fixture")
        self.assertNotIn("TOTP", self.request("info", entry=self.entry, include_totp=True)["attributes"])
        self.authorize()
        self.assertFalse(self.request("info", entry=self.entry)["locked"])
        self.assertRegex(self.request("info", entry=self.entry, include_totp=True)["attributes"]["TOTP"], r"^\d{6}$")
        self.assertNotIn("TOTP", self.request("info", entry=self.entry, include_totp=True)["attributes"])
        self.assertEqual(decoded(self.get()[0]["value"]), b"fixture secret")
        with self.assertRaises(EngineError):
            self.get()
        self.authorize()
        self.get()
        self.assertRegex(self.request("info", entry=self.entry, include_totp=True)["attributes"]["TOTP"], r"^\d{6}$")
        self.assertNotIn("TOTP", self.request("info", entry=self.entry, include_totp=True)["attributes"])
        self.authorize(remember=True)
        for _ in range(2):
            self.assertRegex(self.request("info", entry=self.entry, include_totp=True)["attributes"]["TOTP"], r"^\d{6}$")
            self.get()

    def create(self, value, content_type="text/plain", replace=False, attributes=None, label="Created"):
        pending = self.request("prepare", kind="create", label=label, attributes=attributes or {"xdg:schema": "public.fixture"},
                               replace=replace, value=encoded(value), content_type=content_type)
        result = self.request("finish", token=pending["token"], approved=True)
        return result["entry"]

    def test_text_binary_and_charset_storage_use_upstream_conventions(self):
        text = self.create(b"fixture text\x00with nul")
        self.assertEqual(self.vault.attribute(self.live(text)), "fixture text\x00with nul")
        binary = self.create(b"\x00\xff\x80binary fixture", "application/octet-stream", attributes={"kind": "binary"})
        self.assertIn("FDO_SECRETS_DATA", self.live(binary).attachments)
        secret = self.get(binary)[0]
        self.assertEqual(decoded(secret["value"]), b"\x00\xff\x80binary fixture")
        self.assertEqual(secret["content_type"], "application/octet-stream")
        latin = self.create(b"caf\xe9", "text/plain; charset=ISO-8859-1", attributes={"kind": "latin"})
        self.assertEqual(decoded(self.get(latin)[0]["value"]), "café".encode())

    def test_replace_uses_reviewed_item_preserves_history_and_does_not_touch_other_entries(self):
        self.vault.set_attribute(self.live(), "service", "fixture", False)
        pending = self.request("prepare", kind="create", label="Updated Label", attributes={"service": "fixture"},
                               replace=True, value=encoded(b"updated fixture"), content_type="text/plain")
        self.assertEqual(pending["items"][0]["entry"], self.entry)
        self.assertEqual(pending["items"][0]["new_label"], "Updated Label")
        result = self.request("finish", token=pending["token"], approved=True)
        self.assertEqual(result["entry"], self.entry)
        self.assertEqual(self.vault.attribute(self.live()), "updated fixture")
        self.assertTrue(self.vault.history(self.live()))
        self.assertEqual(self.vault.attribute(self.live(self.hidden)), "hidden fixture secret")

    def test_mutation_requires_authorization_and_cannot_write_protected_lookup_fields(self):
        before = self.path.read_bytes()
        with self.assertRaises(EngineError):
            self.request("mutate", kind="set-secret", entry=self.entry, value=encoded(b"new"), content_type="text/plain")
        self.authorize(remember=True)
        for attrs in ({"Password": "leak"}, {"Uuid": "new-id"}, {"Path": "/outside"}):
            with self.assertRaises(EngineError):
                self.request("mutate", kind="set-attributes", entry=self.entry, attributes=attrs)
        self.assertEqual(self.path.read_bytes(), before)
        self.request("mutate", kind="set-label", entry=self.entry, label="Renamed")
        self.assertEqual(self.live().title, "Renamed")
        self.request("mutate", kind="set-secret", entry=self.entry, value=encoded(b"new fixture"), content_type="text/plain")
        self.assertEqual(self.vault.attribute(self.live()), "new fixture")

    def test_reference_injection_and_outside_scope_mutation_fail_without_changing_the_file(self):
        self.authorize(remember=True)
        before = self.path.read_bytes()
        reference = ("{REF:P@I:" + self.hidden.replace("-", "") + "}").encode()
        for operation in (
            lambda: self.request("mutate", kind="set-secret", entry=self.entry, value=encoded(reference), content_type="text/plain"),
            lambda: self.request("mutate", kind="set-label", entry=self.hidden, label="Escaped"),
            lambda: self.request("prepare", kind="create", label="Bad", attributes={"Password": "forbidden"},
                                 value=encoded(b"fixture"), content_type="text/plain", replace=False)):
            with self.assertRaises(EngineError):
                operation()
        self.assertEqual(self.path.read_bytes(), before)

    def test_delete_is_reviewed_and_uses_the_vault_recycle_policy(self):
        pending = self.request("prepare", kind="delete", entry=self.entry)
        before = self.path.read_bytes()
        self.request("finish", token=pending["token"], approved=False)
        self.assertEqual(self.path.read_bytes(), before)
        pending = self.request("prepare", kind="delete", entry=self.entry)
        self.request("finish", token=pending["token"], approved=True)
        self.assertTrue(self.live().recycled)
        with self.assertRaises(EngineError):
            self.request("info", entry=self.entry)
        self.vault.save_settings(recycle_bin=False)
        created = self.create(b"public delete fixture")
        pending = self.request("prepare", kind="delete", entry=created)
        self.request("finish", token=pending["token"], approved=True)
        self.assertNotIn(created, [entry.uuid for entry in self.vault.snapshot.entries])

    def test_client_creation_path_stays_below_exposed_root_and_label_review_is_effective(self):
        created = self.create(b"fixture", attributes={"Path": "/../Outside/Item", "Title": "Effective Label"}, label="Requested Label")
        entry = self.live(created)
        self.assertEqual(entry.title, "Effective Label")
        self.assertTrue(entry.group_path.startswith("/Passwords/Exposed/"), entry.group_path)
        self.assertEqual(self.request("info", entry=created)["attributes"]["Path"], "/../Outside/Effective Label")


@unittest.skipUnless(ENGINE, "native engine required")
class NativeSessions(unittest.TestCase):
    def setUp(self):
        self.cipher = SecretCipher()
        self.peer = ":1.71"

    def tearDown(self):
        self.cipher.close()

    def test_plain_session_ownership_closure_and_native_session_quota(self):
        session = self.cipher.open(self.peer, "plain", "")
        self.assertTrue(session["plain"])
        values = dict(parameters="", value=encoded(b"public plain fixture"), content_type="application/octet-stream")
        result = self.cipher.call("encode", self.peer, session["session"], session["identity"], **values)
        self.assertEqual(result, values)
        with self.assertRaises(EngineError):
            self.cipher.call("decode", ":1.72", session["session"], session["identity"], **values)
        self.cipher.call("close", self.peer, session["session"], session["identity"])
        with self.assertRaises(EngineError):
            self.cipher.call("encode", self.peer, session["session"], session["identity"], **values)
        for _ in range(16):
            self.cipher.open(self.peer, "plain", "")
        with self.assertRaises(EngineError):
            self.cipher.open(self.peer, "plain", "")
        self.cipher.drop_peer(self.peer)
        self.assertTrue(self.cipher.open(self.peer, "plain", "")["plain"])

    @unittest.skipUnless(OPENSSL, "OpenSSL required for independent AES verification")
    def test_dh_hkdf_aes_matches_independent_client_and_bad_padding_is_rejected(self):
        prime = int("""FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF""", 16)
        private = secrets.randbits(256)
        public = pow(2, private, prime).to_bytes(128, "big")
        session = self.cipher.open(self.peer, "dh-ietf1024-sha256-aes128-cbc-pkcs7", encoded(public))
        remote = int.from_bytes(decoded(session["output"]), "big")
        self.assertTrue(1 < remote < prime - 1)
        shared = pow(remote, private, prime).to_bytes(128, "big")
        prk = hmac.digest(bytes(32), shared, "sha256")
        key = hmac.digest(prk, b"\x01", "sha256")[:16]
        payload = b"independent public AES fixture\x00\xff"
        encrypted = self.cipher.call("encode", self.peer, session["session"], session["identity"],
                                    parameters="", value=encoded(payload), content_type="application/octet-stream")
        iv, ciphertext = decoded(encrypted["parameters"]), decoded(encrypted["value"])
        plain = subprocess.run([OPENSSL, "enc", "-aes-128-cbc", "-d", "-K", key.hex(), "-iv", iv.hex()],
                               input=ciphertext, capture_output=True, check=True).stdout
        self.assertEqual(plain, payload)
        incoming_iv = secrets.token_bytes(16)
        incoming = subprocess.run([OPENSSL, "enc", "-aes-128-cbc", "-K", key.hex(), "-iv", incoming_iv.hex()],
                                  input=payload, capture_output=True, check=True).stdout
        result = self.cipher.call("decode", self.peer, session["session"], session["identity"],
            parameters=encoded(incoming_iv), value=encoded(incoming), content_type="application/octet-stream")
        self.assertEqual(decoded(result["value"]), payload)
        # Alter the penultimate block so the final PKCS7 padding byte is deterministically invalid.
        invalid = bytearray(incoming)
        invalid[-17] ^= 0x80
        with self.assertRaises(EngineError):
            self.cipher.call("decode", self.peer, session["session"], session["identity"],
                parameters=encoded(incoming_iv), value=encoded(invalid), content_type="application/octet-stream")

    def test_malformed_sessions_and_plain_parameters_are_rejected(self):
        for algorithm, value in (("unknown", ""), ("plain", "nonempty"),
                                 ("dh-ietf1024-sha256-aes128-cbc-pkcs7", "???")):
            with self.assertRaises(EngineError):
                self.cipher.open(self.peer, algorithm, value)
        session = self.cipher.open(self.peer, "plain", "")
        with self.assertRaises(EngineError):
            self.cipher.call("decode", self.peer, session["session"], session["identity"],
                parameters=encoded(b"not-empty"), value=encoded(b"fixture"), content_type="text/plain")
