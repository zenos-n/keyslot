"""Native upstream passkeys, independently verified with OpenSSL and disposable vaults."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from keyslot.core_backend import Vault, EngineError

ENGINE = shutil.which(os.environ.get("KEYSLOT_ENGINE", "keyslot-engine"))
OPENSSL = shutil.which(os.environ.get("KEYSLOT_TEST_OPENSSL", "openssl"))
if os.environ.get("KEYSLOT_REQUIRE_ENGINE") == "1" and not (ENGINE and OPENSSL):
    raise RuntimeError("Native passkey tests require the helper and independent OpenSSL verifier.")


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def decode(data):
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def creation(algorithm=-7):
    return {"challenge": b64(b"public registration challenge32!"), "rp": {"id": "example.org", "name": "Example"},
            "user": {"id": b64(b"public-user-id"), "name": "alice", "displayName": "Alice"},
            "pubKeyCredParams": [{"type": "public-key", "alg": algorithm}], "attestation": "none",
            "excludeCredentials": [], "authenticatorSelection": {"residentKey": "preferred", "userVerification": "required"}}


def assertion(identifier=None):
    return {"challenge": b64(b"public authentication challenge!"), "rpId": "example.org", "userVerification": "required",
            "allowCredentials": [] if identifier is None else [{"type": "public-key", "id": identifier}]}


@unittest.skipUnless(ENGINE and OPENSSL, "Build the passkey helper and supply OpenSSL")
class NativePasskeyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.vault = Vault(ENGINE)
        self.addCleanup(self.vault.lock)
        self.path = self.root / "passkeys.kdbx"
        self.master = "public passkey fixture master"
        self.vault.create(self.path, self.master)
        self.key = base64.b64encode(bytes(range(32))).decode()
        self.vault.browser_associate("browser", self.key)

    def prepare(self, mode="register", options=None, origin="https://login.example.org", **changes):
        return self.vault.browser_prepare_passkey("browser", self.key, mode,
            options if options is not None else creation(), origin, **changes)

    def register(self, algorithm=-7, **choices):
        review = self.prepare(options=creation(algorithm))
        self.assertNotIn("PRIVATE KEY", json.dumps(review))
        return self.vault.browser_finish_passkey(review["token"], approved=True, **choices)

    def test_registration_and_assertion_signatures_match_independent_ec_and_rsa_verification(self):
        for algorithm in (-7, -257):
            with self.subTest(algorithm=algorithm):
                registered = self.register(algorithm)
                self.assertEqual(registered["response"]["publicKeyAlgorithm"], algorithm)
                self.assertEqual(len(decode(registered["id"])), 32)
                client = json.loads(decode(registered["response"]["clientDataJSON"]))
                self.assertEqual(client["type"], "webauthn.create")
                self.assertEqual(client["challenge"], creation()["challenge"])
                self.assertEqual(client["origin"], "https://login.example.org")
                public_der = self.root / "public.der"
                public_pem = self.root / "public.pem"
                public_der.write_bytes(decode(registered["response"]["publicKey"]))
                result = subprocess.run([OPENSSL, "pkey", "-pubin", "-inform", "DER", "-in", str(public_der),
                                         "-out", str(public_pem)], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                review = self.prepare("get", assertion(registered["id"]))
                self.assertEqual(len(review["entries"]), 1)
                before = self.path.read_bytes()
                signed = self.vault.browser_finish_passkey(review["token"], approved=True, entry=review["entries"][0]["uuid"])
                self.assertEqual(self.path.read_bytes(), before)
                self.assertEqual(signed["id"], registered["id"])
                response = signed["response"]
                auth_data = decode(response["authenticatorData"])
                self.assertEqual(auth_data[:32], hashlib.sha256(b"example.org").digest())
                self.assertEqual(auth_data[32] & 5, 5)
                client_data = decode(response["clientDataJSON"])
                self.assertEqual(json.loads(client_data)["challenge"], assertion()["challenge"])
                self.assertEqual(response["userHandle"], creation()["user"]["id"])
                message, signature = self.root / "signed.bin", self.root / "signature.bin"
                message.write_bytes(auth_data + hashlib.sha256(client_data).digest())
                signature.write_bytes(decode(response["signature"]))
                command = [OPENSSL, "dgst", "-sha256", "-verify", str(public_pem), "-signature", str(signature), str(message)]
                self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
                message.write_bytes(message.read_bytes() + b"tampered")
                self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_consent_replay_protected_metadata_and_explicit_replacement(self):
        before = self.path.read_bytes()
        review = self.prepare()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.vault.browser_finish_passkey(review["token"]), {"errorCode": 22})
        self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaises(EngineError):
            self.vault.browser_finish_passkey(review["token"], approved=True)
        registered = self.register()
        entry = self.vault.snapshot.entries[0]
        self.assertTrue(entry.passkey)
        self.assertEqual(entry.history_count, 0)
        self.assertIn("KeePassXC-Browser Passkeys", entry.group_path)
        for name in ("KPEX_PASSKEY_CREDENTIAL_ID", "KPEX_PASSKEY_PRIVATE_KEY_PEM", "KPEX_PASSKEY_USER_HANDLE"):
            self.assertTrue(self.vault.attribute_info(entry, name)["protected"])
        self.assertEqual(self.vault.attribute(entry, "KPEX_PASSKEY_CREDENTIAL_ID"), registered["id"])
        review = self.prepare()
        before = self.path.read_bytes()
        with self.assertRaises(EngineError):
            self.vault.browser_finish_passkey(review["token"], approved=True, entry=entry.uuid.replace("-", ""))
        self.assertEqual(self.path.read_bytes(), before)
        review = self.prepare()
        replaced = self.vault.browser_finish_passkey(review["token"], approved=True, entry=entry.uuid.replace("-", ""), replace=True)
        self.assertNotEqual(registered["id"], replaced["id"])
        self.assertEqual(len(self.vault.snapshot.entries), 1)
        self.assertEqual(self.vault.snapshot.entries[0].history_count, 1)
        self.vault.lock()
        self.vault.unlock(self.path, self.master)
        self.assertEqual(len(self.prepare("get", assertion(replaced["id"]))["entries"]), 1)
        self.assertEqual(self.prepare("get", assertion(registered["id"])), {"error_code": 15})
        self.vault.save_entry(self.vault.snapshot.root, "Existing login", "bob", "https://example.org", "Keep notes", "Keep password")
        login = next(e for e in self.vault.snapshot.entries if e.title == "Existing login")
        self.register(entry=login.uuid.replace("-", ""))
        attached = next(e for e in self.vault.snapshot.entries if e.uuid == login.uuid)
        self.assertEqual((attached.username, attached.url, attached.notes), ("bob", "https://example.org", "Keep notes"))
        self.assertEqual(self.vault.attribute(attached), "Keep password")
        self.assertEqual(self.vault.attribute(attached, "KPEX_PASSKEY_USERNAME"), "alice")

    def test_origin_rp_challenge_and_credential_restrictions(self):
        before = self.path.read_bytes()
        for options, origin, expected in [(creation(), "http://example.org", 25),
                ({**creation(), "rp": {"id": "other.org", "name": "Other"}}, "https://example.org", 28),
                ({**creation(), "challenge": "short"}, "https://example.org", 32),
                ({**creation(), "user": {"id": "", "name": "alice"}}, "https://example.org", 33)]:
            self.assertEqual(self.prepare(options=options, origin=origin), {"error_code": expected})
        self.assertEqual(self.path.read_bytes(), before)
        registered = self.register()
        options = creation()
        options["excludeCredentials"] = [{"type": "public-key", "id": registered["id"]}]
        self.assertEqual(self.prepare(options=options), {"error_code": 21})
        self.assertEqual(self.prepare("get", assertion(b64(b"not-this-credential"))), {"error_code": 15})
        review = self.prepare("get", assertion())
        with self.assertRaises(EngineError):
            self.vault.browser_finish_passkey(review["token"], approved=True, entry="1" * 32)
        entry = self.vault.snapshot.entries[0]
        self.vault.delete_entry(entry)
        self.assertEqual(self.prepare("get", assertion()), {"error_code": 15})

    def test_stale_expired_bounded_requests_and_external_revocation_cannot_complete(self):
        review = self.prepare()
        self.vault.refresh()
        with self.assertRaises(EngineError):
            self.vault.browser_finish_passkey(review["token"], approved=True)
        requests = [self.prepare() for _ in range(128)]
        with self.assertRaises(EngineError) as caught:
            self.prepare()
        self.assertEqual(caught.exception.code, "busy")
        self.vault.browser_finish_passkey(requests[0]["token"])
        expired = self.prepare(options={**creation(), "timeout": 1000})
        self.assertEqual(expired["timeout_ms"], 1000)
        time.sleep(1.1)
        with self.assertRaises(EngineError) as caught:
            self.vault.browser_finish_passkey(expired["token"], approved=True)
        self.assertEqual(caught.exception.code, "expired")
        review = self.prepare()
        other = Vault(ENGINE)
        self.addCleanup(other.lock)
        other.unlock(self.path, self.master)
        other.browser_revoke("browser")
        external = self.path.read_bytes()
        with self.assertRaises(EngineError):
            self.vault.browser_finish_passkey(review["token"], approved=True)
        self.assertEqual(self.path.read_bytes(), external)
