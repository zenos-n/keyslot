import json
import os
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from keyslot.backend import VaultError
from keyslot.browser_hosts import NativeHosts, HOST


class NativeHostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.config = self.home / ".private/Config"
        self.data = self.home / ".private/Packages"
        self.proxy = self.root / "keepassxc-proxy"
        self.proxy.write_text("public nonexecuted proxy fixture")
        self.proxy.chmod(0o755)
        self.hosts = NativeHosts(self.proxy, self.home, self.config, self.data)

    def existing(self, data=b"public original browser registration\n"):
        path = self.hosts.paths["chromium"]
        path.parent.mkdir(parents=True)
        path.write_bytes(data)
        path.chmod(0o640)
        return path

    def test_native_manifests_match_official_extension_ids_and_private_paths(self):
        chrome = json.loads(self.hosts.manifest("chromium"))
        firefox = json.loads(self.hosts.manifest("firefox"))
        self.assertEqual(chrome["name"], HOST)
        self.assertEqual(chrome["type"], "stdio")
        self.assertEqual(chrome["path"], str(self.proxy))
        expected = ["chrome-extension://pdffhmdngciaglkoonimfcmckehcpafo/",
                    "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/"]
        if source := os.environ.get("KEYSLOT_UPSTREAM_TEST_DATA"):
            installer = Path(source).parents[1] / "src/browser/NativeMessageInstaller.cpp"
            expected = re.findall(r'"(chrome-extension://[a-p]+/)"', installer.read_text())
            self.assertEqual(len(expected), 2)
        self.assertEqual(chrome["allowed_origins"], expected)
        self.assertEqual(firefox["allowed_extensions"], ["keepassxc-browser@keepassxc.org"])
        self.assertTrue(self.hosts.paths["firefox"].is_relative_to(self.config / "mozilla"))
        standard = NativeHosts(self.proxy, self.home, self.home / ".config", self.data)
        self.assertTrue(standard.paths["firefox"].is_relative_to(self.home / ".mozilla"))

    def test_new_registration_is_private_and_removal_does_not_affect_other_browsers(self):
        self.hosts.enable("chromium", expected=None)
        self.hosts.enable("firefox", expected=None)
        self.assertTrue(self.hosts.status("chromium")["enabled"])
        self.assertEqual(self.hosts.paths["chromium"].stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.hosts.state_path.stat().st_mode & 0o777, 0o600)
        self.hosts.disable("chromium")
        self.assertFalse(self.hosts.paths["chromium"].exists())
        self.assertTrue(self.hosts.status("firefox")["enabled"])

    def test_replace_requires_confirmation_and_restores_exact_original_bytes_and_mode(self):
        path = self.existing()
        original = path.read_bytes()
        expected = self.hosts.status("chromium")["fingerprint"]
        with self.assertRaises(VaultError):
            self.hosts.enable("chromium", expected)
        self.assertEqual(path.read_bytes(), original)
        self.hosts.enable("chromium", expected, replace=True)
        self.assertEqual(json.loads(path.read_bytes())["path"], str(self.proxy))
        self.hosts.disable("chromium")
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_upgrade_refresh_changes_only_owned_registration_and_retains_original_backup(self):
        path = self.existing()
        original = path.read_bytes()
        self.hosts.enable("chromium", self.hosts.status("chromium")["fingerprint"], replace=True)
        new = self.root / "new-proxy"
        new.write_text("public upgraded nonexecuted proxy fixture")
        new.chmod(0o755)
        upgraded = NativeHosts(new, self.home, self.config, self.data)
        upgraded.refresh()
        self.assertEqual(json.loads(path.read_bytes())["path"], str(new))
        upgraded.disable("chromium")
        self.assertEqual(path.read_bytes(), original)

    def test_changed_registration_is_not_overwritten_or_removed(self):
        path = self.existing()
        reviewed = self.hosts.status("chromium")["fingerprint"]
        path.write_bytes(b"public intervening registration")
        with self.assertRaises(VaultError):
            self.hosts.enable("chromium", reviewed, replace=True)
        self.assertEqual(path.read_bytes(), b"public intervening registration")
        self.hosts.enable("chromium", self.hosts.status("chromium")["fingerprint"], replace=True)
        path.write_bytes(b"public externally changed registration")
        with self.assertRaises(VaultError):
            self.hosts.disable("chromium")
        self.hosts.refresh()
        self.assertEqual(path.read_bytes(), b"public externally changed registration")

    def test_managed_symlinks_and_corrupt_backup_records_are_preserved(self):
        path = self.hosts.paths["chromium"]
        path.parent.mkdir(parents=True)
        target = self.root / "system-registration"
        target.write_bytes(b"public system-managed registration")
        path.symlink_to(target)
        with self.assertRaises(VaultError):
            self.hosts.enable("chromium", None, replace=True)
        self.assertTrue(path.is_symlink())
        self.assertEqual(target.read_bytes(), b"public system-managed registration")
        path.unlink()
        self.hosts.state_path.parent.mkdir(parents=True)
        self.hosts.state_path.write_text('{"version":1,"browsers":{"chromium":{"installed":"bad"}}}')
        with self.assertRaises(VaultError):
            self.hosts.enable("chromium", None)
        self.assertFalse(path.exists())

    def test_failed_registration_write_rolls_back_state_and_keeps_original(self):
        path = self.existing()
        original = path.read_bytes()
        with patch.object(self.hosts, "_replace", side_effect=OSError("public write failure")):
            with self.assertRaises(OSError):
                self.hosts.enable("chromium", self.hosts.status("chromium")["fingerprint"], replace=True)
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(json.loads(self.hosts.state_path.read_text())["browsers"], {})

    def test_unmanaged_registration_is_never_removed(self):
        path = self.existing()
        original = path.read_bytes()
        self.hosts.disable("chromium")
        self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
