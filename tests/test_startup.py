import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from keyslot.startup import Startup, LoginKeyring
from types import SimpleNamespace


class StartupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.vault = self.root / "vault.kdbx"
        self.settings = Startup(self.root, '/a path/Keyslot "test"/bin/keyslot')

    def tearDown(self):
        self.temporary.cleanup()

    def test_remember_login_roundtrip_permissions_and_no_credentials(self):
        self.settings.save(True, True, self.vault)
        loaded = Startup(self.root)
        self.assertTrue(loaded.remember)
        self.assertTrue(loaded.login)
        self.assertEqual(loaded.vault, self.vault)
        self.assertEqual(set(json.loads(self.settings.path.read_text())), {"remember", "login", "vault", "background", "lock_minutes", "browser", "ssh", "ssh_socket", "ssh_provider", "autotype", "keeshare", "secret_service", "minimize_on_url"})

        self.assertEqual(self.settings.path.stat().st_mode & 0o777, 0o600)
        command = self.settings.autostart.read_text()
        self.assertIn('Exec="/a path/Keyslot \\\\"test\\\\"/bin/keyslot" --login', command)
        self.assertIn('Icon=keepassxc', command)
        self.assertNotIn(str(self.vault), command)

    def test_url_minimize_preference_roundtrip_and_type_validation(self):
        self.assertFalse(self.settings.minimize_on_url)
        self.settings.save(False, False, minimize_on_url=True)
        self.assertTrue(Startup(self.root).minimize_on_url)
        before = self.settings.path.read_bytes()
        for invalid in (1, "true", []):
            with self.assertRaises(ValueError):
                self.settings.save(False, False, minimize_on_url=invalid)
        self.assertEqual(self.settings.path.read_bytes(), before)
        self.settings.save(False, False, minimize_on_url=False)
        self.assertFalse(Startup(self.root).minimize_on_url)

    def test_turning_off_remember_forgets_path_and_disables_login(self):
        self.settings.save(True, True, self.vault)
        self.settings.save(False, True, self.vault)
        self.assertFalse(self.settings.autostart.exists())
        self.assertIsNone(self.settings.vault)
        self.assertFalse(self.settings.login)
        self.settings.opened(self.vault)
        self.assertIsNone(Startup(self.root).vault)

    def test_successful_open_updates_remembered_path(self):
        self.settings.save(True, False, self.vault)
        second = self.root / 'another.kdbx'
        self.settings.opened(second)
        self.assertEqual(Startup(self.root).vault, second)
        self.assertFalse(self.settings.autostart.exists())

    def test_background_mode_is_independent_and_survives_startup_changes(self):
        self.assertTrue(Startup(self.root).background)
        self.settings.save(False, False, background=True)
        self.assertTrue(Startup(self.root).background)
        self.settings.save(True, True, self.vault)
        self.assertTrue(Startup(self.root).background)
        self.settings.save(False, False)
        self.assertTrue(Startup(self.root).background)
        self.settings.save(False, False, background=False)
        self.assertFalse(Startup(self.root).background)

    def test_browser_opt_in_is_independent_and_survives_other_preference_changes(self):
        self.assertFalse(Startup(self.root).browser)
        self.settings.save(False, False, browser=True)
        self.assertTrue(Startup(self.root).browser)
        self.settings.save(True, True, self.vault, background=False, lock_minutes=37)
        self.assertTrue(Startup(self.root).browser)
        self.settings.save(True, True, self.vault, browser=False)
        loaded = Startup(self.root)
        self.assertFalse(loaded.browser)
        self.assertTrue(loaded.login)
        self.assertFalse(loaded.background)
        self.assertEqual(loaded.lock_minutes, 37)

    def test_unavailable_keyring_service_or_collections_fail_with_recoverable_error(self):
        for service in [None, SimpleNamespace(get_collections=lambda: None)]:
            keyring = object.__new__(LoginKeyring)
            keyring.secret = SimpleNamespace(Service=SimpleNamespace(get_sync=lambda *_args, service=service: service),
                                              ServiceFlags=SimpleNamespace(OPEN_SESSION=1, LOAD_COLLECTIONS=2))
            keyring._service = lambda _cancellable=None, service=service: service
            with self.subTest(service=service), self.assertRaisesRegex(ValueError, "keyring is unavailable"):
                keyring._collection()

    def test_inactivity_timeout_never_custom_and_validation(self):
        for minutes in [0, 1, 37, 1440]:
            self.settings.save(False, False, lock_minutes=minutes)
            self.assertEqual(Startup(self.root).lock_minutes, minutes)
        for value in [-1, 1441, True, "never"]:
            with self.assertRaises(ValueError):
                self.settings.save(False, False, lock_minutes=value)

    def test_invalid_settings_do_not_enable_login(self):
        self.settings.path.parent.mkdir()
        for value in ['broken', '[]', '{"remember": "yes", "login": true, "vault": "/secret"}',
                      '{"remember": true, "login": true, "vault": "relative.kdbx"}']:
            self.settings.path.write_text(value)
            loaded = Startup(self.root)
            self.assertFalse(loaded.login)
            self.assertIsNone(loaded.vault)

    def test_failed_config_write_restores_autostart_and_preferences(self):
        from keyslot.startup import _write
        self.settings.save(True, True, self.vault)
        before = self.settings.autostart.read_text()
        def fail_config(path, data):
            if path == self.settings.path:
                raise OSError('fixture write failure')
            _write(path, data)
        with patch('keyslot.startup._write', fail_config):
            with self.assertRaises(OSError):
                self.settings.save(False, False)
        self.assertEqual(self.settings.autostart.read_text(), before)
        self.assertTrue(self.settings.remember)
        self.assertTrue(self.settings.login)

    def test_source_run_cannot_enable_broken_autostart(self):
        with self.assertRaises(ValueError):
            Startup(self.root).save(True, True, self.vault)
        self.assertFalse(self.settings.autostart.exists())
