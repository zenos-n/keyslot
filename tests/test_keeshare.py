"""Background sharing must not restart cancelled helpers or repeat warnings on every poll."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from keyslot.keeshare import KeeShareIntegration
from keyslot.startup import Startup
import tempfile


class KeeShareLifecycle(unittest.TestCase):
    def setUp(self):
        self.queue = []
        jobs = SimpleNamespace(closed=False, busy=False)
        def run(operation, done=None, failed=None, **options):
            self.queue.append((operation, done, failed, options))
            return True
        jobs.run = run
        self.session = SimpleNamespace(epoch=0, jobs=jobs, error=Mock(), window=SimpleNamespace(show_vault=Mock()))
        # Real session objects are identity-hashable.
        class Session:
            pass
        session = Session()
        session.__dict__.update(self.session.__dict__)
        self.session = session
        session.vault = SimpleNamespace(unlocked=True, identity=object(), snapshot=object(),
            keeshare_configure=Mock(), keeshare_sync=Mock(return_value={"imports": 0, "exports": 0, "warnings": []}))
        self.app = SimpleNamespace(sessions=[session], startup=SimpleNamespace(directory="/tmp/public-fixture-config",
                                   keeshare={"import": False, "export": False}))
        self.integration = KeeShareIntegration(self.app)

    def test_disabled_and_busy_sessions_do_not_sync(self):
        self.integration.state_changed()
        self.assertFalse(self.queue)
        self.app.startup.keeshare["import"] = True
        self.session.jobs.busy = True
        self.integration.state_changed()
        self.assertFalse(self.queue)
        self.session.jobs.busy = False
        self.integration.state_changed()
        self.assertEqual(len(self.queue), 1)
        self.assertEqual(self.queue[0][3], {"interactive": False})
        self.integration.state_changed()
        self.assertEqual(len(self.queue), 1)

    def test_lock_discards_late_completion_and_warning(self):
        self.app.startup.keeshare["import"] = True
        self.integration.state_changed()
        _, done, failed, _ = self.queue.pop()
        self.session.vault.unlocked = False
        self.session.epoch += 1
        self.integration.state_changed()
        done({"imports": 1, "exports": 0, "warnings": ["late warning"]})
        failed("late failure")
        self.session.window.show_vault.assert_not_called()
        self.session.error.assert_not_called()

    def test_unchanged_warning_is_deduplicated_but_new_failure_is_reported(self):
        self.app.startup.keeshare["import"] = True
        with patch("keyslot.keeshare.time.monotonic", return_value=100):
            self.integration.state_changed()
        _, done, failed, _ = self.queue.pop()
        done({"imports": 1, "exports": 0, "warnings": ["missing", "missing"]})
        done({"imports": 0, "exports": 0, "warnings": ["missing"]})
        self.assertEqual(self.session.error.call_count, 1)
        self.session.window.show_vault.assert_called_once_with(self.session.vault.snapshot)
        failed("different")
        self.assertEqual(self.session.error.call_count, 2)
        with patch("keyslot.keeshare.time.monotonic", return_value=131):
            self.integration.state_changed()
        self.assertEqual(len(self.queue), 1)

    def test_reopened_helper_reconfigures_and_close_prevents_polling(self):
        self.app.startup.keeshare["export"] = True
        self.integration.state_changed()
        operation, *_ = self.queue.pop()
        operation()
        self.session.vault.keeshare_configure.assert_called_once_with("/tmp/public-fixture-config", {"import": False, "export": True})
        self.session.vault.identity = object()
        self.integration.state_changed()
        self.assertEqual(len(self.queue), 1)
        self.queue.clear()
        self.integration.close()
        self.integration.state_changed()
        self.assertFalse(self.queue)


class SavedServiceOptions(unittest.TestCase):
    def test_options_survive_other_preferences_and_invalid_values_do_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Startup(directory)
            auto = config.autotype | {"delay": 75, "start_delay": 1500, "relock": True}
            config.save(False, False, autotype=auto, keeshare={"import": True, "export": False})
            config.save(False, False, background=False, ssh=False)
            loaded = Startup(directory)
            self.assertEqual(loaded.autotype, auto)
            self.assertEqual(loaded.keeshare, {"import": True, "export": False})
            before = loaded.path.read_bytes()
            for invalid in (auto | {"delay": True}, auto | {"start_delay": 0}, auto | {"relock": "yes"}):
                with self.assertRaises(ValueError):
                    loaded.save(False, False, autotype=invalid)
            with self.assertRaises(ValueError):
                loaded.save(False, False, keeshare={"import": True, "export": "yes"})
            self.assertEqual(loaded.path.read_bytes(), before)
