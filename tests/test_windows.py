"""Exercise window-controller decisions without constructing display widgets."""
from pathlib import Path
import os
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

try:
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
except (ImportError, ValueError):
    if os.environ.get("KEYSLOT_REQUIRE_ENGINE") == "1":
        raise RuntimeError("GTK/Adwaita window-controller tests are required for the package build.")
    raise unittest.SkipTest("GTK/Adwaita introspection is required for window-controller tests")

from keyslot.app import Keyslot, MainWindow
from keyslot.application import VaultSession, Gio


class FakeSession:
    def __init__(self, path=None, unlocked=False):
        self.requested_path = path
        self.vault = SimpleNamespace(path=path, unlocked=unlocked)
        self.busy = False
        self.pending_unlock = None
        self.dialogs = []
        self.errors = []
        self.activated = self.deactivated = 0
        self.host_window = SimpleNamespace()

    @property
    def path(self):
        return self.requested_path or self.vault.path

    def error(self, message):
        self.errors.append(message)

    def activate(self):
        self.activated += 1

    def deactivate(self):
        self.deactivated += 1


class FakeApp:
    def __init__(self, sessions):
        self.sessions = sessions
        self.active_session = sessions[0]
        self.window = object()

    def update_session(self, session):
        pass

    def new_window(self, present=True):
        session = FakeSession()
        self.sessions.append(session)
        if present:
            self.select_session(session)
        return session

    def select_session(self, session):
        self.active_session = session


class WindowTests(unittest.TestCase):
    def test_inactivity_lock_honors_never_and_configured_duration(self):
        calls = []
        app = SimpleNamespace(startup=SimpleNamespace(lock_minutes=0), last_activity=0,
                              locked=False, busy=False, lock=lambda: calls.append(True))
        with patch('keyslot.app.time.monotonic', return_value=36000):
            Keyslot._idle_check(app)
        self.assertFalse(calls)
        app.startup.lock_minutes = 5
        with patch('keyslot.app.time.monotonic', return_value=299):
            Keyslot._idle_check(app)
        self.assertFalse(calls)
        with patch('keyslot.app.time.monotonic', return_value=300):
            Keyslot._idle_check(app)
        self.assertEqual(calls, [True])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_new_database_uses_another_session_and_preserves_existing_unlock(self):
        first = FakeSession(self.directory / "first.kdbx", unlocked=True)
        app = FakeApp([first])
        new = Keyslot.open_database(app, self.directory / "second.kdbx")
        self.assertIsNot(new, first)
        self.assertIs(app.active_session, new)
        self.assertTrue(first.vault.unlocked)
        self.assertEqual(new.pending_unlock[0], str(self.directory / "second.kdbx"))

    def test_symlink_duplicate_selects_existing_session_without_reunlock(self):
        path = self.directory / "first.kdbx"
        path.write_bytes(b"public fixture")
        alias = self.directory / "alias.kdbx"
        alias.symlink_to(path)
        first = FakeSession(path, unlocked=True)
        app = FakeApp([first, FakeSession()])
        app.active_session = app.sessions[1]
        result = Keyslot.open_database(app, alias)
        self.assertIs(result, first)
        self.assertEqual(len(app.sessions), 2)
        self.assertIsNone(first.pending_unlock)
        self.assertTrue(first.vault.unlocked)

    def test_create_does_not_replace_existing_file_or_close_live_session(self):
        first = FakeSession(self.directory / "first.kdbx", unlocked=True)
        app = FakeApp([first])
        target = self.directory / "existing.kdbx"
        target.write_bytes(b"keep existing")
        self.assertIsNone(Keyslot.open_database(app, target, create=True))
        self.assertEqual(target.read_bytes(), b"keep existing")
        self.assertTrue(first.vault.unlocked)
        self.assertEqual(len(app.sessions), 1)
        self.assertTrue(first.errors)

    def test_public_state_aggregates_all_sessions(self):
        first, second = FakeSession(unlocked=False), FakeSession(unlocked=True)
        app = FakeApp([first, second])
        self.assertFalse(Keyslot.locked.fget(app))
        second.vault.unlocked = False
        self.assertTrue(Keyslot.locked.fget(app))
        first.busy = True
        self.assertTrue(Keyslot.busy.fget(app))

    def test_focusing_another_window_preserves_origin_modal(self):
        first, second = FakeSession(), FakeSession()
        first.dialogs = [object()]
        app = FakeApp([first, second])
        window = SimpleNamespace(app=app, session=second, is_active=lambda: True)
        MainWindow._focused(window)
        self.assertIs(app.active_session, second)
        self.assertEqual(first.deactivated, 0)
        self.assertEqual(len(first.dialogs), 1)

    def test_inactive_session_does_not_publish_late_clipboard_values(self):
        session = SimpleNamespace(active=False, jobs=SimpleNamespace(closed=False),
                                  clear_clipboard=lambda: self.fail("An inactive result must not touch the clipboard"))
        VaultSession.copy(session, "public late fixture")

    def test_late_file_selection_after_window_close_is_ignored(self):
        selected = []
        class DeferredPicker:
            def open(self, parent, cancellable, callback):
                self.cancellable, self.callback = cancellable, callback
            def open_finish(self, result):
                return Gio.File.new_for_path(str(Path(self.directory) / "public fixture"))
        picker = DeferredPicker()
        picker.directory = self.directory
        session = SimpleNamespace(active=True, jobs=SimpleNamespace(closed=False), epoch=0, view_epoch=0,
                                  file_requests=set(), host_window=object())
        with patch("keyslot.application.Gtk.FileDialog", return_value=picker):
            VaultSession.choose_file(session, selected.append)
        session.active = False
        session.jobs.closed = True
        session.view_epoch += 1
        VaultSession.cancel_file_requests(session)
        self.assertTrue(picker.cancellable.is_cancelled())
        picker.callback(picker, None)
        self.assertEqual(selected, [])
