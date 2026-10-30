"""Exercise login unlock against a disposable keyring on its own private bus."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import time

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))

if sys.argv[1:] != ["--isolated"]:
    with tempfile.TemporaryDirectory(prefix="keyslot-login-test-") as directory:
        env = os.environ.copy()
        for name, leaf in [("XDG_CONFIG_HOME", "config"), ("XDG_DATA_HOME", "data"), ("XDG_RUNTIME_DIR", "runtime")]:
            path = Path(directory) / leaf
            path.mkdir(mode=0o700)
            env[name] = str(path)
        raise SystemExit(subprocess.run(["dbus-run-session", "--config-file=" + str(root / "tools/test-session.conf"),
            "--", sys.executable, __file__, "--isolated"], env=env, timeout=40).returncode)

from keyslot.startup import Startup, LoginKeyring
from keyslot.core_backend import Vault
from keyslot.app import Keyslot
from keyslot import preferences
from gi.repository import Adw, GLib, Gtk

daemon = subprocess.Popen(["gnome-keyring-daemon", "--foreground", "--unlock", "--components=secrets",
                           "--control-directory=" + os.environ["XDG_RUNTIME_DIR"]],
                          stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
daemon.stdin.write(b"public fixture login password")
daemon.stdin.close()
vault = Vault()
app = None
try:
    keyring = LoginKeyring()
    deadline = time.monotonic() + 5
    while True:
        try:
            keyring._collection()
            break
        except (GLib.Error, ValueError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(.05)
    path = Path(os.environ["XDG_DATA_HOME"]) / "login-fixture.kdbx"
    credentials = {"password": "public fixture vault password", "keyfile": "", "yubikey": "", "no_password": False}
    vault.create(path, credentials["password"])
    vault.save_entry(vault.snapshot.root, "Login fixture", "", "", "", "public fixture entry secret")
    vault.lock()
    keyring.store(path, credentials)
    assert keyring.lookup(path) == credentials
    settings = Startup(launcher="/unused-fixture-keyslot")
    settings.save(True, True, path, background=False)
    app = Keyslot()
    app.startup.launcher = "/unused-fixture-keyslot"
    failures = []
    checks = [0]
    phase = [0]
    attempts = [0]
    def quick_attempt(session, password):
        session._unlock_dialog(str(path))
        widgets = list(descendants(session.dialogs[-1]))
        next(item for item in widgets if isinstance(item, Adw.PasswordEntryRow)
             and item.get_title() == "Short Password").set_text(password)
        next(item for item in widgets if isinstance(item, Gtk.Button) and item.get_label() == "Unlock").emit("clicked")
    def descendants(widget):
        yield widget
        child = widget.get_first_child()
        while child:
            yield from descendants(child)
            child = child.get_next_sibling()
    def inspect():
        checks[0] += 1
        if checks[0] > 80:
            failures.append("Login unlock did not finish")
            app.quit()
            return False
        if not app.sessions or app.busy:
            return True
        session = app.sessions[0]
        try:
            if phase[0] == 0:
                assert session.vault.unlocked, "Login keyring did not unlock the vault"
                assert session.vault.attribute(session.vault.snapshot.entries[0]) == "public fixture entry secret"
                session.lock()
                assert not session.vault.unlocked
                app._command_line(app, LoginCommand())
                assert not session.vault.unlocked, "A duplicate login activation undid a manual lock"
                session.jobs.executor.submit(lambda: None).result(timeout=3)
                session.vault.unlock(path, **credentials)
                session.window.show_vault(session.vault.snapshot)
                app.startup.save(True, False, path)
                keyring.clear()
                preferences.enroll(session)
                widgets = list(descendants(session.dialogs[-1]))
                next(item for item in widgets if isinstance(item, Adw.PasswordEntryRow)).set_text(credentials["password"])
                next(item for item in widgets if isinstance(item, Gtk.Button)
                     and item.get_label() == "Enable Login Unlock").emit("clicked")
                phase[0] = 1
                return True
            if phase[0] == 1:
                assert app.startup.login, "Enrollment did not enable login unlock"
                assert keyring.lookup(path) == credentials
                preferences.show(session)
                rows = list(descendants(session.dialogs[-1]))
                next(item for item in rows if isinstance(item, Adw.SwitchRow)
                     and item.get_title() == "Unlock at Login").set_active(False)
                phase[0] = 2
                return True
            if phase[0] == 2:
                assert not app.startup.login, "Preferences did not disable login unlock"
                assert not app.startup.autostart.exists()
                try:
                    keyring.lookup(path)
                    raise AssertionError("Disabled login credential remained in the keyring")
                except ValueError:
                    pass
                session.close_dialogs()
                preferences.enroll(session, quick=True)
                widgets = list(descendants(session.dialogs[-1]))
                def group_of(widget):
                    while widget and not isinstance(widget, Adw.PreferencesGroup):
                        widget = widget.get_parent()
                    return widget
                master = next(item for item in widgets if isinstance(item, Adw.PasswordEntryRow)
                              and item.get_title() == 'Master Password')
                short = next(item for item in widgets if isinstance(item, Adw.PasswordEntryRow)
                             and item.get_title() == 'Short Password')
                assert group_of(short) is not group_of(master), 'Short password shares the master credential group'
                for widget in widgets:
                    if isinstance(widget, Adw.PasswordEntryRow):
                        widget.set_text('wrong fixture password' if widget.get_title() == 'Master Password' else '1234')
                next(item for item in widgets if isinstance(item, Gtk.Button)
                     and item.get_label() == "Enable Quick Unlock").emit("clicked")
                phase[0] = 6
                return True
            if phase[0] == 6:
                assert session.vault.unlocked and not session.quick_blob
                assert session.dialogs[-1].get_title() == 'Set Up Quick Unlock', 'Credential failure closed the setup form'
                widgets = list(descendants(session.dialogs[-1]))
                master = next(item for item in widgets if isinstance(item, Adw.PasswordEntryRow)
                              and item.get_title() == 'Master Password')
                short = next(item for item in widgets if isinstance(item, Adw.PasswordEntryRow)
                             and item.get_title() == 'Short Password')
                assert master.get_text() == 'wrong fixture password' and short.get_text() == '1234'
                assert any(isinstance(item, Gtk.Label) and item.has_css_class('error') and item.get_visible() for item in widgets)
                master.set_text(credentials['password'])
                save = next(item for item in widgets if isinstance(item, Gtk.Button) and item.get_label() == 'Enable Quick Unlock')
                assert save.is_sensitive(), 'Credential failure left the setup form disabled'
                save.emit('clicked')
                phase[0] = 3
                return True
            if phase[0] == 3:
                assert session.quick_blob, 'Quick-unlock enrollment did not retain an encrypted bundle'
                session.lock()
                quick_attempt(session, '1234')
                phase[0] = 4
                return True
            if phase[0] == 4:
                assert session.vault.unlocked, 'Correct short password did not unlock the vault'
                assert session.vault.attribute(session.vault.snapshot.entries[0]) == 'public fixture entry secret'
                session.lock()
                quick_attempt(session, 'wrong fixture PIN')
                attempts[0] = 1
                phase[0] = 5
                return True
            assert not session.vault.unlocked
            assert session.quick_attempts == attempts[0]
            session.close_dialogs()
            if attempts[0] < 5:
                quick_attempt(session, 'wrong fixture PIN')
                attempts[0] += 1
                return True
            assert session.quick_blob is None, 'Five failed attempts did not remove the cached credential'
            session._unlock_dialog(str(path))
            assert session.dialogs[-1].get_title() == 'Unlock Database', 'Failed quick unlock did not fall back to master password'
        except Exception as exc:
            failures.append(str(exc))
        app.quit()
        return False
    class LoginCommand:
        def get_options_dict(self):
            return GLib.VariantDict.new(GLib.Variant("a{sv}", {"login": GLib.Variant("b", True)}))
    GLib.timeout_add(100, inspect)
    assert app.run(["keyslot", "--login"]) == 0
    assert not failures, failures
    keyring.clear()
    try:
        keyring.lookup(path)
        raise AssertionError("Disabled login credential remained in the keyring")
    except ValueError:
        pass
    settings.save(True, False, path)
    assert not settings.autostart.exists()
    print("Login keyring, GTK enrollment/removal, short-password unlock and five-attempt fallback: PASS")
finally:
    vault.lock()
    daemon.terminate()
    try:
        daemon.wait(timeout=3)
    except subprocess.TimeoutExpired:
        daemon.kill()
        daemon.wait()
