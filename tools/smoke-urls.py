"""Mapped URL consent, actual private URI handler and sealed linked-vault windows."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
temporary = tempfile.TemporaryDirectory(prefix="keyslot-url-ui-")
directory = Path(temporary.name)
os.environ.update(XDG_CONFIG_HOME=str(directory / "config"), XDG_DATA_HOME=str(directory / "data"),
                  XDG_CACHE_HOME=str(directory / "cache"))
from keyslot.app import Keyslot
from keyslot.core_backend import Vault
from keyslot import preferences
from gi.repository import Adw, Gio, GLib, Gtk

app = Keyslot()
failures = []
expected_error = False
records = directory / "Records.jsonl"
script = directory / "Recorder.py"
script.write_text('''import json, os, sys
fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
with os.fdopen(fd,"a") as output: output.write(json.dumps(sys.argv[2:])+"\\n")
''')
applications = directory / "data/applications"
applications.mkdir(parents=True)
desktop = applications / "keyslot-url-fixture.desktop"
desktop.write_text(f"[Desktop Entry]\nType=Application\nName=Keyslot URL Fixture\nExec={sys.executable} {script} {records} %u\nNoDisplay=true\nMimeType=x-scheme-handler/keyslot-fixture;\n")
handler = Gio.DesktopAppInfo.new_from_filename(str(desktop))
assert handler and handler.set_as_default_for_type("x-scheme-handler/keyslot-fixture")


def widgets(root):
    yield root
    child = root.get_first_child()
    while child:
        yield from widgets(child)
        child = child.get_next_sibling()


def click(dialog, label=None, tooltip=None):
    next(item for item in widgets(dialog) if isinstance(item, Gtk.Button)
         and (item.get_label() == label if label else item.get_tooltip_text() == tooltip)).emit("clicked")


def wait(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, "URL GTK fixture timed out"
        yield


def lines():
    try:
        return [json.loads(line) for line in records.read_text().splitlines()]
    except FileNotFoundError:
        return []


def scenario():
    global expected_error
    yield from wait(lambda: app.active_session is not None)
    source = app.active_session
    app.set_background(False)
    source.requested_path = directory / "Source.kdbx"
    source.vault.create(source.path, "public source master")
    command = f'cmd://"{sys.executable}" "{script}" "{records}" "command" "{{PASSWORD}}"'
    source.vault.save_entry(source.vault.snapshot.root, "Command", "", command, "", "public command secret")
    source.vault.save_entry(source.vault.snapshot.root, "Web", "public-user", "keyslot-fixture://example.org/{USERNAME}?pw={PASSWORD}", "", "public URI secret",
                            override_url="keyslot-fixture://override.example/{USERNAME}")
    source.vault.save_entry(source.vault.snapshot.root, "Linked", "", "kdbx://Target.kdbx", "", "public target master")
    source.vault.save_entry(source.vault.snapshot.root, "Wrong Linked", "", "kdbx://Target.kdbx", "", "public wrong master")
    target_path = directory / "Target.kdbx"
    creator = Vault()
    try:
        creator.create(target_path, "public target master")
        creator.save_entry(creator.snapshot.root, "Target Entry", "public user", "", "", "public target secret")
    finally:
        creator.lock()
    source.window.show_vault(source.vault.snapshot)

    def entry(title):
        return next(item for item in source.vault.snapshot.entries if item.title == title)

    def select(title):
        row = source.window.entries.get_first_child()
        while row:
            if row.entry.title == title:
                source.window.entries.select_row(row)
                return
            row = row.get_next_sibling()
        raise AssertionError("Fixture entry is missing")

    select("Command")
    click(source.window.detail, tooltip="Open Entry URL")
    yield from wait(lambda: source.dialogs and isinstance(source.dialogs[-1], Adw.AlertDialog) and source.dialogs[-1].get_heading() == "Run This Command?")
    review = source.dialogs[-1]
    assert "[Hidden]" in review.get_body() and "public command secret" not in review.get_body()
    click(review, "Cancel")
    yield from wait(lambda: source.urls.pending is None and not source.dialogs)
    source.jobs.executor.submit(lambda: None).result(timeout=3)
    assert not lines()
    source.open_entry_url(entry("Command"))
    yield from wait(lambda: source.dialogs and source.dialogs[-1].get_heading() == "Run This Command?")
    next(item for item in widgets(source.dialogs[-1]) if isinstance(item, Gtk.CheckButton)).set_active(True)
    click(source.dialogs[-1], "Run")
    yield from wait(lambda: not source.busy and source.urls.pending is None and len(lines()) == 1 and not source.dialogs)
    assert lines()[0] == ["command", "public command secret"]
    assert entry("Command").command_approved
    source.open_entry_url(entry("Command"))
    yield from wait(lambda: source.urls.pending is None and len(lines()) == 2)
    assert not source.dialogs
    select("Command")
    click(source.window.detail, tooltip="Forget Command Approval")
    yield from wait(lambda: not source.busy and not entry("Command").command_approved)

    source.vault.save_entry(source.vault.snapshot.root, "Bad Command", "", "cmd:///definitely/not/a/fixture-program", "", "public failed command secret")
    source.window.show_vault(source.vault.snapshot)
    select("Bad Command")
    source.open_entry_url(entry("Bad Command"))
    yield from wait(lambda: source.dialogs and source.dialogs[-1].get_heading() == "Run This Command?")
    next(item for item in widgets(source.dialogs[-1]) if isinstance(item, Gtk.CheckButton)).set_active(True)
    expected_error = True
    click(source.dialogs[-1], "Run")
    yield from wait(lambda: source.urls.pending is None and not source.busy and source.dialogs
                    and source.dialogs[-1].get_heading() == "Could Not Complete Operation")
    assert "could not be started" in source.dialogs[-1].get_body()
    assert entry("Bad Command").command_approved and len(lines()) == 2
    assert any(isinstance(item, Gtk.Button) and item.get_tooltip_text() == "Forget Command Approval" for item in widgets(source.window.detail))
    click(source.dialogs[-1], "Close")
    yield from wait(lambda: not source.dialogs)
    expected_error = False

    # Exercise GtkUriLauncher and an actual default handler, isolated by XDG_CONFIG/DATA_HOME.
    select("Web")
    assert source.host_window.activate_action("win.open-url", None)
    yield from wait(lambda: source.urls.pending is None and len(lines()) == 3)
    assert lines()[-1] == ["keyslot-fixture://example.org/public-user?pw=public%20URI%20secret"]
    select("Web")
    click(source.window.detail, tooltip="Open URL Override")
    yield from wait(lambda: source.urls.pending is None and len(lines()) == 4)
    assert lines()[-1] == ["keyslot-fixture://override.example/public-user"]
    assert source.vault.attribute(entry("Web")) == "public URI secret"

    class ErrorLauncher:
        def __init__(self, cancelled):
            self.cancelled, self.finished = cancelled, False
        def launch(self, parent, cancellable, callback):
            GLib.idle_add(lambda: (callback(self, None), False)[1])
        def launch_finish(self, result):
            self.finished = True
            if self.cancelled:
                raise GLib.Error.new_literal(Gtk.dialog_error_quark(), "public cancellation", Gtk.DialogError.DISMISSED)
            raise GLib.Error.new_literal(Gio.io_error_quark(), "public URI secret in a private error", Gio.IOErrorEnum.FAILED)
    for cancelled in (True, False):
        launcher = ErrorLauncher(cancelled)
        expected_error = not cancelled
        with patch.object(Gtk.UriLauncher, "new", return_value=launcher):
            source.open_entry_url(entry("Web"))
            yield from wait(lambda: launcher.finished and source.urls.pending is None)
        if cancelled:
            assert not source.dialogs
        else:
            assert source.dialogs[-1].get_heading() == "Could Not Complete Operation"
            assert "public URI secret" not in source.dialogs[-1].get_body()
            click(source.dialogs[-1], "Close")
            yield from wait(lambda: not source.dialogs)
        expected_error = False

    preferences.show(source)
    dialog = source.dialogs[-1]
    minimize = next(item for item in widgets(dialog) if isinstance(item, Adw.SwitchRow) and item.get_title() == "Minimize After Opening Links")
    minimize.set_active(True)
    assert app.startup.minimize_on_url
    dialog.close()
    yield from wait(lambda: not source.dialogs)
    app.set_background(True)
    source.open_entry_url(entry("Web"))
    yield from wait(lambda: source.urls.pending is None and not source.host_window.get_visible() and len(lines()) == 5)
    assert source.vault.unlocked
    app.select_session(source)
    app.set_background(False)
    with patch.object(source.host_window, "minimize") as minimize_window:
        source.open_entry_url(entry("Web"))
        yield from wait(lambda: source.urls.pending is None and len(lines()) == 6)
        assert minimize_window.call_count == 1
    app.startup.save(app.startup.remember, app.startup.login, app.startup.vault, minimize_on_url=False)

    app.startup.save(True, False, source.path)
    source.open_entry_url(entry("Linked"))
    yield from wait(lambda: len(app.sessions) == 2 and app.active_session is not source and app.active_session.vault.unlocked)
    target = app.active_session
    assert target.path == target_path and source.vault.unlocked
    assert target.vault.attribute(target.vault.snapshot.entries[0]) == "public target secret"
    assert not target.dialogs and source.urls.pending is None
    assert app.startup.vault == target_path
    identity = target.vault.identity
    app.select_session(source)
    source.open_entry_url(entry("Linked"))
    yield from wait(lambda: app.active_session is target and source.urls.pending is None)
    assert len(app.sessions) == 2 and target.vault.identity is identity
    target.lock()
    app.select_session(source)
    source.open_entry_url(entry("Linked"))
    yield from wait(lambda: app.active_session is target and target.vault.unlocked and source.urls.pending is None)
    assert len(app.sessions) == 2

    target.lock()
    app.select_session(source)
    expected_error = True
    source.open_entry_url(entry("Wrong Linked"))
    yield from wait(lambda: app.active_session is target and source.urls.pending is None and len(target.dialogs) >= 2)
    assert not target.vault.unlocked and source.vault.unlocked
    assert any(item.get_title() == "Unlock Database" for item in target.dialogs if not isinstance(item, Adw.AlertDialog))
    assert any(isinstance(item, Adw.AlertDialog) and "credential" in item.get_body() for item in target.dialogs)
    target.close_dialogs()
    expected_error = False
    app.select_session(source)

    # A late URI completion after locking must not minimize, report success or leave its request alive.
    class DeferredLauncher:
        def launch(self, parent, cancellable, callback):
            self.cancellable, self.callback = cancellable, callback
        def launch_finish(self, result):
            return True
    deferred = DeferredLauncher()
    with patch.object(Gtk.UriLauncher, "new", return_value=deferred):
        source.open_entry_url(entry("Web"))
        yield from wait(lambda: hasattr(deferred, "callback"))
        source.lock()
        assert deferred.cancellable.is_cancelled() and source.urls.pending is None
        deferred.callback(deferred, None)
        assert not source.pending_errors and not source.dialogs and not source.vault.unlocked
    source.run_job(lambda: source.vault.unlock(source.path, "public source master"), source.window.show_vault)
    yield from wait(lambda: not source.busy and source.vault.unlocked)

    # Cancel a linked opening before its recipient starts; a stale worker cannot restart the helper.
    other_path = directory / "Other.kdbx"
    try:
        creator.create(other_path, "public other master")
    finally:
        creator.lock()
    source.vault.save_entry(source.vault.snapshot.root, "Paused Linked", "", "kdbx://Other.kdbx", "", "public other master")
    source.window.show_vault(source.vault.snapshot)
    entered, release = threading.Event(), threading.Event()
    original_new = app.new_window
    created = []
    def new_window(present=True):
        session = original_new(present)
        original_offer = session.vault.url_offer
        def paused(ticket):
            entered.set()
            assert release.wait(8)
            return original_offer(ticket)
        session.vault.url_offer = paused
        created.append(session)
        return session
    with patch.object(app, "new_window", new_window):
        source.open_entry_url(entry("Paused Linked"))
        yield from wait(entered.is_set)
        timer = threading.Timer(.05, release.set)
        timer.start()
        source.lock()
        timer.join()
    yield
    assert source.urls.pending is None and not source.vault.unlocked
    assert created[0] not in app.sessions and created[0].jobs.closed and created[0].vault._process is None
    assert target in app.sessions and not target.jobs.closed
    assert len(lines()) == 6
    app.quit()


steps = scenario()
def tick():
    try:
        if not expected_error:
            for session in app.sessions:
                if session.pending_errors:
                    raise AssertionError(session.pending_errors)
                for dialog in session.dialogs:
                    if isinstance(dialog, Adw.AlertDialog) and dialog.get_heading() == "Could Not Complete Operation":
                        raise AssertionError(dialog.get_body())
        next(steps)
        return True
    except StopIteration:
        return False
    except Exception as exc:
        failures.append(exc)
        app.quit()
        return False

app.connect("activate", lambda *_: GLib.timeout_add(25, tick))
status = app.run(["keyslot-url-fixture"])
temporary.cleanup()
if failures:
    raise failures[0]
assert status == 0
print("GTK command approval/revoke, real private URI handler/override, minimize preference, sealed linked-vault open/dedup/manual fallback and late-lock cancellation: PASS")
