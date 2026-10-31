"""Mapped GTK auto-type workflows with a private, permission-gated portal fixture."""
import os
from pathlib import Path
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
temporary = tempfile.TemporaryDirectory(prefix="keyslot-autotype-ui-")
directory = Path(temporary.name)
os.environ["XDG_CONFIG_HOME"] = str(directory / "config")
from gi.repository import Gio, GLib, Gtk, Adw
from keyslot.app import Keyslot
from keyslot import autotype, autotype_views, keeshare_views

PORTAL_XML = '''<node><interface name="org.freedesktop.portal.RemoteDesktop">
<method name="CreateSession"><arg type="a{sv}" direction="in"/><arg type="o" direction="out"/></method>
<method name="SelectDevices"><arg type="o" direction="in"/><arg type="a{sv}" direction="in"/><arg type="o" direction="out"/></method>
<method name="Start"><arg type="o" direction="in"/><arg type="s" direction="in"/><arg type="a{sv}" direction="in"/><arg type="o" direction="out"/></method>
<method name="NotifyKeyboardKeysym"><arg type="o" direction="in"/><arg type="a{sv}" direction="in"/><arg type="i" direction="in"/><arg type="u" direction="in"/></method>
</interface></node>'''
REQUEST_XML = '''<node><interface name="org.freedesktop.portal.Request"><method name="Close"/>
<signal name="Response"><arg type="u"/><arg type="a{sv}"/></signal></interface></node>'''
SESSION_XML = '''<node><interface name="org.freedesktop.portal.Session"><method name="Close"/>
<signal name="Closed"/></interface></node>'''
SHELL_XML = '''<node><interface name="com.neg_zero.keyslot.AutoType1">
<method name="Capture"><arg type="s" direction="out"/><arg type="s" direction="out"/></method>
<method name="Focus"><arg type="s" direction="in"/><arg type="b" direction="out"/></method>
<method name="Check"><arg type="s" direction="in"/><arg type="b" direction="out"/></method></interface></node>'''


def interface(xml):
    return Gio.DBusNodeInfo.new_for_xml(xml).interfaces[0]


class DesktopFixture:
    def __init__(self):
        self.connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self.registrations = []
        self.requests, self.sessions, self.events = [], set(), []
        self.closed = 0
        self.focus = True
        self.abort_after = None
        self.hold = False
        self.waiting = False
        self.owners = [Gio.bus_own_name_on_connection(self.connection, name, Gio.BusNameOwnerFlags.DO_NOT_QUEUE, None, None)
                       for name in (autotype.PORTAL_NAME, autotype.SHELL_NAME)]
        self.register(autotype.PORTAL_PATH, PORTAL_XML, self.portal)
        self.register(autotype.SHELL_PATH, SHELL_XML, self.shell)

    def register(self, path, xml, callback):
        self.registrations.append(self.connection.register_object(path, interface(xml), callback, None, None))

    def shell(self, _c, _sender, _path, _interface, method, params, invocation):
        if method == "Capture":
            invocation.return_value(GLib.Variant("(ss)", ("fixture-target", "Public Fixture Destination")))
        elif method == "Focus":
            self.focus = True
            invocation.return_value(GLib.Variant("(b)", (params.unpack()[0] == "fixture-target",)))
        else:
            invocation.return_value(GLib.Variant("(b)", (self.focus,)))

    def portal(self, _c, sender, _path, _interface, method, params, invocation):
        values = params.unpack()
        if method == "NotifyKeyboardKeysym":
            session, _options, symbol, state = values
            assert session in self.sessions
            self.events.append((symbol, state))
            if self.abort_after and sum(event[1] for event in self.events) >= self.abort_after:
                self.focus = False
            invocation.return_value(None)
            return
        options = values[-1]
        path = "/org/freedesktop/portal/desktop/request/" + sender[1:].replace(".", "_") + "/" + options["handle_token"]
        self.requests.append(path)
        self.register(path, REQUEST_XML, lambda _c, _s, _p, _i, _m, _v, call: call.return_value(None))
        data = {}
        if method == "CreateSession":
            session = "/org/freedesktop/portal/desktop/session/" + sender[1:].replace(".", "_") + "/" + options["session_handle_token"]
            self.sessions.add(session)
            def close(_c, _s, path, _i, _m, _v, call):
                self.sessions.discard(path)
                self.closed += 1
                call.return_value(None)
            self.register(session, SESSION_XML, close)
            data["session_handle"] = GLib.Variant("o", session)
        elif method == "SelectDevices":
            assert options["types"] == 1 and options["persist_mode"] == 0
        elif method == "Start":
            data["devices"] = GLib.Variant("u", 1)
        invocation.return_value(GLib.Variant("(o)", (path,)))
        if method == "Start" and self.hold:
            self.waiting = True
        else:
            GLib.idle_add(lambda: (self.connection.emit_signal(sender, path, "org.freedesktop.portal.Request", "Response",
                GLib.Variant("(ua{sv})", (0, data))), False)[1])


def widgets(root):
    yield root
    child = root.get_first_child()
    while child:
        yield from widgets(child)
        child = child.get_next_sibling()


def wait(predicate, seconds=12):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, "GTK workflow timed out"
        yield


app = Keyslot()
desktop = DesktopFixture()
failure = []


def scenario():
    yield from wait(lambda: app.active_session is not None)
    session = app.active_session
    session.requested_path = directory / "fixture.kdbx"
    session.vault.create(session.requested_path, "public fixture master")
    root = session.vault.snapshot.root
    session.vault.save_entry(root, "Fixture Entry", "fixture-user", "", "", "aBc123")
    entry = session.vault.snapshot.entries[0]
    session.window.show_vault(session.vault.snapshot)
    targets = []
    session.run_job(autotype.capture_target, targets.append)
    yield from wait(lambda: bool(targets) and not session.busy)
    target = targets[0]
    # Read settings via the real helper, then save through the actual GTK dialog.
    autotype_views.settings(session, entry=entry)
    yield from wait(lambda: session.dialogs and not session.busy)
    dialog = session.dialogs[-1]
    sequence = next(w for w in widgets(dialog) if isinstance(w, Adw.EntryRow) and w.get_title() == "Default Sequence")
    sequence.set_text("{USERNAME}{TAB}{PICKCHARS}{ENTER}")
    next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_label() == "Save").emit("clicked")
    yield from wait(lambda: not session.dialogs and not session.busy)
    entry = session.vault.snapshot.entries[0]
    data = session.vault.autotype_prepare(entry, target, "{USERNAME}{TAB}{PICKCHARS}{ENTER}", 0, 100)
    autotype_views.review(session, target, data)
    yield
    dialog = session.dialogs[-1]
    positions = next(w for w in widgets(dialog) if isinstance(w, Adw.EntryRow) and w.get_title() == "Character Positions")
    positions.set_text("2 4 6")
    next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_label() == "Type").emit("clicked")
    yield from wait(lambda: not session.jobs.busy and desktop.closed == 1)
    assert [symbol for symbol, state in desktop.events if state] == [*map(ord, "fixture-user"), 0xFF09, *map(ord, "B13"), 0xFF0D]
    assert not desktop.sessions and desktop.focus
    # A focus change after the first press aborts all remaining credential keys and still releases the key.
    desktop.events.clear()
    desktop.abort_after = 1
    data = session.vault.autotype_prepare(entry, target, "{PASSWORD}", 0, 100)
    session.run_job(lambda: autotype.execute_portal(session, target, data["token"], [], session.epoch),
                    failed=lambda message: failure.append(message))
    yield from wait(lambda: not session.jobs.busy and desktop.closed == 2)
    assert len(failure) == 1 and "window changed" in failure.pop()
    assert desktop.events == [(ord("a"), 1), (ord("a"), 0)]
    assert not desktop.sessions
    # Shared-group settings are mapped, rounded libadwaita groups; their password clears on close.
    keeshare_views.settings(session, root)
    yield from wait(lambda: session.dialogs and not session.busy)
    dialog = session.dialogs[-1]
    secret = next(w for w in widgets(dialog) if isinstance(w, Adw.PasswordEntryRow))
    secret.set_text("public share password")
    dialog.force_close()
    assert secret.get_text() == ""
    # Locking while permission is pending closes both request and predicted session; no keyboard event escapes.
    desktop.events.clear()
    desktop.abort_after = None
    desktop.hold = True
    data = session.vault.autotype_prepare(entry, target, "{PASSWORD}")
    epoch = session.epoch
    session.run_job(lambda: autotype.execute_portal(session, target, data["token"], [], epoch))
    yield from wait(lambda: desktop.waiting)
    session.lock()
    yield from wait(lambda: desktop.closed == 3)
    assert not desktop.sessions and not desktop.events and not session.vault.unlocked
    app.quit()


steps = scenario()
def tick():
    try:
        next(steps)
        return True
    except StopIteration:
        return False
    except Exception as exc:
        failure.append(exc)
        app.quit()
        return False


app.connect("activate", lambda *_: GLib.timeout_add(25, tick))
status = app.run(["keyslot-autotype-ui"])
temporary.cleanup()
if failure:
    raise failure[0] if isinstance(failure[0], Exception) else AssertionError(failure[0])
if status:
    raise SystemExit(status)
print("GTK auto-type: native parser/settings, PICKCHARS, portal permission, focus abort, key release and lock cancellation: PASS")
