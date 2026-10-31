"""Send native XTEST auto-type to an owned GTK receiver on the test's Xvfb display."""
import ctypes
import ctypes.util
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile

if "--receiver" in sys.argv:
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("GdkX11", "4.0")
    from gi.repository import Gtk, GdkX11, GLib
    x11 = ctypes.CDLL(ctypes.util.find_library("X11"))
    x11.XOpenDisplay.argtypes, x11.XOpenDisplay.restype = [ctypes.c_char_p], ctypes.c_void_p
    x11.XDefaultRootWindow.argtypes, x11.XDefaultRootWindow.restype = [ctypes.c_void_p], ctypes.c_ulong
    x11.XInternAtom.argtypes, x11.XInternAtom.restype = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int], ctypes.c_ulong
    x11.XChangeProperty.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
                                  ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    x11.XSetInputFocus.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    x11.XFlush.argtypes = [ctypes.c_void_p]
    display = x11.XOpenDisplay(None)
    assert display
    application = Gtk.Application(application_id="com.neg_zero.KeyslotAutoTypeReceiver")
    def activate(*_):
        window = Gtk.ApplicationWindow(application=application, title="Public Auto-Type Receiver", default_width=420, default_height=180)
        username, password = Gtk.Entry(), Gtk.Entry()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.append(username)
        box.append(password)
        window.set_child(box)
        window.present()
        alternate = Gtk.ApplicationWindow(application=application, title="Public Focus Abort Receiver")
        alternate.set_child(Gtk.Entry())
        alternate.present()
        def focus(widget):
            identifier = widget.get_surface().get_xid()
            state = x11.XInternAtom(display, b"WM_STATE", False)
            data = (ctypes.c_ulong * 2)(1, 0)
            x11.XChangeProperty(display, identifier, state, state, 32, 0, data, 2)
            # Xvfb has no window manager. Advertise the EWMH atom and focus this fixture explicitly.
            x11.XInternAtom(display, b"_NET_ACTIVE_WINDOW", False)
            x11.XSetInputFocus(display, identifier, 1, 0)
            x11.XFlush(display)
            return identifier
        def ready():
            window.present()
            username.grab_focus()
            identifier = focus(window)
            if "--abort" in sys.argv:
                username.connect("changed", lambda *_: focus(alternate))
            print(json.dumps(dict(target=str(identifier), title=window.get_title(), backend="x11")), flush=True)
            return False
        GLib.timeout_add(250, ready)
        def report(*_):
            print(json.dumps([username.get_text(), password.get_text()]), flush=True)
        password.connect("activate", report)
        def command(_source, _condition):
            value = sys.stdin.readline()
            if value.strip() == "state":
                report()
            elif value.strip() == "quit" or not value:
                application.quit()
                return False
            return True
        GLib.io_add_watch(sys.stdin, GLib.IO_IN | GLib.IO_HUP, command)
    application.connect("activate", activate)
    raise SystemExit(application.run(["keyslot-public-receiver"]))

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keyslot.core_backend import Vault, EngineError
def line(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        assert selector.select(10), "GTK receiver timed out"
        value = process.stdout.readline()
        assert value, "GTK receiver exited"
        return json.loads(value)

with tempfile.TemporaryDirectory(prefix="keyslot-autotype-x11-") as directory:
    vault = Vault()
    vault.create(Path(directory) / "fixture.kdbx", "public fixture master")
    vault.save_entry(vault.snapshot.root, "Public Receiver", "fixture-user", "", "", "fixture-Pass_42")
    entry = vault.snapshot.entries[0]
    try:
        for abort in (False, True):
            receiver = subprocess.Popen([sys.executable, __file__, "--receiver"] + (["--abort"] if abort else []),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            try:
                target = line(receiver)
                assert any(item["target"] == target["target"] for item in vault.autotype_targets())
                prepared = vault.autotype_prepare(entry, target, "{USERNAME}{TAB}{PASSWORD}{ENTER}", 25, 100)
                if abort:
                    try:
                        vault.autotype_finish(prepared["token"], approved=True)
                        raise AssertionError("Native auto-type ignored a focus change")
                    except EngineError as exc:
                        assert exc.code == "focus_changed", exc
                    receiver.stdin.write("state\n")
                    receiver.stdin.flush()
                    username, password = line(receiver)
                    assert username and len(username) < len("fixture-user") and password == "", (username, password)
                else:
                    result = vault.autotype_finish(prepared["token"], approved=True)
                    assert result["typed"]
                    assert line(receiver) == ["fixture-user", "fixture-Pass_42"]
            finally:
                receiver.stdin.write("quit\n")
                receiver.stdin.flush()
                try:
                    receiver.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    receiver.kill()
                    receiver.wait(timeout=3)
    finally:
        vault.lock()
print("X11 native auto-type: upstream executor to GTK receiver and focus-change abort: PASS")
