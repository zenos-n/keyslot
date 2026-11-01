"""GNOME keyboard portal execution, scoped to one approved window and vault epoch."""
import collections
import threading
import time
import uuid

from gi.repository import Gio, GLib
from .backend import VaultError

SHELL_NAME = "org.gnome.Shell"
SHELL_PATH = "/com/neg_zero/keyslot/AutoType1"
SHELL_INTERFACE = "com.neg_zero.keyslot.AutoType1"
PORTAL_NAME = "org.freedesktop.portal.Desktop"
PORTAL_PATH = "/org/freedesktop/portal/desktop"
PORTAL_INTERFACE = "org.freedesktop.portal.RemoteDesktop"


def shell_call(method, parameters=None, signature=None):
    try:
        connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        return connection.call_sync(SHELL_NAME, SHELL_PATH, SHELL_INTERFACE, method, parameters,
            GLib.VariantType.new(signature) if signature else None, Gio.DBusCallFlags.NO_AUTO_START, 3000, None).unpack()
    except GLib.Error as exc:
        raise VaultError("Enable the Keyslot GNOME companion for guarded Wayland auto-type.") from exc


def capture_target():
    token, title = shell_call("Capture", signature="(ss)")
    if not token or not title:
        raise VaultError("Focus the destination window, then return to Keyslot and try Auto-Type again.")
    return dict(backend="portal", target=token, title=title)


class PortalKeyboard:
    def __init__(self, valid, permissions=None):
        self.valid = valid
        self.connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self.session = None
        self.request_path = None
        self.closed = False
        self.pressed = []
        self.subscription = 0
        self.permissions = permissions
        self.ticket = None
        self.persist_mode = 0
        self.persistence_supported = False
        self.restore_token = ""

    def _check(self):
        if (not self.valid() or self.closed
                or (self.ticket is not None and not self.permissions.valid(self.ticket))):
            raise VaultError("Auto-type was cancelled.")

    def _call(self, method, parameters):
        self._check()
        return self.connection.call_sync(PORTAL_NAME, PORTAL_PATH, PORTAL_INTERFACE, method, parameters,
            None, Gio.DBusCallFlags.NONE, 5000, None)

    def _request(self, method, values=()):
        self._check()
        token = "keyslot" + uuid.uuid4().hex
        sender = self.connection.get_unique_name()[1:].replace(".", "_")
        path = f"/org/freedesktop/portal/desktop/request/{sender}/{token}"
        done = threading.Event()
        result = []
        def response(_connection, _sender, _path, _interface, _signal, parameters):
            result.append(parameters.unpack())
            done.set()
        subscription = self.connection.signal_subscribe(PORTAL_NAME, "org.freedesktop.portal.Request",
            "Response", path, None, Gio.DBusSignalFlags.NONE, response)
        self.request_path = path
        options = {"handle_token": GLib.Variant("s", token)}
        if method == "CreateSession":
            options["session_handle_token"] = GLib.Variant("s", token)
            self.session = f"/org/freedesktop/portal/desktop/session/{sender}/{token}"
            parameters = GLib.Variant("(a{sv})", (options,))
        elif method == "SelectDevices":
            options["types"] = GLib.Variant("u", 1)
            if self.ticket is not None and self.persistence_supported:
                options["persist_mode"] = GLib.Variant("u", self.persist_mode)
                if self.restore_token:
                    options["restore_token"] = GLib.Variant("s", self.restore_token)
            parameters = GLib.Variant("(oa{sv})", (self.session, options))
        else:
            parameters = GLib.Variant("(osa{sv})", (self.session, "", options))
        try:
            returned = self._call(method, parameters).unpack()[0]
            if returned != path:
                raise VaultError("The keyboard portal returned an unexpected request handle.")
            deadline = time.monotonic() + 90
            while not done.wait(0.05):
                self._check()
                if time.monotonic() >= deadline:
                    raise VaultError("Keyboard permission timed out.")
            self._check()
            status, data = result[0]
            if status != 0:
                raise VaultError("Keyboard permission was not granted.")
            return data
        finally:
            self.connection.signal_unsubscribe(subscription)
            self._close_path(path, "org.freedesktop.portal.Request")
            self.request_path = None
            if method == "SelectDevices":
                self.restore_token = ""

    def open(self):
        self._check()
        try:
            version = self.connection.call_sync(PORTAL_NAME, PORTAL_PATH, "org.freedesktop.DBus.Properties", "Get",
                GLib.Variant("(ss)", (PORTAL_INTERFACE, "version")), GLib.VariantType.new("(v)"),
                Gio.DBusCallFlags.NONE, 5000, None).unpack()[0]
        except GLib.Error:
            version = 0
        returned = self._request("CreateSession").get("session_handle")
        if returned != self.session:
            raise VaultError("The keyboard portal returned an invalid session.")
        self.subscription = self.connection.signal_subscribe(PORTAL_NAME, "org.freedesktop.portal.Session",
            "Closed", self.session, None, Gio.DBusSignalFlags.NONE, lambda *_: setattr(self, "closed", True))
        self.persistence_supported = type(version) is int and version >= 2
        if self.permissions:
            self.ticket, self.restore_token = self.permissions.begin(self.persistence_supported)
            self.persist_mode = self.ticket[2]
        self._request("SelectDevices")
        result = self._request("Start")
        devices = result.get("devices", 0)
        if type(devices) is not int or devices < 0 or devices & 1 == 0:
            raise VaultError("The portal did not grant keyboard access.")
        if self.ticket is not None and self.persistence_supported:
            self.permissions.granted(self.ticket, result.get("restore_token", ""))
        self._check()

    def _close_path(self, path, interface):
        try:
            self.connection.call_sync(PORTAL_NAME, path, interface, "Close", None,
                None, Gio.DBusCallFlags.NO_AUTO_START, 1000, None)
        except GLib.Error:
            pass

    def close(self):
        self.restore_token = ""
        self.ticket = None
        for key in reversed(self.pressed):
            try:
                self._notify(key, False, cleanup=True)
            except GLib.Error:
                pass
        self.pressed.clear()
        if self.subscription:
            self.connection.signal_unsubscribe(self.subscription)
            self.subscription = 0
        if self.session:
            self._close_path(self.session, "org.freedesktop.portal.Session")
            self.session = None
        self.closed = True

    def _notify(self, key, pressed, cleanup=False):
        if not cleanup:
            self._check()
        self.connection.call_sync(PORTAL_NAME, PORTAL_PATH, PORTAL_INTERFACE, "NotifyKeyboardKeysym",
            GLib.Variant("(oa{sv}iu)", (self.session, {}, key, int(pressed))), None,
            Gio.DBusCallFlags.NO_AUTO_START, 3000, None)

    def key(self, key, modifiers, guard):
        # Qt modifier flags map to XKB keysyms; modifiers are always released, including on cancellation.
        modifier_keys = [(0x02000000, 0xFFE1), (0x04000000, 0xFFE3),
                         (0x08000000, 0xFFE9), (0x10000000, 0xFFEB)]
        guard()
        try:
            for mask, symbol in modifier_keys:
                if modifiers & mask:
                    guard()
                    self.pressed.append(symbol)
                    self._notify(symbol, True)
            guard()
            self.pressed.append(key)
            self._notify(key, True)
            self._notify(key, False)
            self.pressed.pop()
        finally:
            for symbol in reversed(self.pressed):
                try:
                    self._notify(symbol, False, cleanup=True)
                except GLib.Error:
                    pass
            self.pressed.clear()


def execute_portal(session, target, token, pick, epoch, flow_valid=None):
    valid = lambda: (session.epoch == epoch and session.vault.unlocked and not session.jobs.closed
                     and (flow_valid is None or flow_valid()))
    keyboard = PortalKeyboard(valid, session.application.portal_permissions)
    plan = collections.deque()
    focus_token = GLib.Variant("(s)", (target["target"],))
    deadline = time.monotonic() + 120
    def guard():
        keyboard._check()
        if not valid() or time.monotonic() > deadline:
            raise VaultError("Auto-type was cancelled or took too long.")
        if not shell_call("Check", focus_token, "(b)")[0]:
            raise VaultError("Auto-type stopped because the destination window changed.")
    def wait(milliseconds):
        end = time.monotonic() + milliseconds / 1000
        while time.monotonic() < end:
            guard()
            time.sleep(min(0.05, max(0, end - time.monotonic())))
    try:
        keyboard.open()
        keyboard._check()
        if not shell_call("Focus", focus_token, "(b)")[0]:
            raise VaultError("The auto-type destination is no longer available.")
        # Resolve TOTP/placeholders after portal approval, immediately before typing.
        guard()
        result = session.vault.autotype_finish(token, pick, approved=True)
        plan.extend(result["plan"])
        wait(result["start_delay"])
        delay = 25
        while plan:
            guard()
            action = plan.popleft()
            if action["type"] == "key_delay":
                delay = action["milliseconds"]
            elif action["type"] == "delay":
                wait(action["milliseconds"])
            elif action["type"] == "clear":
                for key, modifiers in ((0xFF50, 0), (0xFF57, 0x02000000), (0xFF08, 0)):
                    keyboard.key(key, modifiers, guard)
                    wait(delay)
            elif action["type"] == "key":
                keyboard.key(action["keysym"], action["modifiers"], guard)
                wait(delay)
        return {"typed": True}
    except GLib.Error as exc:
        raise VaultError("The keyboard portal could not complete auto-type.") from exc
    finally:
        plan.clear()
        keyboard.close()
