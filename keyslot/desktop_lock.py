"""Observe desktop events; only explicit policy changes may relax automatic locks."""
import os
import re
import math
import time
from gi.repository import Gdk, Gio, GLib

LOGIN = "org.freedesktop.login1"
MANAGER = "/org/freedesktop/login1"
SESSION = LOGIN + ".Session"
PROPERTIES = "org.freedesktop.DBus.Properties"
SCREENSAVER = "org.gnome.ScreenSaver"
SCREEN_PATH = "/org/gnome/ScreenSaver"


class DesktopLock:
    def __init__(self, app):
        self.app = app
        self.closed = False
        self.request = Gio.Cancellable()
        self.subscriptions, self.session_subscriptions = [], []
        self.screen_locked = self.session_active = None
        self.sleeping = False
        self.screen_serial = self.sleep_serial = self.session_generation = self.active_serial = 0
        self.session_path = ""
        self.system = None
        self.timer = 0

    @property
    def blocked(self):
        settings = self.app.startup
        return ((settings.lock_on_screen and (self.screen_locked is True or self.sleeping))
                or (settings.lock_on_user_switch and self.session_active is False))

    def _subscribe(self, bus, sender, interface, signal, path, callback, arg=None, *, session=False):
        token = bus.signal_subscribe(sender, interface, signal, path, arg, Gio.DBusSignalFlags.NONE, callback)
        (self.session_subscriptions if session else self.subscriptions).append((bus, token))

    def _call(self, bus, name, path, interface, method, args, result_type, done):
        def finished(connection, result):
            try:
                reply = connection.call_finish(result).unpack()
            except GLib.Error:
                reply = None
            if not self.closed:
                done(reply)
        bus.call(name, path, interface, method, args, GLib.VariantType.new(result_type),
                 Gio.DBusCallFlags.NONE, 5000, self.request, finished)

    def start(self):
        self._subscribe(self.app.connection, SCREENSAVER, SCREENSAVER, "ActiveChanged", SCREEN_PATH, self._screen_changed)
        self._subscribe(self.app.connection, "org.freedesktop.DBus", "org.freedesktop.DBus", "NameOwnerChanged",
                        "/org/freedesktop/DBus", self._screen_owner, SCREENSAVER)
        self._query_screen()
        Gio.bus_get(Gio.BusType.SYSTEM, self.request, self._system_ready)

    def _screen_changed(self, _bus, _sender, _path, _interface, _signal, params):
        value = params.unpack()
        if self.closed or len(value) != 1 or type(value[0]) is not bool:
            return
        self.screen_serial += 1
        self.screen_locked = value[0]
        self.refresh_policy()

    def _query_screen(self):
        self.screen_serial += 1
        serial = self.screen_serial
        def queried(reply):
            if serial == self.screen_serial and reply and type(reply[0]) is bool:
                self.screen_locked = reply[0]
                self.refresh_policy()
        self._call(self.app.connection, SCREENSAVER, SCREEN_PATH, SCREENSAVER, "GetActive", None, "(b)", queried)

    def _screen_owner(self, _bus, _sender, _path, _interface, _signal, params):
        if self.closed:
            return
        _name, old, new = params.unpack()
        self.screen_serial += 1
        self.screen_locked = None
        if old and self.app.startup.lock_on_screen:
            self.app.lock()
        if new:
            self._query_screen()

    def _system_ready(self, _source, result):
        try:
            system = Gio.bus_get_finish(result)
        except GLib.Error:
            return
        if self.closed:
            return
        self.system = system
        self._subscribe(system, LOGIN, LOGIN + ".Manager", "PrepareForSleep", MANAGER, self._sleep)
        self._subscribe(system, LOGIN, LOGIN + ".Manager", "SessionRemoved", MANAGER, self._session_removed)
        self._subscribe(system, "org.freedesktop.DBus", "org.freedesktop.DBus", "NameOwnerChanged",
                        "/org/freedesktop/DBus", self._login_owner, LOGIN)
        self._query_sleep()
        self._resolve_session()

    def _sleep(self, _bus, _sender, _path, _interface, _signal, params):
        value = params.unpack()
        if not self.closed and len(value) == 1 and type(value[0]) is bool:
            self.sleep_serial += 1
            self.sleeping = value[0]
            self.refresh_policy()
            if not self.sleeping:
                self._query_screen()

    def _query_sleep(self):
        self.sleep_serial += 1
        serial = self.sleep_serial
        def queried(reply):
            if serial == self.sleep_serial and reply and type(reply[0]) is bool:
                self.sleeping = reply[0]
                self.refresh_policy()
        self._call(self.system, LOGIN, MANAGER, PROPERTIES, "Get",
                   GLib.Variant("(ss)", (LOGIN + ".Manager", "PreparingForSleep")), "(v)", queried)

    def _login_owner(self, _bus, _sender, _path, _interface, _signal, params):
        if self.closed:
            return
        _name, old, new = params.unpack()
        self._clear_session()
        self.sleep_serial += 1
        self.sleeping = False
        if old and (self.app.startup.lock_on_user_switch or self.app.startup.lock_on_screen):
            self.app.lock()
        if new:
            self._query_sleep()
            self._resolve_session()

    def _clear_session(self):
        self.session_generation += 1
        self.session_path = ""
        self.session_active = None
        for bus, token in self.session_subscriptions:
            bus.signal_unsubscribe(token)
        self.session_subscriptions.clear()

    def _resolve_session(self):
        self._clear_session()
        generation = self.session_generation
        def lookup(method, args, fallback=None):
            def resolved(reply):
                if generation != self.session_generation:
                    return
                if not reply or not reply[0].startswith(MANAGER + "/session/"):
                    if fallback:
                        fallback()
                    return
                path = reply[0]
                def inspected(values):
                    if generation != self.session_generation:
                        return
                    properties = values[0] if values else {}
                    user = properties.get("User", ())
                    if (not isinstance(user, (tuple, list)) or len(user) != 2 or user[0] != os.getuid()
                        or properties.get("Class") not in {"user", "user-early", "user-light", "user-early-light"}):
                        if fallback:
                            fallback()
                        return
                    self.session_path = path
                    self._subscribe(self.system, LOGIN, SESSION, "Lock", path, self._session_lock, session=True)
                    self._subscribe(self.system, LOGIN, PROPERTIES, "PropertiesChanged", path, self._active_changed, SESSION, session=True)
                    self._query_active()
                self._call(self.system, LOGIN, path, PROPERTIES, "GetAll", GLib.Variant("(s)", (SESSION,)), "(a{sv})", inspected)
            self._call(self.system, LOGIN, MANAGER, LOGIN + ".Manager", method, args, "(o)", resolved)
        def by_pid():
            lookup("GetSessionByPID", GLib.Variant("(u)", (os.getpid(),)))
        identifier = os.environ.get("XDG_SESSION_ID", "")
        if re.fullmatch(r"[a-zA-Z0-9_-]{1,256}", identifier):
            lookup("GetSession", GLib.Variant("(s)", (identifier,)), by_pid)
        else:
            by_pid()

    def _query_active(self):
        self.active_serial += 1
        serial, generation, path = self.active_serial, self.session_generation, self.session_path
        def queried(reply):
            if generation == self.session_generation and serial == self.active_serial and reply:
                value = reply[0].get("Active")
                if type(value) is bool:
                    self.session_active = value
                    self.refresh_policy()
        self._call(self.system, LOGIN, path, PROPERTIES, "GetAll", GLib.Variant("(s)", (SESSION,)), "(a{sv})", queried)

    def _active_changed(self, _bus, _sender, path, _interface, _signal, params):
        if self.closed or path != self.session_path:
            return
        interface, changed, invalidated = params.unpack()
        if interface != SESSION:
            return
        if type(changed.get("Active")) is bool:
            self.active_serial += 1
            self.session_active = changed["Active"]
            self.refresh_policy()
        elif "Active" in invalidated:
            self._query_active()

    def _session_lock(self, _bus, _sender, path, _interface, _signal, _params):
        if not self.closed and path == self.session_path and self.app.startup.lock_on_screen:
            self.app.lock()

    def _session_removed(self, _bus, _sender, _path, _interface, _signal, params):
        if not self.closed and params.unpack()[1] == self.session_path:
            self.active_serial += 1
            self.session_active = False
            self.refresh_policy()

    def refresh_policy(self):
        if self.closed:
            return
        if not self.app.startup.lock_on_minimize:
            self.cancel_delayed()
        if self.blocked:
            self.app.lock()

    def cancel_delayed(self):
        if self.timer:
            GLib.source_remove(self.timer)
            self.timer = 0

    def minimized(self):
        if self.closed or self.app.quitting or not self.app.startup.lock_on_minimize:
            return
        remaining = 0
        for session in self.app.sessions:
            if session.clipboard_provider and session.window.get_clipboard().get_content() == session.clipboard_provider:
                remaining = max(remaining, session.clipboard_deadline - time.monotonic())
        delay = min(20, max(1, math.ceil(remaining)))
        self.cancel_delayed()
        def expired():
            self.timer = 0
            if not self.closed and self.app.startup.lock_on_minimize:
                self.app.lock()
            return GLib.SOURCE_REMOVE
        self.timer = GLib.timeout_add(delay * 1000, expired)

    def watch_window(self, window):
        state = {"visible": window.get_visible(), "minimized": False, "surface": None, "handler": 0}
        def hidden(*_):
            visible = window.get_visible()
            if state["visible"] and not visible and window.session and not window.session.jobs.closed:
                self.minimized()
            state["visible"] = visible
        def changed(surface, _property):
            minimized = bool(surface.get_state() & Gdk.ToplevelState.MINIMIZED)
            if minimized and not state["minimized"] and window.session and not window.session.jobs.closed:
                self.minimized()
            state["minimized"] = minimized
        def realized(*_):
            surface = window.get_surface()
            if isinstance(surface, Gdk.Toplevel):
                state["surface"] = surface
                state["handler"] = surface.connect("notify::state", changed)
                changed(surface, None)
        def unrealized(*_):
            if state["surface"] and state["handler"]:
                state["surface"].disconnect(state["handler"])
            state.update(surface=None, handler=0, minimized=False)
        window.connect("notify::visible", hidden)
        window.connect("realize", realized)
        window.connect("unrealize", unrealized)
        if window.get_realized():
            realized()

    def close(self):
        self.closed = True
        self.cancel_delayed()
        self.request.cancel()
        self._clear_session()
        for bus, token in self.subscriptions:
            bus.signal_unsubscribe(token)
        self.subscriptions.clear()
