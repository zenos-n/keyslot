"""Window actions after explicit entry copies and successful unlocks."""
import weakref
from gi.repository import Adw, Gio, GLib, Gtk
from .backend import VaultError

TARGET_PATH = "/com/neg_zero/keyslot/AutoType1"
TARGET_INTERFACE = "com.neg_zero.keyslot.AutoType1"


class WindowBehavior:
    def __init__(self, session):
        self.session = session
        self.request = None
        self.unlock_pending = None
        self.serial = 0
        self.closed = False
        if session.host_window:
            session.host_window.connect("notify::visible", self._window_changed)
            session.host_window.connect("notify::is-active", self._window_changed)

    def _window_changed(self, window, _property):
        if not window.get_visible() or not window.is_active():
            self.cancel()

    def cancel(self):
        self.serial += 1
        self.unlock_pending = None
        if self.request:
            self.request.cancel()
            self.request = None

    def close(self):
        self.closed = True
        self.cancel()

    def ready(self):
        session = self.session
        return not self.closed and not session.jobs.closed and session.active and session.vault.unlocked

    def minimize(self):
        if not self.ready():
            return
        self.cancel()
        session = self.session
        if session.application.startup.minimize_to_background and session.application.background_enabled:
            session.host_window.set_visible(False)
            session.application.emit_state()
        else:
            session.host_window.minimize()

    def unlocked(self):
        session = self.session
        if not session.application.startup.minimize_after_unlock or not self.ready():
            return
        self.cancel()
        self.unlock_pending = (session.epoch, session.view_epoch, session.vault.generation,
                               weakref.ref(session.vault.snapshot))
        self.finish_unlock()

    def finish_unlock(self):
        if self.unlock_pending is None:
            return
        session = self.session
        epoch, view_epoch, generation, snapshot = self.unlock_pending
        if (not self.ready() or not session.application.startup.minimize_after_unlock
                or epoch != session.epoch or view_epoch != session.view_epoch
                or generation != session.vault.generation or snapshot() is not session.vault.snapshot
                or session.window.snapshot is not session.vault.snapshot):
            self.unlock_pending = None
            return
        # Unlock dialogs may still be completing their closing animation.
        if session.dialogs or session.file_requests:
            return
        self.unlock_pending = None
        self.minimize()

    def copied(self):
        self.cancel()
        session = self.session
        settings = session.application.startup
        if not self.ready() or not session.host_window.is_active() or not settings.hide_window_on_copy:
            return
        if settings.minimize_on_copy:
            self.minimize()
        elif settings.drop_to_background_on_copy:
            self.lower()

    def lower(self):
        session = self.session
        app, window = session.application, session.host_window
        connection = app.get_dbus_connection()
        path, identifier = app.get_dbus_object_path(), window.get_id()
        if connection is None or not path or not identifier:
            session.toast("Could not identify this window for the GNOME companion")
            return
        self.request = request = Gio.Cancellable()
        serial, epoch, view_epoch = self.serial, session.epoch, session.view_epoch
        def completed(bus, result):
            try:
                accepted = bus.call_finish(result).unpack()[0]
            except GLib.Error:
                accepted = False
            if self.request is request:
                self.request = None
            if (serial != self.serial or request.is_cancelled() or not self.ready()
                    or epoch != session.epoch or view_epoch != session.view_epoch):
                return
            if not accepted:
                session.toast("Could not lower this window. Check that the updated Keyslot GNOME companion is enabled.")
        try:
            connection.call("org.gnome.Shell", TARGET_PATH, TARGET_INTERFACE, "Lower",
                GLib.Variant("(s)", (f"{path}/window/{identifier}",)), GLib.VariantType.new("(b)"),
                Gio.DBusCallFlags.NO_AUTO_START, 3000, request, completed)
        except GLib.Error:
            self.cancel()
            session.toast("Could not contact the Keyslot GNOME companion")


def preferences(session, page, background):
    settings = session.application.startup
    group = Adw.PreferencesGroup(title="Window Behavior",
        description="Minimize and hide actions also follow your automatic locking settings.")
    mode = Adw.ComboRow(title="After Copying Entry Data",
        subtitle="Lowering behind other windows requires the Keyslot GNOME companion",
        model=Gtk.StringList.new(["Keep Window Open", "Minimize", "Lower Behind Other Windows"]))
    def selected_mode():
        if not settings.hide_window_on_copy:
            return 0
        return 1 if settings.minimize_on_copy else 2 if settings.drop_to_background_on_copy else 0
    mode.set_selected(selected_mode())
    unlock = Adw.SwitchRow(title="Minimize After Unlocking", active=settings.minimize_after_unlock)
    hide = Adw.SwitchRow(title="Hide Instead of Minimize", active=settings.minimize_to_background,
        subtitle="Requires Run in Background; open Keyslot again to restore its window", sensitive=settings.background)
    links = Adw.SwitchRow(title="Minimize After Opening Links", active=settings.minimize_on_url)
    for row in (mode, unlock, hide, links):
        group.add(row)
    updating = False
    def changed(row, _property):
        nonlocal updating
        if updating:
            return
        if row is mode:
            selected = mode.get_selected()
            options = dict(hide_window_on_copy=selected != 0)
            if selected:
                options.update(minimize_on_copy=selected == 1, drop_to_background_on_copy=selected == 2)
        else:
            name = {unlock: "minimize_after_unlock", hide: "minimize_to_background", links: "minimize_on_url"}[row]
            options = {name: row.get_active()}
        try:
            settings.save(settings.remember, settings.login, settings.vault, **options)
            for item in session.application.sessions:
                item.windows.cancel()
        except (OSError, ValueError, VaultError) as exc:
            updating = True
            mode.set_selected(selected_mode())
            unlock.set_active(settings.minimize_after_unlock)
            hide.set_active(settings.minimize_to_background)
            links.set_active(settings.minimize_on_url)
            updating = False
            session.error(str(exc))
    mode.connect("notify::selected", changed)
    for row in (unlock, hide, links):
        row.connect("notify::active", changed)
    background.connect("notify::active", lambda *_: hide.set_sensitive(settings.background))
    page.add(group)
