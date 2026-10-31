"""Monitor the encrypted file without replacing modal drafts or extending idle time."""
from gi.repository import Adw, Gio, GLib

from .core_backend import EngineError


ATTRIBUTES = "standard::type,standard::size,time::modified,time::modified-usec,time::changed,time::changed-usec,unix::device,unix::inode"


class FileChanges:
    def __init__(self, session):
        self.session = session
        self.path = self.monitor = self.query = self.notice = None
        self.timer = self.poll = self.epoch = self.serial = 0
        self.pending = self.running = self.force = self.force_query = self.waiting = False
        self.observed = self.failed_serial = None

    def sync(self):
        vault = self.session.vault
        if not vault.unlocked:
            self.stop()
            return
        if self.path != vault.path:
            self.stop()
            self.path = vault.path
            parent = Gio.File.new_for_path(str(self.path.parent))
            try:
                self.monitor = parent.monitor_directory(Gio.FileMonitorFlags.WATCH_MOVES, None)
                self.monitor.connect("changed", self._event)
            except GLib.Error:
                self.monitor = None
            self.poll = GLib.timeout_add_seconds(5, self._poll)
            self._metadata(force=True)
        self.resume()

    def stop(self):
        self.epoch += 1
        if self.monitor:
            self.monitor.cancel()
        if self.query:
            self.query.cancel()
        for source in (self.timer, self.poll):
            if source:
                GLib.source_remove(source)
        self.path = self.monitor = self.query = None
        self.timer = self.poll = 0
        self.pending = self.running = self.force = self.force_query = self.waiting = False
        self.observed = self.failed_serial = None
        self._dismiss()

    def _event(self, _monitor, file, other, _event):
        if self.path and any(item and item.get_path() == str(self.path) for item in (file, other)):
            self._metadata(force=True)

    def _poll(self):
        if not self.path:
            self.poll = 0
            return GLib.SOURCE_REMOVE
        self._metadata()
        self.resume()
        return GLib.SOURCE_CONTINUE

    def _metadata(self, force=False):
        self.force_query |= force
        if not self.path or self.query:
            return
        self.query = Gio.Cancellable()
        epoch = self.epoch
        def received(file, result):
            if epoch != self.epoch:
                return
            self.query = None
            try:
                info = file.query_info_finish(result)
                stamp = tuple(info.get_attribute_as_string(name) for name in ATTRIBUTES.split(","))
            except GLib.Error as exc:
                if exc.matches(Gio.io_error_quark(), Gio.IOErrorEnum.CANCELLED):
                    return
                stamp = ("unavailable", exc.code)
            if self.force_query or stamp != self.observed:
                self.serial += 1
                self.pending = True
                self.waiting = False
            self.observed, self.force_query = stamp, False
            self.resume()
        Gio.File.new_for_path(str(self.path)).query_info_async(ATTRIBUTES, Gio.FileQueryInfoFlags.NONE,
            GLib.PRIORITY_LOW, self.query, received)

    def resume(self):
        if self.path and self.pending and not self.timer and not self.running:
            self.timer = GLib.timeout_add(400, self._check)

    def _check(self):
        self.timer = 0
        session = self.session
        if not self.path or not self.pending or self.running or not session.vault.unlocked:
            return GLib.SOURCE_REMOVE
        if session.jobs.busy or session.dialogs or session.file_requests:
            return GLib.SOURCE_REMOVE
        reload = self.force or (self.waiting and session.application.startup.auto_reload)
        if not self.force and (self.failed_serial == self.serial or (self.waiting and not reload)):
            return GLib.SOURCE_REMOVE
        serial = self.serial
        self.running = True
        def perform():
            try:
                return session.vault.watch_file(reload=reload)
            except EngineError as exc:
                return {"state": "failed", "message": str(exc)}
        def checked(data):
            self.running = self.force = False
            state = data["state"]
            if state in ("unchanged", "reloaded"):
                self.pending = self.serial != serial
                self.waiting = False
                self.failed_serial = None
                self._dismiss()
                if state == "reloaded":
                    session.view_epoch += 1
                    session.totp.clear()
                    session.urls.clear()
                    session.icons.clear()
                    session.clear_clipboard()
                    session.window.show_vault(data["snapshot"])
                    session.toast("Vault updated")
            elif state == "changed":
                self.waiting = True
                if not session.application.startup.auto_reload:
                    self._show("Vault changed elsewhere", "Reload", self.reload)
            else:
                self.failed_serial = serial
                self._show("Vault file is unavailable" if state == "unavailable" else "Vault could not be reloaded",
                           "Save Copy", self.save_copy)
            self.resume()
        def failed(_message):
            self.running = self.force = False
            self.failed_serial = serial
            self._show("Vault could not be reloaded", "Save Copy", self.save_copy)
        # Checks are passive; only an actual reload reserves the foreground slot
        # so a form cannot open halfway through it. Neither operation touches idle time.
        if not session.jobs.run(perform, checked, failed, interactive=reload):
            self.running = False
        return GLib.SOURCE_REMOVE

    def reload(self):
        self.session.touch()
        self.force = self.pending = True
        self.serial += 1
        self.resume()

    def save_copy(self):
        from . import database_views
        self.session.touch()
        database_views.save_copy(self.session)

    def refreshed(self):
        self.serial += 1
        self.failed_serial = None
        self.waiting = self.force = False
        self.pending = True
        self._dismiss()
        self.resume()

    def _dismiss(self):
        if self.notice:
            self.notice.dismiss()
            self.notice = None

    def _show(self, title, label, action):
        if self.notice and self.notice.get_title() == title:
            return
        self._dismiss()
        notice = Adw.Toast(title=title, button_label=label, timeout=0)
        notice.connect("button-clicked", lambda *_: action())
        def dismissed(item):
            if self.notice is item:
                self.notice = None
        notice.connect("dismissed", dismissed)
        self.notice = notice
        self.session.window.toasts.add_toast(notice)
