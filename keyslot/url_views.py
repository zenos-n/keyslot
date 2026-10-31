"""Entry URL activation with native command approval and sealed linked-vault handoff."""
from dataclasses import dataclass
from pathlib import Path
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk
from .backend import VaultError


@dataclass(repr=False)
class Pending:
    epoch: int
    generation: int
    identity: object
    ticket: dict = None
    dialog: object = None
    request: object = None
    timer: int = 0
    target: object = None
    target_generation: int = 0
    target_identity: object = None
    target_owned: bool = False
    created: bool = False


class UrlController:
    def __init__(self, session):
        self.session = session
        self.pending = None

    def valid(self, item, active=False):
        session = self.session
        return (self.pending is item and not session.jobs.closed and session.vault.unlocked
                and session.epoch == item.epoch and session.vault.generation == item.generation
                and session.vault.identity is item.identity
                and (not active or session.active or session.application.active_session is item.target))

    def clear(self):
        if self.pending:
            self.drop(self.pending)

    def _cancel_native(self, item):
        session = self.session
        if not item.ticket or session.jobs.closed:
            return
        def cancel():
            try:
                with session.vault.operation(item.generation):
                    if session.vault.generation == item.generation and session.vault.identity is item.identity:
                        session.vault.url_cancel(item.ticket["token"])
            except (VaultError, OSError):
                pass
        session.jobs.executor.submit(cancel)

    def drop(self, item, cancel_target=True):
        if self.pending is not item:
            return
        self.pending = None
        if item.timer:
            GLib.source_remove(item.timer)
            item.timer = 0
        if item.request:
            item.request.cancel()
        if item.dialog and item.dialog in self.session.dialogs:
            item.dialog.set_body("")
            item.dialog.force_close()
        self._cancel_native(item)
        target = item.target
        if cancel_target and target and not target.jobs.closed:
            owns = (target.vault.generation == item.target_generation
                    and (item.target_owned or (target.vault.identity is item.target_identity and not target.busy)))
            owns = owns or (item.created and not target.host_window.get_visible() and not target.vault.unlocked
                            and (item.target_owned or not target.busy))
            if owns:
                target.lock()
                if item.created and not target.host_window.get_visible():
                    self.session.application.close_session(target)
                    target.host_window.destroy()

    def fail(self, item, message):
        if self.pending is item:
            self.drop(item)
            self.session.error(message)

    def open(self, entry, override=False):
        session = self.session
        if session.busy or not session.active or not session.vault.unlocked:
            return
        self.clear()
        item = Pending(session.epoch, session.vault.generation, session.vault.identity)
        self.pending = item
        def expired():
            item.timer = 0
            self.fail(item, "Opening this link expired. Choose the entry again.")
            return GLib.SOURCE_REMOVE
        item.timer = GLib.timeout_add_seconds(120, expired)
        def prepared(ticket):
            if not self.valid(item, active=True):
                if self.pending is item:
                    item.ticket = ticket
                    self.drop(item)
                return
            item.ticket = ticket
            if ticket["kind"] == "database":
                self._linked(item)
            elif ticket["kind"] == "command" and not ticket["remembered"]:
                self._review(item)
            else:
                self._finish(item)
        if not session.run_job(lambda: session.vault.url_prepare(entry, override), prepared,
                               lambda message: self.fail(item, message)):
            self.drop(item)

    def _review(self, item):
        alert = Adw.AlertDialog(heading="Run This Command?", body=item.ticket["display"], body_use_markup=False)
        remember = Gtk.CheckButton(label="Always allow this command for this entry")
        alert.set_extra_child(remember)
        alert.add_response("cancel", "Cancel")
        alert.add_response("run", "Run")
        alert.set_close_response("cancel")
        alert.set_default_response("cancel")
        alert.set_response_appearance("run", Adw.ResponseAppearance.SUGGESTED)
        item.dialog = alert
        def response(_alert, choice):
            item.dialog = None
            if choice != "run":
                self.drop(item)
            elif self.valid(item, active=True):
                self._finish(item, approved=True, remember=remember.get_active())
            else:
                self.drop(item)
        alert.connect("response", response)
        self.session.present_dialog(alert)

    def _finish(self, item, approved=False, remember=False):
        if not self.valid(item, active=True):
            self.drop(item)
            return
        def finished(value):
            if not self.valid(item):
                return
            if value["kind"] == "command":
                self.drop(item)
                self.session.window.show_vault(self.session.vault.snapshot)
                if value["launched"]:
                    self._minimize()
                else:
                    self.session.error(value["error"])
                return
            if not self.valid(item, active=True):
                self.drop(item)
                return
            request = Gio.Cancellable()
            item.request = request
            launcher = Gtk.UriLauncher.new(value["uri"])
            def launched(sender, result):
                try:
                    success = sender.launch_finish(result)
                except GLib.Error as exc:
                    if not self.valid(item):
                        return
                    self.drop(item)
                    cancelled = (exc.matches(Gio.io_error_quark(), Gio.IOErrorEnum.CANCELLED)
                                 or exc.matches(Gtk.dialog_error_quark(), Gtk.DialogError.DISMISSED)
                                 or exc.matches(Gtk.dialog_error_quark(), Gtk.DialogError.CANCELLED))
                    if not cancelled:
                        self.session.error("The link could not be opened. Check that an application is available for this type of link.")
                    return
                if self.valid(item):
                    self.drop(item)
                    if success:
                        self._minimize()
                    else:
                        self.session.error("No application opened this link.")
            launcher.launch(self.session.host_window, request, launched)
        if not self.session.run_job(lambda: self.session.vault.url_finish(item.ticket["token"], approved, remember),
                                    finished, lambda message: self.fail(item, message)):
            self.fail(item, "The vault is busy. Open the entry again.")

    def _minimize(self):
        session = self.session
        if session.active and session.application.startup.minimize_on_url:
            if session.application.background_enabled:
                session.host_window.set_visible(False)
                session.application.emit_state()
            else:
                session.host_window.minimize()

    def _linked(self, item):
        app = self.session.application
        path = Path(item.ticket["path"])
        target = next((session for session in app.sessions if session.path and session.path.resolve() == path), None)
        if target and target.vault.unlocked:
            self.drop(item)
            app.select_session(target)
            return
        if target and (target.busy or target.dialogs or target.jobs.closed):
            self.fail(item, "Finish opening or editing the destination vault first.")
            return
        if target is None:
            target = app.new_window(present=False)
            item.created = True
        item.target = target
        target.requested_path = path
        item.target_generation = target.vault.generation
        item.target_identity = target.vault.identity
        item.target_owned = True
        def operation():
            try:
                if not self.valid(item):
                    raise VaultError("The linked-vault opening was cancelled.")
                return True, target.vault.url_offer(item.ticket)
            except (VaultError, OSError) as exc:
                return False, str(exc)
        def offered(result):
            item.target_owned = False
            item.target_identity = target.vault.identity
            if not self.valid(item, active=True):
                self.drop(item)
                return
            ok, value = result
            if not ok:
                self.fail(item, value)
                return
            def sealed(envelope):
                if not self.valid(item, active=True):
                    self.drop(item)
                    return
                if (target.busy or target.jobs.closed or target.dialogs or target.vault.generation != item.target_generation
                        or target.vault.identity is not item.target_identity or target.vault.unlocked):
                    self.fail(item, "The destination changed. Open the link again.")
                    return
                item.target_owned = True
                def accept():
                    try:
                        if not self.valid(item):
                            raise VaultError("The linked-vault opening was cancelled.")
                        return True, target.vault.url_accept(envelope)
                    except (VaultError, OSError) as exc:
                        return False, str(exc)
                def accepted(result):
                    item.target_owned = False
                    if not self.valid(item):
                        return
                    ok, snapshot = result
                    if not ok:
                        # Keep the target window for manual credentials; sealed credentials never enter GTK.
                        self.drop(item, cancel_target=False)
                        target.pending_unlock = (str(path), False, None)
                        app.select_session(target)
                        target.error(snapshot)
                        return
                    self.drop(item, cancel_target=False)
                    target.pending_unlock = None
                    target.window.show_vault(snapshot)
                    try:
                        app.startup.opened(path)
                    except (OSError, ValueError) as exc:
                        target.error(str(exc))
                    app.select_session(target)
                if not target.run_job(accept, accepted):
                    item.target_owned = False
                    self.fail(item, "The destination is busy. Open the link again.")
            if not self.session.run_job(lambda: self.session.vault.url_finish(item.ticket["token"], destination=value),
                                        sealed, lambda message: self.fail(item, message)):
                self.fail(item, "The source is busy. Open the link again.")
        if not target.run_job(operation, offered):
            item.target_owned = False
            self.fail(item, "The destination is busy. Open the link again.")
