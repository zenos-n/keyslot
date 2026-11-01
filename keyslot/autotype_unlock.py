"""One destination-bound unlock request; never a credential or typing approval."""
import os
import time
from collections import Counter
import weakref
from pathlib import Path
from gi.repository import Adw, GLib, Gtk
from . import autotype
from .application import clear_dialog_fields


class UnlockRequest:
    def __init__(self, session, allow_automatic, expires=None, expected_path=None):
        self.app = session.application
        self.owner = weakref.ref(session)
        self.path = expected_path if expected_path is not None else Path(session.path).resolve()
        self.epoch = session.epoch
        self.allow_automatic = allow_automatic
        self.dialog = self.target = self.result = None
        self.closing = weakref.WeakSet()
        self.resetting = self.switching = self.cancelled = False
        self.watch = self.timer = 0
        self.expires = time.monotonic() + 180 if expires is None else expires
        self.deadline = GLib.timeout_add(max(1, int((self.expires - time.monotonic()) * 1000)), self.expired)
        self.app.autotype_unlock = self

    def valid(self):
        session = self.owner()
        monitor = self.app.desktop_lock
        try:
            return bool(not self.cancelled and time.monotonic() < self.expires
                and self.app.autotype_unlock is self and not self.app.quitting
                and session and not session.jobs.closed and session in self.app.sessions
                and self.app.active_session is session and session.epoch == self.epoch
                and session.path and Path(session.path).resolve() == self.path
                and not (monitor and monitor.blocked))
        except OSError:
            return False

    def cancel(self, *, lock=True):
        if self.cancelled:
            return
        self.cancelled = True
        if self.app.autotype_unlock is self:
            self.app.autotype_unlock = None
        session = self.owner()
        if self.watch and session:
            session.host_window.disconnect(self.watch)
        self.watch = 0
        for name in ("timer", "deadline"):
            if handle := getattr(self, name):
                GLib.source_remove(handle)
                setattr(self, name, 0)
        dialogs = list(self.closing)
        if self.dialog:
            dialogs.append(self.dialog)
        self.dialog = self.target = self.result = None
        for dialog in dialogs:
            clear_dialog_fields(dialog)
            dialog.force_close()
        self.closing.clear()
        if lock and session and not session.jobs.closed:
            session.lock()

    def cancel_for(self, session, *, locking=False):
        if self.owner() is session and not self.resetting and not self.switching:
            self.cancel(lock=not locking)

    def expired(self):
        self.deadline = 0
        session = self.owner()
        self.cancel()
        if session and session.active:
            session.toast("Auto-Type unlock request expired. Invoke Auto-Type again.")
        return GLib.SOURCE_REMOVE

    def reset(self):
        if not self.valid():
            self.cancel()
            return False
        session = self.owner()
        if session.vault.unlocked:
            self.cancel()
            return False
        self.resetting = True
        try:
            session.lock()
            self.epoch = session.epoch
        finally:
            self.resetting = False
        return self.valid()

    def add_vault_choice(self, dialog, box):
        choices = []
        for session in self.app.sessions:
            if session.jobs.closed or session.vault.unlocked or not session.path:
                continue
            try:
                choices.append((weakref.ref(session), Path(session.path).resolve()))
            except OSError:
                continue
        if len(choices) < 2:
            return
        owner = self.owner()
        selected = next((index for index, (reference, _path) in enumerate(choices) if reference() is owner), None)
        if selected is None:
            return
        names = Counter(path.name for _reference, path in choices)
        labels = [path.name if names[path.name] == 1 else f"{path.name} · {path.parent}"
                  for _reference, path in choices]
        row = Adw.ComboRow(title="Vault", model=Gtk.StringList.new(labels), selected=selected,
                           subtitle=str(self.path.parent), use_subtitle=False, use_markup=False)
        group = Adw.PreferencesGroup()
        group.add(row)
        box.append(group)
        def changed(*_):
            index = row.get_selected()
            if index == selected:
                return
            # Restore the old form's owner before attempting a provider handoff.
            row.set_selected(selected)
            if self.owns(dialog) and index < len(choices):
                reference, path = choices[index]
                self.switch_vault(reference(), path)
        row.connect("notify::selected", changed)

    def switch_vault(self, session, path):
        owner = self.owner()
        if not self.valid() or not owner or owner.busy:
            return
        if (not session or session not in self.app.sessions or session.jobs.closed or session.vault.unlocked
                or session.busy or session.vault.finishing or session.file_requests
                or any(dialog is not session.unlock_prompt for dialog in session.dialogs)):
            owner.toast("That vault is no longer available to unlock. Finish its current operation and try again.")
            return
        try:
            if not session.path or Path(session.path).resolve() != path:
                owner.toast("That vault changed. Open it again before using Auto-Type.")
                return
        except OSError:
            owner.toast("That vault path is no longer available.")
            return
        target, automatic, expires = self.target, self.allow_automatic, self.expires
        self.cancel()
        self.app.select_session(session, activate=False)
        request(session, allow_automatic=automatic, target=target, expires=expires, captured=True, expected_path=path)

    def present(self, dialog):
        if not self.valid():
            clear_dialog_fields(dialog)
            self.cancel()
            return False
        self.dialog = dialog
        dialog.set_title("Unlock for Auto-Type")
        dialog.connect("closed", lambda *_: self.cancel() if self.dialog is dialog else None)
        self.owner().present_unlock_prompt(dialog)
        return not self.cancelled

    def owns(self, dialog):
        return self.valid() and self.dialog is dialog

    def release(self, dialog):
        if self.dialog is dialog:
            self.dialog = None
            self.closing.add(dialog)

    def open(self, target=None):
        if not self.valid():
            self.cancel(lock=False)
            return
        self.target = target
        session = self.owner()
        session.pending_unlock = None
        session.dismiss_unlock_prompt()
        self.switching = True
        try:
            self.app.select_session(session, activate=False)
        finally:
            self.switching = False
        self.watch = session.host_window.connect("notify::visible", lambda window, _prop:
            self.cancel() if not window.get_visible() else None)
        session._unlock_dialog(self.path, resume=self)

    def finished(self, snapshot):
        session = self.owner()
        if (not self.valid() or not session.vault.unlocked or session.vault.snapshot is not snapshot
                or session.vault.path != self.path):
            self.cancel()
            return
        self.result = (session.vault.identity, session.vault.generation, weakref.ref(snapshot))
        self.timer = GLib.timeout_add(50, self.resume)

    def resume(self):
        session = self.owner()
        if not self.valid() or not self.result:
            self.timer = 0
            self.cancel()
            return GLib.SOURCE_REMOVE
        identity, generation, snapshot = self.result
        if (not session.vault.unlocked or session.vault.identity is not identity
                or session.vault.generation != generation or session.vault.snapshot is not snapshot()):
            self.timer = 0
            self.cancel()
            return GLib.SOURCE_REMOVE
        if session.busy or session.dialogs or session.file_requests:
            return GLib.SOURCE_CONTINUE
        self.timer = 0
        target = self.target
        automatic = self.allow_automatic
        self.cancel(lock=False)
        from .autotype_views import choose
        choose(session, target=target, allow_automatic=automatic, temporary=True)
        return GLib.SOURCE_REMOVE


def request(session, *, allow_automatic=True, global_shortcut=False, target=None, expires=None, captured=False, expected_path=None):
    app = session.application
    if global_shortcut and any(item.host_window.is_active() for item in app.sessions):
        return
    if app.autotype_unlock or app.autotype_flow:
        session.toast("Auto-Type is already in progress")
        return
    if (not session.path or session.busy or session.vault.finishing or session.file_requests
            or any(dialog is not session.unlock_prompt for dialog in session.dialogs)):
        app.select_session(session)
        session.toast("Open a vault and finish the current operation before using Auto-Type")
        return
    if app.desktop_lock and app.desktop_lock.blocked:
        return
    if expires is not None and time.monotonic() >= expires:
        session.toast("Auto-Type unlock request expired. Invoke Auto-Type again.")
        return
    if app.active_session is None:
        app.active_session, app.window = session, session.host_window
    try:
        pending = UnlockRequest(session, allow_automatic, expires, expected_path)
    except OSError:
        session.error("The vault path is no longer available. Open it again before using Auto-Type.")
        return
    if captured:
        pending.open(target)
    elif os.environ.get("XDG_SESSION_TYPE") == "wayland":
        def failed(message):
            pending.cancel()
            app.select_session(session, activate=False)
            session.error(message)
        if not session.run_job(autotype.capture_target, pending.open, failed):
            pending.cancel()
    else:
        # X11 keeps its explicit native destination chooser after the unlock.
        pending.open()
