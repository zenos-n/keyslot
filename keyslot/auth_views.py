"""Session-only Polkit unlock without credential material in GTK."""
from pathlib import Path
from gi.repository import Adw, Gtk
from .database_views import _dialog
from .backend import VaultError


def unlock(session, path, allow_recovery=False, resume=None):
    if resume:
        if not resume.reset():
            return
    else:
        session.lock()
    epoch = session.epoch
    dialog, _header, box = _dialog("Unlock with System Authentication", width=460, height=400)
    dialog.set_can_close(False)
    state = {"closed": False, "working": False}
    box.append(Gtk.Image(icon_name="changes-prevent-symbolic", pixel_size=64))
    box.append(Gtk.Label(label=Path(path).name, css_classes=["title-2"], wrap=True))
    if resume:
        resume.add_vault_choice(dialog, box)
    box.append(Gtk.Label(label="Authenticate using your system's agent. It may offer your login password or configured biometrics. "
                         "A hardware key may still require a touch afterward.", xalign=0, wrap=True))
    status = Gtk.Label(wrap=True, xalign=0)
    box.append(status)
    spinner = Gtk.Spinner(spinning=False, halign=Gtk.Align.CENTER)
    box.append(spinner)
    system = Gtk.Button(label="Authenticate and Unlock", css_classes=["suggested-action", "pill"])
    master = Gtk.Button(label="Use Master Password", css_classes=["pill"])
    short = Gtk.Button(label="Use Short Password", css_classes=["pill"],
                       visible=bool(session.quick_blob and Path(path).resolve() == session.quick_path))
    cancel = Gtk.Button(label="Cancel", css_classes=["pill"])
    for control in (system, master, short, cancel):
        box.append(control)
    def current():
        return (not state["closed"] and session.epoch == epoch and not session.jobs.closed
                and session.unlock_prompt is dialog and (resume is None or resume.owns(dialog)))
    def clear(*_):
        state["closed"] = True
    def close(*_):
        if state["closed"]:
            return
        clear()
        if state["working"] and session.epoch == epoch:
            session.lock()
        dialog.force_close()
    def submit(*_):
        if not current() or session.busy or state["working"]:
            return
        state["working"] = True
        system.set_sensitive(False); master.set_sensitive(False); short.set_sensitive(False)
        spinner.set_spinning(True)
        status.set_label("Waiting for system authentication…")
        def operation():
            try:
                return session.vault.system_unlock(path, allow_recovery=allow_recovery), ""
            except (VaultError, OSError, ValueError) as exc:
                return None, str(exc)
        def finished(result):
            if not current():
                return
            state["working"] = False
            spinner.set_spinning(False)
            snapshot, error = result
            if snapshot is None:
                status.set_label(error)
                system.set_sensitive(session.vault.has_system_auth(path)); master.set_sensitive(True); short.set_sensitive(True)
                return
            clear()
            if resume:
                resume.release(dialog)
            dialog.force_close()
            session.show_unlocked(snapshot, resume=resume)
        if not session.run_job(operation, finished) and resume:
            resume.cancel()
    def fallback(use_short=False):
        if not current() or state["working"]:
            return
        clear()
        if resume:
            resume.release(dialog)
        dialog.force_close()
        if use_short:
            session._quick_unlock_dialog(path, allow_recovery=allow_recovery, resume=resume)
        else:
            session._unlock_dialog(path, use_quick=False, recovery_checked=allow_recovery, resume=resume)
    system.connect("clicked", submit)
    master.connect("clicked", lambda *_: fallback())
    short.connect("clicked", lambda *_: fallback(True))
    cancel.connect("clicked", close)
    dialog.connect("close-attempt", close)
    dialog.connect("closed", clear)
    dialog._clear_sensitive_fields = close
    if resume:
        resume.present(dialog)
    else:
        session.present_unlock_prompt(dialog)
