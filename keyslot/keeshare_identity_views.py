"""Application-wide signing identity controls; private keys stay in a keyless native helper."""
from .i18n import tr as _tr
from pathlib import Path
import threading
from gi.repository import Pango

from .backend import VaultError
from .core_backend import Vault
from .database_views import Adw, Gtk, _dialog, _save


def show(session):
    if session.busy:
        session.toast(_tr("Wait for the current operation to finish"))
        return
    startup = session.application.startup
    path = Path(startup.directory) / "keyslot" / "keeshare-identity.xml"
    epoch = session.epoch
    dialog, header, box = _dialog(_tr("KeeShare Signing Identity"), width=520, height=430)
    state = {"closed": False, "working": False, "helper": None, "info": None}
    mutex = threading.Lock()
    group = Adw.PreferencesGroup(title=_tr("Signing Identity"),
        description=_tr("Used for legacy .kdbx.share exports. Current KeePassXC ignores signatures when importing."))
    signer = Adw.EntryRow(title=_tr("Signer Name"))
    fingerprint = Adw.ActionRow(title=_tr("Fingerprint"), use_markup=False)
    fingerprint_text = Gtk.Label(selectable=True, wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR,
                                 max_width_chars=32, css_classes=["monospace"], valign=Gtk.Align.CENTER)
    fingerprint.add_suffix(fingerprint_text)
    group.add(signer)
    group.add(fingerprint)
    box.append(group)
    status = Gtk.Label(label=_tr("Loading signing identity…"), wrap=True, xalign=0)
    box.append(status)
    regenerate = Gtk.Button(label=_tr("Generate Identity…"))
    box.append(regenerate)
    reload = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text=_tr("Reload Identity"), valign=Gtk.Align.CENTER)
    header.pack_start(reload)
    def current():
        return (not state["closed"] and not session.jobs.closed and session.epoch == epoch
                and session.application.startup is startup and session.active and dialog in session.dialogs)
    def controls():
        info = state["info"]
        group.set_sensitive(not state["working"] and info is not None)
        regenerate.set_sensitive(not state["working"] and info is not None)
        reload.set_sensitive(not state["working"])
        save.set_sensitive(not state["working"] and bool(info and info["exists"] and signer.get_text() != info["signer"]))
        dialog.set_can_close(False)
    def cancel(*_):
        with mutex:
            state["closed"] = True
            helper = state["helper"]
        if helper:
            helper.cancel()
        state["info"] = None
        signer.set_text("")
        fingerprint_text.set_text("")
    dialog._clear_sensitive_fields = cancel
    dialog.connect("closed", cancel)
    def close_attempt(*_):
        if state["working"]:
            session.toast(_tr("Wait for the identity update to finish"))
        else:
            cancel()
            dialog.force_close()
    dialog.connect("close-attempt", close_attempt)
    def request(operation="read", *, revision="", name=""):
        if not current() or state["working"]:
            return
        state["working"] = True
        status.remove_css_class("error")
        status.set_label(_tr("Loading signing identity…") if operation == "read" else _tr("Updating signing identity…"))
        controls()
        def work():
            helper = Vault(executable=session.vault.executable)
            generation = helper.generation
            try:
                with mutex:
                    if state["closed"]:
                        raise VaultError("The identity request was cancelled.")
                    state["helper"] = helper
                with helper.operation(generation):
                    return helper.keeshare_identity(path, operation, revision, name), ""
            except (VaultError, OSError, ValueError) as exc:
                return None, str(exc)
            finally:
                with mutex:
                    if state["helper"] is helper:
                        state["helper"] = None
                helper.lock()
        def finished(result):
            if not current():
                return
            state["working"] = False
            info, error = result
            if error:
                status.set_label(error)
                status.add_css_class("error")
            else:
                state["info"] = info
                signer.set_text(info["signer"] if info["exists"] else "Keyslot")
                fingerprint_text.set_text(info["fingerprint"] if info["exists"] else _tr("No signing identity has been generated"))
                regenerate.set_label(_tr("Regenerate Identity…") if info["exists"] else _tr("Generate Identity…"))
                if info["exists"]:
                    regenerate.add_css_class("destructive-action")
                else:
                    regenerate.remove_css_class("destructive-action")
                status.set_label(_tr("Changes saved") if operation != "read" else "")
            controls()
        if not session.run_job(work, finished):
            state["working"] = False
            status.set_label(_tr("Wait for the current operation, then reload the identity."))
            controls()
    def save_name(*_):
        if current() and not state["working"] and state["info"] and state["info"]["exists"]:
            request("rename", revision=state["info"]["revision"], name=signer.get_text())
    def generate(*_):
        if not current() or state["working"] or state["info"] is None:
            return
        info, name = dict(state["info"]), signer.get_text()
        if not info["exists"]:
            request("regenerate", revision=info["revision"], name=name)
            return
        alert = Adw.AlertDialog(heading=_tr("Replace Signing Identity?"),
            body=_tr("This replaces the current signing key. Legacy share exports will use the new identity on their next synchronization."))
        alert.add_response("cancel", _tr("Cancel"))
        alert.add_response("replace", _tr("Replace Identity"))
        alert.set_default_response("cancel")
        alert.set_close_response("cancel")
        alert.set_response_appearance("replace", Adw.ResponseAppearance.DESTRUCTIVE)
        def response(_alert, choice):
            if (choice == "replace" and current() and not state["working"] and state["info"]
                    and state["info"]["revision"] == info["revision"]):
                request("regenerate", revision=info["revision"], name=name)
        alert.connect("response", response)
        session.present_dialog(alert)
    save = _save(header, save_name)
    signer.connect("changed", lambda *_: controls())
    regenerate.connect("clicked", generate)
    reload.connect("clicked", lambda *_: request())
    controls()
    if session.present_dialog(dialog):
        request()
