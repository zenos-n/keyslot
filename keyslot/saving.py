"""Explicit saves, closing decisions and encrypted interrupted-save recovery."""
from .i18n import tr as _tr, trf as _trf
import os
from pathlib import Path

from gi.repository import Adw, GLib


def before_close(session, done, cancelled=lambda: None):
    if not session.vault.unlocked or not session.vault.snapshot.modified:
        done()
        return
    if session.busy:
        session.toast(_tr("Wait for the current operation to finish"))
        cancelled()
        return
    def save():
        if not session.save(done=done, failed=lambda message: (session.error(message), cancelled())):
            cancelled()
    if session.application.startup.auto_save_on_exit:
        save()
        return
    dialog = Adw.AlertDialog(heading=_tr("Save Changes?"),
        body=_tr("This vault has unsaved changes. Save them before closing or locking?"))
    dialog.add_response("cancel", _tr("Cancel"))
    dialog.add_response("discard", _tr("Discard"))
    dialog.add_response("save", _tr("Save"))
    dialog.set_default_response("save")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("discard", Adw.ResponseAppearance.DESTRUCTIVE)
    dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
    handled = [False]
    def selected(_dialog, response):
        handled[0] = True
        if response == "save":
            save()
        elif response == "discard":
            session.vault.discard_on_stop = True
            done()
        else:
            cancelled()
    dialog.connect("response", selected)
    def closed(*_):
        def finish():
            if not handled[0]:
                cancelled()
            return False
        GLib.idle_add(finish)
    dialog.connect("closed", closed)
    if not session.present_dialog(dialog):
        cancelled()


def offer_recovery(session, path, opened):
    # Only consult the native validator when durable manual-save records exist.
    state = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")
    if not any((state / "keyslot/recovery").glob("manual-*/manifest.json")):
        return False
    def found(records):
        if not records:
            opened()
            return
        from .application import Gtk, GLib, margins, scroll, button
        dialog = Adw.Dialog(title=_tr("Recover Unsaved Changes"), content_width=480)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18), 24)
        box.append(Gtk.Label(label=Path(path).name, css_classes=["title-2"], wrap=True))
        box.append(Gtk.Label(label=_tr("Encrypted copies contain changes left after an interrupted or deferred save. Open a working copy to review it; the recovery original stays intact."), wrap=True))
        group = Adw.PreferencesGroup(title=_tr("Recovery Copies"))
        def recover(item):
            dialog.close()
            def cloned(copy):
                target = session.application.open_database(copy, preferred=session)
                if target:
                    target.recovery_origin = item
            session.run_job(lambda: session.vault.recovery_action("clone", item["manifest"], Path(path).resolve()), cloned)
        for index, item in enumerate(records, 1):
            date = GLib.DateTime.new_from_unix_local(int(item["modified"]) // 1000)
            row = Adw.ActionRow(title=date.format("%c") if date else _trf('Recovery Copy {arg0}', arg0=index), subtitle=_tr("Open an encrypted working copy"))
            open_button = button("document-open-symbolic", _tr('Open Recovery Copy'), lambda item=item: recover(item))
            row.add_suffix(open_button)
            row.set_activatable_widget(open_button)
            group.add(row)
        box.append(group)
        saved = Gtk.Button(label=_tr("Open Saved Vault"))
        saved.connect("clicked", lambda *_: (dialog.close(), opened()))
        box.append(saved)
        discard = Gtk.Button(label=_tr("Discard Unsaved Copies…"), css_classes=["destructive-action"])
        discard.connect("clicked", lambda *_: (dialog.close(), confirm_discard(session, path, records, opened)))
        box.append(discard)
        toolbar.set_content(scroll(box, natural=True))
        dialog.set_child(toolbar)
        session.present_dialog(dialog)
    session.run_job(lambda: session.vault.recovery_action("list", source=Path(path).resolve()), found)
    return True


def confirm_discard(session, path, records, opened):
    dialog = Adw.AlertDialog(heading=_tr("Discard Unsaved Copies?"),
        body=_tr("This permanently removes the unsaved recovery copies for this vault. The saved vault is unchanged."))
    dialog.add_response("cancel", _tr("Cancel"))
    dialog.add_response("discard", _tr("Discard"))
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("discard", Adw.ResponseAppearance.DESTRUCTIVE)
    def discard():
        for item in records:
            session.vault.recovery_action("discard", item["manifest"], Path(path).resolve())
    ready = {"closed": False, "discarded": False}
    def continue_when_ready():
        if ready["closed"] and ready["discarded"]:
            opened()
    def closed(*_):
        ready["closed"] = True
        continue_when_ready()
    def discarded(_result):
        ready["discarded"] = True
        continue_when_ready()
    dialog.connect("closed", closed)
    dialog.connect("response", lambda _d, response: session.run_job(discard, discarded) if response == "discard" else None)
    session.present_dialog(dialog)


def show_recoveries(application):
    from .application import Gtk, GLib, margins, scroll, button
    session = application.active_session or application.new_window()
    if not session.active:
        application.select_session(session)
    if session.busy or session.vault.finishing or session.dialogs or session.file_requests:
        session.toast(_tr("Finish the current operation or dialog first"))
        return
    def found(records):
        if not records:
            session.toast(_tr("No unsaved recovery copies"))
            return
        dialog = Adw.Dialog(title=_tr("Recover Unsaved Changes"), content_width=540)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18), 24)
        box.append(Gtk.Label(label=_tr("Open an independent encrypted working copy. The recovery original stays intact until you save the working copy to a normal location."), wrap=True))
        group = Adw.PreferencesGroup()
        def recover(item):
            dialog.close()
            def cloned(copy):
                target = application.open_database(copy, preferred=session)
                if target:
                    target.recovery_origin = item
            session.run_job(lambda: session.vault.recovery_action("clone", item["manifest"], Path(item["source"])), cloned)
        def discard(item):
            dialog.close()
            confirm_discard(session, Path(item["source"]), [item], lambda: show_recoveries(application))
        for item in records:
            date = GLib.DateTime.new_from_unix_local(int(item["modified"]) // 1000)
            subtitle = item["source"] + ("\n" + date.format("%c") if date else "")
            row = Adw.ActionRow(title=Path(item["source"]).name, subtitle=subtitle)
            row.add_suffix(button("document-open-symbolic", _tr('Open Recovery Copy'), lambda item=item: recover(item)))
            row.add_suffix(button("user-trash-symbolic", _tr('Discard Recovery Copy'), lambda item=item: discard(item)))
            group.add(row)
        box.append(group)
        toolbar.set_content(scroll(box, natural=True))
        dialog.set_child(toolbar)
        session.present_dialog(dialog)
    session.run_job(lambda: session.vault.recovery_action("list", all=True), found)


def save_as(session, destination=None):
    if not session.vault.unlocked or session.busy:
        return
    if destination is None:
        if session.dialogs or session.file_requests:
            session.toast(_tr("Finish the current dialog before saving the vault"))
            return
        session.choose_file(lambda path: save_as(session, path), save=True,
                            name=session.vault.path.name, kdbx=True)
        return
    old_path = session.vault.path
    def inspected(info):
        target = Path(info["path"])
        def save():
            others = [item for item in session.application.sessions if item is not session and item.path == target]
            if any(item.vault.unlocked or item.busy or item.vault.finishing or item.dialogs or item.file_requests for item in others):
                session.error(_tr("The destination is open in another window. Lock it and finish its current operation before replacing it."))
                return
            for item in others:
                session.application.close_session(item, confirmed=True)
            session.requested_path = target
            def failed(message):
                session.requested_path = old_path
                session.emit_state()
                session.error(message)
            def saved(snapshot):
                session.requested_path = session.vault.path
                origin, session.recovery_origin = session.recovery_origin, None
                if session.vault.path != old_path:
                    session.quick_blob = session.quick_path = None
                    session.quick_attempts = 0
                session.apply_refreshed(snapshot)
                session.files.refreshed()
                session.emit_state()
                session.toast("Vault saved as " + session.vault.path.name)
                if session.vault.path != old_path or origin:
                    remember_saved_as(session, old_path, origin)
            session.run_job(lambda: session.vault.save_as(target, info["revision"], info["hash"], info["exists"]), saved, failed)
        if not info["exists"]:
            save()
            return
        dialog = Adw.AlertDialog(heading=_tr("Replace Existing Vault?"),
            body=_trf('Replace {arg0} with this vault’s current contents? The existing file’s version will be kept as an encrypted backup.', arg0=target))
        dialog.add_response("cancel", _tr("Cancel"))
        dialog.add_response("replace", _tr("Replace"))
        dialog.set_close_response("cancel")
        dialog.set_response_appearance("replace", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.connect("response", lambda _d, response: save() if response == "replace" else None)
        session.present_dialog(dialog)
    session.run_job(lambda: session.vault.inspect_output(destination), inspected)


def remember_saved_as(session, old_path, origin):
    from .backend import VaultError
    from gi.repository import GLib
    settings = session.application.startup
    new_path = session.vault.path
    def remember(request):
        try:
            resolved = False
            if origin:
                if Path(origin["manifest"]).exists():
                    session.vault.recovery_action("discard", origin["manifest"], Path(origin["source"]),
                                                  expected_hash=origin["snapshot_hash"])
                resolved = True
            storage = settings.storage
            components = storage.key_components(old_path) if storage else {"keyfile": "", "yubikey": ""}
            if settings.login:
                credentials = session.application.login_keyring().lookup(old_path, request)
                session.vault.verify_credentials(**credentials)
                session.application.login_keyring().store(new_path, credentials, request)
                components = credentials
            request.set_error_if_cancelled()
            if storage:
                storage.remember_components(new_path, components["keyfile"], components["yubikey"])
            settings.opened(new_path)
            return resolved
        except (VaultError, OSError, ValueError, GLib.Error) as exc:
            raise VaultError(f"The vault was saved to {new_path}, but its startup or recovery settings could not be updated: {exc}") from exc
    session.run_keyring_job(remember)
