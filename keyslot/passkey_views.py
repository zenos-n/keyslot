"""Passkey management; private keys stay in the native helper during transfer."""
from .i18n import ntrf as _ntrf, mark as _mark, tr as _tr, trf as _trf
import os
from pathlib import Path

from .database_views import Adw, Gtk, _dialog, _save


def _lifetime(session, dialog):
    epoch, state = session.epoch, {"closed": False}
    dialog.connect("closed", lambda *_: state.__setitem__("closed", True))
    return lambda: not state["closed"] and session.epoch == epoch and session.vault.unlocked and not session.jobs.closed


def _confirm(session, heading, body, label, callback):
    if not session.vault.unlocked or session.busy:
        return
    epoch = session.epoch
    dialog = Adw.AlertDialog(heading=heading, body=body, body_use_markup=False)
    dialog.add_response("cancel", _tr("Cancel"))
    dialog.add_response("apply", label)
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("apply", Adw.ResponseAppearance.DESTRUCTIVE)
    dialog.connect("response", lambda _dialog, response: callback()
        if response == "apply" and session.epoch == epoch and session.vault.unlocked and not session.jobs.closed else None)
    session.present_dialog(dialog)


def manage(session, data=None):
    if not session.vault.unlocked or session.busy:
        return
    if data is None:
        session.run_job(session.vault.passkey_list, lambda value: manage(session, value))
        return
    entries = sorted((entry for entry, _ in data), key=lambda entry: entry.title.casefold())
    metadata = {entry.uuid: info for entry, info in data}
    dialog, header, box = _dialog(_tr("Passkeys"), width=600, height=min(640, 300 + len(entries) * 56) if entries else 360)
    current = _lifetime(session, dialog)
    import_button = Gtk.Button(label=_tr("Import…"), valign=Gtk.Align.CENTER)
    import_button.connect("clicked", lambda *_: (dialog.close(), choose_import(session)) if current() else None)
    header.pack_start(import_button)
    export = Gtk.Button(label=_tr("Export…"), valign=Gtk.Align.CENTER, sensitive=False)
    header.pack_end(export)
    if entries:
        search = Gtk.SearchEntry(placeholder_text=_tr("Search passkeys"))
        box.append(search)
        expired = Gtk.CheckButton(label=_tr("Show Expired Passkeys"), valign=Gtk.Align.CENTER)
        box.append(expired)
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"], valign=Gtk.Align.START)
        box.append(rows)
        selected = {}
        def update(*_):
            count = sum(check.get_active() for check in selected.values())
            export.set_label(_trf('Export ({arg0})…', arg0=count) if count else _tr("Export…"))
            export.set_sensitive(count > 0)
        def open_info(entry):
            if not current():
                return
            dialog.close()
            show_info(session, entry)
        for entry in entries:
            info = metadata[entry.uuid]
            row = Adw.ActionRow(title=(entry.title or "Untitled Entry") + (" (Expired)" if entry.expired else ""), subtitle=" · ".join(
                value for value in (info["username"], info["relyingParty"], entry.group_path) if value), use_markup=False,
                title_lines=2, subtitle_lines=2)
            row.entry = entry
            check = Gtk.CheckButton(valign=Gtk.Align.CENTER)
            check.update_property([Gtk.AccessibleProperty.LABEL], ["Select " + (entry.title or "Untitled Entry")])
            check.connect("toggled", update)
            selected[entry.uuid] = check
            row.add_prefix(check)
            row.set_activatable_widget(check)
            info = Gtk.Button(icon_name="document-properties-symbolic", tooltip_text=_tr("Passkey Details"), valign=Gtk.Align.CENTER)
            info.connect("clicked", lambda _button, entry=entry: open_info(entry))
            row.add_suffix(info)
            rows.append(row)
        def visible(entry):
            info = metadata[entry.uuid]
            return (expired.get_active() or not entry.expired) and search.get_text().casefold() in " ".join(
                (entry.title, info["username"], info["relyingParty"], entry.group_path)).casefold()
        def filter_changed(*_):
            for entry in entries:
                if not visible(entry):
                    selected[entry.uuid].set_active(False)
            rows.invalidate_filter()
        rows.set_filter_func(lambda row: visible(row.entry))
        search.connect("search-changed", filter_changed)
        expired.connect("toggled", filter_changed)
        def export_clicked(*_):
            if not current():
                return
            chosen = [entry for entry in entries if selected[entry.uuid].get_active()]
            dialog.close()
            session.choose_file(lambda folder: session.run_job(
                lambda: session.vault.plan_passkey_exports(chosen, folder), lambda plan: confirm_export(session, plan)), folder=True)
        export.connect("clicked", export_clicked)
    else:
        box.append(Adw.StatusPage(title=_tr("No Passkeys"), icon_name="dialog-password-symbolic",
            description=_tr("Create passkeys with KeePassXC-Browser, or import a .passkey file.")))
    session.present_dialog(dialog)


def show_info(session, entry, data=None):
    if not session.vault.unlocked or session.busy:
        return
    if data is None:
        session.run_job(lambda: session.vault.passkey_info(entry), lambda value: show_info(session, entry, value))
        return
    dialog, header, box = _dialog(_tr("Passkey Details"), height=460)
    current = _lifetime(session, dialog)
    account = Adw.PreferencesGroup(title=entry.title or _tr("Untitled Entry"))
    for label, field in [(_mark("Website"), "relyingParty"), (_mark("Account"), "username"), (_mark("Credential ID"), "credentialId")]:
        account.add(Adw.ActionRow(title=_tr(label), subtitle=data[field] or _tr("None"), use_markup=False, subtitle_lines=2))
    box.append(account)
    export = Gtk.Button(label=_tr("Export…"), valign=Gtk.Align.CENTER)
    def export_clicked(*_):
        if not current():
            return
        dialog.close()
        session.choose_file(lambda path: confirm_export(session, [(entry, Path(path))]), save=True, name=data["filename"])
    export.connect("clicked", export_clicked)
    header.pack_end(export)
    replacement = Gtk.Button(label=_tr("Import Replacement…"), sensitive=not entry.recycled)
    replacement.connect("clicked", lambda *_: (dialog.close(), choose_import(session, entry)) if current() else None)
    box.append(replacement)
    remove = Gtk.Button(label=_tr("Remove Passkey…"), css_classes=["destructive-action"], sensitive=not entry.recycled)
    def remove_clicked(*_):
        if not current():
            return
        dialog.close()
        _confirm(session, "Remove Passkey?", "Remove the passkey from this entry? Its other fields will stay. "
            "Saved history and encrypted backups may still contain the passkey. This does not remove it from the website.",
            "Remove Passkey", lambda: session.run_job(lambda: session.vault.remove_passkey(entry), session.window.show_vault))
    remove.connect("clicked", remove_clicked)
    box.append(remove)
    session.present_dialog(dialog)


def choose_import(session, entry=None):
    if not session.vault.unlocked or session.busy:
        return
    session.choose_file(lambda source: session.run_job(lambda: session.vault.inspect_passkey(source),
        lambda data: review_import(session, source, data, entry)))


def review_import(session, source, data, entry=None):
    if not session.vault.unlocked or session.busy:
        return
    dialog, header, box = _dialog(_tr("Import Passkey"), height=460)
    current = _lifetime(session, dialog)
    account = Adw.PreferencesGroup(title=Path(source).name)
    account.add(Adw.ActionRow(title=_tr("Website"), subtitle=data["relyingParty"] or _tr("None"), use_markup=False))
    account.add(Adw.ActionRow(title=_tr("Account"), subtitle=data["username"] or _tr("None"), use_markup=False))
    box.append(account)
    entries = [None] + [item for item in session.vault.snapshot.entries if not item.recycled]
    groups = [None] + [group for group in session.vault.snapshot.groups if not group.recycled]
    selected = next((index for index, item in enumerate(entries) if item is not None and entry is not None and item.uuid == entry.uuid), 0)
    targets = Adw.ComboRow(title=_tr("Save To"), model=Gtk.StringList.new([_tr("New Entry")] + [
        (item.title or "Untitled Entry") + " · " + (item.username or item.group_path) for item in entries[1:]]))
    targets.set_selected(selected)
    group = Adw.ComboRow(title=_tr("Group"), model=Gtk.StringList.new([_tr("Imported Passkeys (Default)")] + [item.path for item in groups[1:]]))
    destination = Adw.PreferencesGroup(title=_tr("Destination"))
    destination.add(targets)
    destination.add(group)
    group.set_visible(selected == 0)
    targets.connect("notify::selected", lambda *_: group.set_visible(targets.get_selected() == 0))
    box.append(destination)
    def save(replace=False):
        if not current():
            return
        target = entries[targets.get_selected()]
        parent = groups[group.get_selected()]
        dialog.close()
        session.run_job(lambda: session.vault.import_passkey(source, data["source_fingerprint"], target,
            parent.uuid if parent and target is None else "", replace), session.window.show_vault)
    def submit(*_):
        if not current():
            return
        target = entries[targets.get_selected()]
        if target and target.passkey:
            _confirm(session, "Replace Existing Passkey?", "This entry already contains a passkey. Importing replaces "
                "its current passkey. Other entry fields stay unchanged.", "Replace Passkey", lambda: save(True))
        else:
            save()
    _save(header, submit, _tr('Import'))
    session.present_dialog(dialog)


def confirm_export(session, plan):
    if not session.vault.unlocked or session.busy or not plan:
        return
    overwrite = any(os.path.lexists(path) for _, path in plan)
    names = "\n".join(str(path) for _, path in plan[:8])
    if len(plan) > 8:
        names += f"\n…and {len(plan) - 8} more files"
    _confirm(session, "Export Unencrypted Passkeys?", "Exported files contain private keys. Anyone with these files "
        f"may be able to sign in as you. Store them securely.\n\n{len(plan)} file(s):\n" + names +
        ("\n\nExisting files at these destinations will be replaced." if overwrite else ""),
        "Export and Replace" if overwrite else "Export", lambda: session.run_job(
            lambda: session.vault.export_passkeys(plan, overwrite), lambda count: session.toast(
                _tr("Passkey exported") if count == 1 else _ntrf('{count} passkey exported', '{count} passkeys exported', count))))
