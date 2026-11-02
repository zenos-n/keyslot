"""Reviewed entry copy/move between unlocked vaults, with explicit partial outcomes."""
from .i18n import tr as _tr
from pathlib import Path
from gi.repository import Adw, GLib, Gtk
from .backend import VaultError
from .database_views import _dialog, _save
from .transfers import EntryTransfer


def descendants(snapshot, root):
    result = {root}
    children = {}
    for item in snapshot.groups:
        children.setdefault(item.parent, []).append(item.identity)
    pending = [root]
    while pending:
        for child in children.get(pending.pop(), []):
            if child not in result:
                result.add(child)
                pending.append(child)
    return result


def cancel_transfer(transfer, *sessions):
    transfer.cancelled = True
    for session in sessions:
        if not session.jobs.closed:
            try:
                session.jobs.executor.submit(transfer.cancel)
                return
            except RuntimeError:
                continue


def choose(session, entries=(), source_group=""):
    if session.busy or not session.vault.unlocked:
        return
    entries = list(entries)
    app = session.application
    sessions = [item for item in app.sessions if item.vault.unlocked and not item.jobs.closed]
    noun = "Group" if source_group else "Entry" if len(entries) == 1 else "Entries"
    dialog, header, box = _dialog("Copy or Move " + noun, width=480, height=320)
    options = Adw.PreferencesGroup(description=_tr("Open and unlock another vault to include it in the destination list."))
    action = Adw.ComboRow(title=_tr("Action"), model=Gtk.StringList.new([_tr("Copy"), _tr("Move")]))
    action.set_selected(1)
    labels = [(item.vault.snapshot.name or item.path.stem) + " — " + Path(item.path).name for item in sessions]
    vault = Adw.ComboRow(title=_tr("Destination Vault"), model=Gtk.StringList.new(labels))
    vault.set_selected(sessions.index(session))
    group = Adw.ComboRow(title=_tr("Destination Group"))
    groups = []
    def changed(*_):
        nonlocal groups
        target = sessions[vault.get_selected()]
        excluded = descendants(target.vault.snapshot, source_group) if target is session and source_group else set()
        groups = [item for item in target.vault.snapshot.groups if item.addressable
                  and (not item.recycled or "transfer-recycled" in target.vault.capabilities)
                  and item.identity not in excluded] if target.vault.unlocked else []
        group.set_model(Gtk.StringList.new([(item.path or item.name) + (" (Recycle Bin)" if item.recycled else "") for item in groups]))
        group.set_selected(next((index for index, item in enumerate(groups) if item.identity == target.window.selected_group), 0))
    vault.connect("notify::selected", changed)
    changed()
    for row in (action, vault, group):
        options.add(row)
    box.append(options)
    state = {"phase": "choose", "transfer": None}
    def closed(*_):
        if state["phase"] in ("choose", "preparing"):
            state["phase"] = "cancelled"
            if transfer := state["transfer"]:
                cancel_transfer(transfer, session)
    dialog.connect("closed", closed)

    def continue_(*_):
        if session.busy or state["phase"] != "choose" or not groups:
            return
        target = sessions[vault.get_selected()]
        if target.jobs.closed or not target.vault.unlocked or target.busy or (target is not session and target.dialogs):
            session.error(_tr("Finish editing or unlocking the destination vault first."))
            return
        destination = groups[group.get_selected()].identity
        transfer = EntryTransfer(session.vault, target.vault, entries, destination, action.get_selected() == 1, source_group)
        state.update(phase="preparing", transfer=transfer)
        def failed(message):
            if state["phase"] != "cancelled":
                state["phase"] = "choose"
                session.error(message)
        def ready(source):
            if state["phase"] == "cancelled" or not session.active:
                state["phase"] = "cancelled"
                cancel_transfer(transfer, session, target)
                return
            state["phase"] = "review"
            dialog.close()
            _review(session, target, transfer, state)
        session.run_job(transfer.prepare, ready, failed)
    _save(header, continue_, _tr('Continue'))
    session.present_dialog(dialog)


def _review(source, destination, transfer, state, presenter=None):
    presenter = presenter or source
    epochs = source.epoch, destination.epoch
    move = transfer.source_ticket["move"]
    names = [item["title"] for item in transfer.source_ticket["entries"]]
    count = transfer.source_ticket["count"]
    grouped = bool(transfer.source_group)
    target = transfer.destination_ticket
    target_name = (target["name"] or Path(target["path"]).name) if target else source.vault.snapshot.name
    target_path = target["path"] if target else transfer.source_ticket["path"]
    group_name = target["group_name"] if target else next(g.path for g in source.vault.snapshot.groups if g.identity == transfer.group)
    recycled_target = target.get("recycled", False) if target else any(
        g.identity == transfer.group and g.recycled for g in source.vault.snapshot.groups)
    noun = "Group" if grouped else "Entry" if count == 1 else f"{count} Entries"
    heading = ("Move " if move else "Copy ") + noun + "?"
    body = "\n".join(names) + (f"\n…and {count - len(names)} more" if count > len(names) else "")
    if grouped:
        group_count = len(transfer.source_ticket["groups"])
        group_word = "group" if group_count == 1 else "groups"
        entry_word = "entry" if count == 1 else "entries"
        body = (transfer.source_ticket["group_name"] + f"\n{group_count} {group_word} and {count} {entry_word}, including nested groups."
                + "\nGroup settings, including Auto-Type and KeeShare, are retained. Review shared-file paths in the destination.")
    body += f"\n\nFrom: {source.vault.snapshot.name or Path(source.path).name}\n{transfer.source_ticket['path']}\n\nTo: {target_name}\n{target_path}\nGroup: {group_name}"
    if transfer.position >= 0:
        position = transfer.position
        if move and source is destination:
            siblings = [item.identity for item in source.vault.snapshot.groups if item.parent == transfer.group]
            if transfer.source_group in siblings and position > siblings.index(transfer.source_group):
                position -= 1
        body += f"\nInsert at position {position + 1} among the destination group's subgroups."
    if move and source is not destination:
        body += "\n\nThe destination will be saved before the originals are removed."
    recycled_entries = transfer.source_ticket.get("recycled_entries", 0)
    recycled_group = transfer.source_ticket.get("recycled_group", False)
    if recycled_entries or recycled_group:
        body += "\n\nThe source includes a recycled group." if recycled_group else f"\n\nThe source includes {recycled_entries} recycled entries."
        if move and source is not destination:
            body += " Their originals will be permanently removed from the source recycle bin after the destination is saved."
    contains_bin = transfer.source_ticket.get("contains_recycle_bin", False)
    if contains_bin:
        if move and source is destination:
            body += "\n\nThis group contains the designated recycle bin. Moving it within this vault keeps that bin's role and recycled contents."
        else:
            body += "\n\nThis group contains the designated recycle bin. Its copy is an ordinary group unless placed inside the destination recycle bin; it does not replace that vault's designated bin."
            if move:
                body += " The source bin will be removed after the destination is saved. If recycling is enabled, a fresh bin is created when next needed."
    if recycled_target:
        body += "\n\nThe destination is in the recycle bin. Transferred items will remain recycled and hidden from ordinary entry lists."
    if not source.application.startup.auto_save:
        body += ("\n\nThese changes remain unsaved until you save this vault." if source is destination else
                 "\n\nThis transfer saves the destination vault and any source changes it makes, including existing unsaved changes.")
    if transfer.source_ticket["references"]:
        body += "\n\nField references are kept as written; check them in the destination."
    alert = Adw.AlertDialog(heading=heading, body=body, body_use_markup=False)
    alert.add_response("cancel", _tr("Cancel"))
    alert.add_response("apply", _tr("Move") if move else _tr("Copy"))
    alert.set_close_response("cancel")
    alert.set_response_appearance("apply", Adw.ResponseAppearance.DESTRUCTIVE if move and (recycled_target or contains_bin and source is not destination) else Adw.ResponseAppearance.SUGGESTED)
    def response(_alert, choice):
        if state["phase"] != "review":
            return
        state["phase"] = "running" if choice == "apply" else "cancelled"
        if choice != "apply":
            cancel_transfer(transfer, source, destination)
            return
        if (source.jobs.closed or source.busy or not source.vault.unlocked
            or destination.jobs.closed or destination.busy or not destination.vault.unlocked
            or any(item is not alert for item in destination.dialogs)
            or any(item is not alert for item in source.dialogs)):
            cancel_transfer(transfer, source, destination)
            presenter.error("A transfer vault is busy, locked or closed. Choose the destination again.")
            return
        def destination_done(value):
            destination.window.selected_group = value.get("root_group") or transfer.group
            destination.window.show_vault(destination.vault.snapshot)
        if source is not destination:
            if not destination.run_job(transfer.receive, destination_done, lambda _message: None):
                cancel_transfer(transfer, source, destination)
                presenter.error("The destination is busy. Try again.")
                return
        def done(outcome):
            state["phase"] = "done"
            if source.vault.unlocked:
                if source is destination:
                    source.window.selected_group = outcome.destination_group or transfer.group
                if outcome.copied:
                    source.window.set_selection_mode(False)
                source.window.show_vault(source.vault.snapshot)
            if outcome.message:
                if outcome.uncertain:
                    title = "Transfer Could Not Be Confirmed"
                    body = ("A destination copy was saved. Source cleanup could not be confirmed; reopen the source vault before repeating the move."
                            if outcome.copied else "Source items were not removed. Check the destination before trying again.")
                else:
                    title = (("Group Copied; Original Kept" if grouped else "Entries Copied; Originals Kept" if count > 1 else "Entry Copied; Original Kept")
                             if outcome.copied else "Transfer Did Not Complete")
                    body = "The destination contains a saved copy. The original was kept.\n\n" + outcome.message if outcome.copied else outcome.message
                notice = Adw.AlertDialog(heading=title, body=body, body_use_markup=False)
                notice.add_response("close", _tr("Close"))
                if presenter.active:
                    presenter.present_dialog(notice)
                else:
                    presenter.error(title + "\n\n" + body)
            else:
                item = "Group" if grouped else "Entry" if count == 1 else f"{count} entries"
                presenter.toast(item + (" moved" if outcome.moved else " copied"))
        if not source.run_job(transfer.send, done):
            cancel_transfer(transfer, source, destination)
            presenter.error("The source is busy. The transfer was cancelled.")
    alert.connect("response", response)
    def release():
        if state["phase"] == "review":
            state["phase"] = "cancelled"
            cancel_transfer(transfer, source, destination)
        return False
    alert.connect("closed", lambda *_: GLib.idle_add(release))
    if not presenter.present_dialog(alert):
        release()
        return
    def watch():
        if state["phase"] != "review":
            return False
        if (source.jobs.closed or destination.jobs.closed or not source.vault.unlocked or not destination.vault.unlocked
            or (source.epoch, destination.epoch) != epochs):
            release()
            alert.force_close()
            return False
        return True
    GLib.timeout_add(250, watch)
