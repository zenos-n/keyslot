"""Reviewed entry copy/move between unlocked vaults, with explicit partial outcomes."""
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


def choose(session, entries=(), source_group=""):
    if session.busy or not session.vault.unlocked:
        return
    entries = list(entries)
    app = session.application
    sessions = [item for item in app.sessions if item.vault.unlocked and not item.jobs.closed]
    noun = "Group" if source_group else "Entry" if len(entries) == 1 else "Entries"
    dialog, header, box = _dialog("Copy or Move " + noun, width=480, height=320)
    options = Adw.PreferencesGroup(description="Open and unlock another vault to include it in the destination list.")
    action = Adw.ComboRow(title="Action", model=Gtk.StringList.new(["Copy", "Move"]))
    action.set_selected(1)
    labels = [(item.vault.snapshot.name or item.path.stem) + " — " + Path(item.path).name for item in sessions]
    vault = Adw.ComboRow(title="Destination Vault", model=Gtk.StringList.new(labels))
    vault.set_selected(sessions.index(session))
    group = Adw.ComboRow(title="Destination Group")
    groups = []
    def changed(*_):
        nonlocal groups
        target = sessions[vault.get_selected()]
        excluded = descendants(target.vault.snapshot, source_group) if target is session and source_group else set()
        groups = [item for item in target.vault.snapshot.groups if not item.recycled and item.addressable
                  and item.identity not in excluded] if target.vault.unlocked else []
        group.set_model(Gtk.StringList.new([item.path or item.name for item in groups]))
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
                transfer.cancelled = True
                session.jobs.executor.submit(transfer.cancel)
    dialog.connect("closed", closed)

    def continue_(*_):
        if session.busy or state["phase"] != "choose" or not groups:
            return
        target = sessions[vault.get_selected()]
        if target.jobs.closed or not target.vault.unlocked or target.busy or (target is not session and target.dialogs):
            session.error("Finish editing or unlocking the destination vault first.")
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
                session.jobs.executor.submit(transfer.cancel)
                return
            state["phase"] = "review"
            dialog.close()
            _review(session, target, transfer, state)
        session.run_job(transfer.prepare, ready, failed)
    _save(header, continue_, "Continue")
    session.present_dialog(dialog)


def _review(source, destination, transfer, state):
    move = transfer.source_ticket["move"]
    names = [item["title"] for item in transfer.source_ticket["entries"]]
    count = transfer.source_ticket["count"]
    grouped = bool(transfer.source_group)
    target = transfer.destination_ticket
    target_name = (target["name"] or Path(target["path"]).name) if target else source.vault.snapshot.name
    target_path = target["path"] if target else transfer.source_ticket["path"]
    group_name = target["group_name"] if target else next(g.path for g in source.vault.snapshot.groups if g.identity == transfer.group)
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
    if move and source is not destination:
        body += "\n\nThe destination will be saved before the originals are removed."
    if transfer.source_ticket["references"]:
        body += "\n\nField references are kept as written; check them in the destination."
    alert = Adw.AlertDialog(heading=heading, body=body, body_use_markup=False)
    alert.add_response("cancel", "Cancel")
    alert.add_response("apply", "Move" if move else "Copy")
    alert.set_close_response("cancel")
    alert.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)
    def response(_alert, choice):
        if state["phase"] != "review":
            return
        state["phase"] = "running" if choice == "apply" else "cancelled"
        if choice != "apply":
            transfer.cancelled = True
            source.jobs.executor.submit(transfer.cancel)
            return
        if destination.jobs.closed or destination.busy or (destination is not source and destination.dialogs):
            transfer.cancelled = True
            source.jobs.executor.submit(transfer.cancel)
            source.error("The destination is busy or closed. Choose it again.")
            return
        def destination_done(value):
            destination.window.selected_group = value.get("root_group") or transfer.group
            destination.window.show_vault(destination.vault.snapshot)
        if source is not destination:
            if not destination.run_job(transfer.receive, destination_done, lambda _message: None):
                transfer.cancelled = True
                source.jobs.executor.submit(transfer.cancel)
                source.error("The destination is busy. Try again.")
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
                notice.add_response("close", "Close")
                if source.active:
                    source.present_dialog(notice)
                else:
                    source.error(title + "\n\n" + body)
            else:
                item = "Group" if grouped else "Entry" if count == 1 else f"{count} entries"
                source.toast(item + (" moved" if outcome.moved else " copied"))
        if not source.run_job(transfer.send, done):
            transfer.cancelled = True
            source.jobs.executor.submit(transfer.cancel)
            source.error("The source is busy. The transfer was cancelled.")
    alert.connect("response", response)
    source.present_dialog(alert)
