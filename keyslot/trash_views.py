"""Native, revision-bound review for recycling, restoring and permanent deletion."""
from .i18n import tr as _tr
from gi.repository import Adw, GLib, Gtk


def _count(entries, groups):
    parts = []
    if entries:
        parts.append(f"{entries} entry" if entries == 1 else f"{entries} entries")
    if groups:
        parts.append(f"{groups} group" if groups == 1 else f"{groups} groups")
    return " and ".join(parts)


def choose(session, action="delete", entries=(), groups=(), bulk=False, destination=""):
    if session.busy or not session.vault.unlocked:
        return
    entries, groups = list(entries), list(groups)
    session.run_job(lambda: session.vault.review_trash(action, entries, groups),
                    lambda review: _review(session, action, review, bulk, destination))


def _review(session, action, review, bulk, initial_destination=""):
    token = review["token"]
    state = {"phase": "review"}

    def cancel():
        if state["phase"] == "review":
            state["phase"] = "cancelled"
            if not session.jobs.closed and session.vault.unlocked:
                session.jobs.run(lambda: session.vault.cancel_trash(token), failed=lambda _error: None, interactive=False)
        return False

    if not review["entries"] and not review["groups"]:
        cancel()
        session.toast(_tr("The recycle bin is empty"))
        return
    restore = review["restore"]
    permanent = review["purge_entries"] or review["purge_groups"]
    recycled = review["recycle_entries"] or review["recycle_groups"]
    if restore:
        heading, label = "Restore Items?", "Restore"
    elif action == "empty":
        heading, label = "Empty Recycle Bin?", "Empty Recycle Bin"
    elif permanent and recycled:
        heading, label = "Delete Selected Items?", "Delete"
    elif permanent:
        heading, label = "Permanently Delete Items?", "Delete Permanently"
    else:
        heading, label = "Move Items to Recycle Bin?", "Move to Recycle Bin"
    names = review["names"]
    body = "\n".join(names)
    if len(names) == 12:
        body += "\nSelection totals include all contents."
    body += "\n\n" + _count(review["entries"], review["groups"]) + ", including nested groups."
    if restore:
        body += "\n\nRestore to each item's original group, or choose a destination for all selected items."
        if review["fallbacks"]:
            body += f"\n{review['fallbacks']} original locations are unavailable; those items will use {review['root']}."
    else:
        if recycled:
            body += "\n\nMove to Recycle Bin: " + _count(review["recycle_entries"], review["recycle_groups"]) + "."
        if permanent:
            body += "\n\nPermanently delete: " + _count(review["purge_entries"], review["purge_groups"]) + "."
            body += " Their saved history and attachments will also be deleted. This cannot be undone in Keyslot."
    if not session.vault.auto_save:
        body += "\n\nThese changes will remain unsaved until you save the vault."
    dialog = Adw.AlertDialog(heading=heading, body=body, body_use_markup=False)
    destinations = review["destinations"]
    dropdown = None
    if restore:
        options = Adw.PreferencesGroup()
        dropdown = Adw.ComboRow(title=_tr("Destination"), model=Gtk.StringList.new(
            [_tr("Original Locations")] + [item["path"] for item in destinations]))
        if initial_destination:
            index = next((index for index, item in enumerate(destinations) if item["id"] == initial_destination), None)
            if index is None:
                cancel()
                session.error(_tr("The drop destination is no longer available for restoration."))
                return
            dropdown.set_selected(index + 1)
        options.add(dropdown)
        dialog.set_extra_child(options)
    dialog.add_response("cancel", _tr("Cancel"))
    dialog.add_response("apply", label)
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED if restore else Adw.ResponseAppearance.DESTRUCTIVE)

    def response(_dialog, choice):
        if state["phase"] != "review":
            return
        if choice != "apply":
            cancel()
            return
        destination = ""
        if dropdown and dropdown.get_selected():
            destination = destinations[dropdown.get_selected() - 1]["id"]
        state["phase"] = "applying"

        def done(snapshot):
            state["phase"] = "done"
            if bulk:
                session.window.set_selection_mode(False)
            if restore and destination:
                session.window.selected_group = destination
            session.apply_refreshed(snapshot)
            session.toast(_tr("Items restored") if restore else _tr("Recycle bin emptied") if action == "empty" else _tr("Items deleted"))

        if not session.run_job(lambda: session.vault.apply_trash(token, destination), done):
            state["phase"] = "review"
            cancel()

    dialog.connect("response", response)
    # AlertDialog may close before emitting its response; defer cancellation until both have run.
    dialog.connect("closed", lambda *_: GLib.idle_add(cancel))
    if not session.present_dialog(dialog):
        cancel()
