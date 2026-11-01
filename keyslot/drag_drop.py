"""App-local object drags and reviewed local-file drops; no secret field provider."""
from pathlib import Path
import weakref
from gi.repository import Adw, Gdk, GLib, GObject, Gtk
from . import transfer_views, trash_views
from .database_views import _dialog
from .transfers import EntryTransfer


class Items(GObject.Object):
    __gtype_name__ = "KeyslotDragItems"

    def __init__(self, session, entries=(), group=""):
        super().__init__()
        self.session = weakref.ref(session)
        self.snapshot = weakref.ref(session.vault.snapshot)
        self.epoch = session.epoch
        self.identity = session.vault.identity
        self.generation = session.vault.generation
        self.entries = tuple(item.uuid for item in entries)
        self.group = group

    def source(self):
        session = self.session()
        return session if (session and session.vault.unlocked and not session.jobs.closed and session.epoch == self.epoch
                           and session.vault.identity is self.identity and session.vault.generation == self.generation
                           and session.vault.snapshot is self.snapshot()) else None


def _ready(session):
    return session.vault.unlocked and not session.busy and not session.jobs.closed and not session.dialogs and not session.file_requests


def _source(session, row, entries=None, group=None):
    source = Gtk.DragSource(actions=Gdk.DragAction.MOVE | Gdk.DragAction.COPY)
    def prepare(_source, _x, _y):
        if not _ready(session):
            return None
        snapshot = session.vault.snapshot
        if group is not None:
            matches = [item for item in snapshot.groups if item.identity == group]
            if len(matches) != 1 or group == snapshot.root:
                return None
            payload = Items(session, group=group)
        else:
            selected = session.window.selected_entries() if session.window.selection_mode else []
            chosen = selected if any(item.uuid == entries.uuid for item in selected) else [entries]
            ids = {item.uuid for item in chosen}
            if len(ids) != len(chosen) or any(sum(item.uuid == identifier for item in snapshot.entries) != 1 for identifier in ids):
                session.toast("Ambiguous entry identifiers cannot be dragged")
                return None
            payload = Items(session, chosen)
        return Gdk.ContentProvider.new_for_value(payload)
    def begin(_source, drag):
        label = Gtk.Label(label="Move or Copy Group" if group is not None else "Move or Copy Entries",
                          margin_start=12, margin_end=12, margin_top=8, margin_bottom=8, css_classes=["card"])
        Gtk.DragIcon.get_for_drag(drag).set_child(label)
    source.connect("prepare", prepare)
    source.connect("drag-begin", begin)
    # Native receipt handling owns move cleanup. GDK's delete_data flag never deletes a vault item.
    source.connect("drag-end", lambda *_: source.set_content(None))
    source.connect("drag-cancel", lambda *_: (source.set_content(None), False)[1])
    row.add_controller(source)


def entry_row(session, row, entry):
    grip = Gtk.Image(icon_name="list-drag-handle-symbolic", tooltip_text="Drag Entry or Selected Entries; Hold Ctrl to Copy",
                     valign=Gtk.Align.CENTER, css_classes=["dim-label"])
    grip.keyslot_drag_handle = True
    row.add_suffix(grip)
    _source(session, row, entries=entry)


def group_row(session, row, group):
    if group.identity != session.vault.snapshot.root:
        _source(session, row, group=group.identity)
    _target(session, row, group.identity)


def entry_list(session, widget):
    _target(session, widget, None)


def _target(session, widget, group):
    target = Gtk.DropTarget.new(Items.__gtype__, Gdk.DragAction.COPY | Gdk.DragAction.MOVE)
    target.set_preload(True)
    if group:
        provider = Gtk.CssProvider()
        provider.load_from_string("row.keyslot-drop-before {box-shadow: inset 0 3px @accent_color;} "
                                  "row.keyslot-drop-after {box-shadow: inset 0 -3px @accent_color;}")
        widget.get_style_context().add_provider(provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        widget.set_tooltip_text("Drop entries or groups here; hold Ctrl to copy. Drop groups near an edge to reorder.")
    def clear_marker(*_):
        widget.remove_css_class("keyslot-drop-before")
        widget.remove_css_class("keyslot-drop-after")
    def location(payload, y):
        snapshot = session.vault.snapshot
        identifier = group or session.window.selected_group or snapshot.root
        matches = [item for item in snapshot.groups if item.identity == identifier]
        if len(matches) != 1:
            return None
        item = matches[0]
        position = -1
        if payload.group and group and item.parent:
            height = max(1, widget.get_height())
            if y < height * .25 or y > height * .75:
                siblings = [other for other in snapshot.groups if other.parent == item.parent]
                position = next(index for index, other in enumerate(siblings) if other.identity == identifier)
                if y > height * .75:
                    position += 1
                identifier = item.parent
        return identifier, position
    def motion(controller, _x, y):
        clear_marker()
        payload = controller.get_value()
        if not isinstance(payload, Items) or not payload.source() or not _ready(session):
            return Gdk.DragAction(0)
        destination = location(payload, y)
        if destination is None:
            return Gdk.DragAction(0)
        source = payload.source()
        if payload.group and source is session and destination[0] in transfer_views.descendants(session.vault.snapshot, payload.group):
            return Gdk.DragAction(0)
        if destination[1] >= 0:
            widget.add_css_class("keyslot-drop-before" if y < widget.get_height() * .25 else "keyslot-drop-after")
        return Gdk.DragAction.COPY if controller.get_current_event_state() & Gdk.ModifierType.CONTROL_MASK else Gdk.DragAction.MOVE
    def dropped(controller, payload, _x, y):
        clear_marker()
        source = payload.source() if isinstance(payload, Items) else None
        if not source or not _ready(source) or not _ready(session):
            return False
        destination = location(payload, y)
        if destination is None:
            return False
        identifier, position = destination
        drag = controller.get_current_drop().get_drag() if controller.get_current_drop() else None
        move = not (controller.get_current_event_state() & Gdk.ModifierType.CONTROL_MASK
                    or (drag and drag.get_selected_action() == Gdk.DragAction.COPY))
        entries = [item for item in source.vault.snapshot.entries if item.uuid in payload.entries]
        groups = [item for item in source.vault.snapshot.groups if item.identity == payload.group]
        item = next((item for item in session.vault.snapshot.groups if item.identity == identifier), None)
        if not item:
            return False
        if payload.group and source is session and identifier in transfer_views.descendants(session.vault.snapshot, payload.group):
            return False
        recycled = bool(groups and groups[0].recycled) or any(entry.recycled for entry in entries)
        contains_bin = bool(payload.group and source.vault.snapshot.recycle_bin in transfer_views.descendants(
            source.vault.snapshot, payload.group))
        if (recycled or item.recycled or contains_bin) and ("transfer-recycled" not in source.vault.capabilities or "transfer-recycled" not in session.vault.capabilities):
            session.toast("Update the native engine before transferring recycled items")
            return False
        # A local move into the bin root keeps upstream recycling and original-location bookkeeping.
        if source is session and move and not recycled and not contains_bin and identifier == session.vault.snapshot.recycle_bin and position < 0:
            trash_views.choose(session, "delete", entries=entries, groups=[payload.group] if payload.group else [], bulk=bool(entries))
            return True
        if source is session and move and recycled and not contains_bin and not item.recycled and position < 0 and (
            bool(groups) or all(entry.recycled for entry in entries)):
            trash_views.choose(session, "restore", entries=entries, groups=[payload.group] if payload.group else [],
                               bulk=bool(entries), destination=identifier)
            return True
        if move and source is session and entries and all(entry.group == identifier for entry in entries):
            session.toast("These entries are already in that group")
            return False
        if position >= 0 and ("transfer-position" not in source.vault.capabilities or "transfer-position" not in session.vault.capabilities):
            session.toast("Update the native engine before positioning groups")
            return False
        _transfer(payload, session, entries, identifier, position, move)
        return True
    target.connect("enter", motion); target.connect("motion", motion)
    target.connect("leave", clear_marker)
    target.connect("drop", dropped)
    widget.add_controller(target)


def _transfer(payload, destination, entries, group, position, move):
    source = payload.source()
    if source is None:
        return
    destination_epoch, destination_snapshot = destination.epoch, destination.vault.snapshot
    transfer = EntryTransfer(source.vault, destination.vault, entries, group, move, payload.group, position)
    state = {"phase": "preparing", "transfer": transfer}
    dialog, header, box = _dialog("Preparing Transfer", width=380, height=200)
    box.append(Gtk.Spinner(spinning=True, halign=Gtk.Align.CENTER))
    box.append(Gtk.Label(label="Preparing an encrypted review…", wrap=True))
    def cancel(*_):
        if state["phase"] == "preparing":
            state["phase"] = "cancelled"
            transfer_views.cancel_transfer(transfer, source, destination)
    dialog._clear_sensitive_fields = cancel
    def closed(*_):
        if state["phase"] == "review":
            if (payload.source() is not None and not destination.jobs.closed and destination.epoch == destination_epoch
                and destination.vault.snapshot is destination_snapshot and destination.active):
                transfer_views._review(source, destination, transfer, state, presenter=destination)
            else:
                state["phase"] = "cancelled"
                transfer_views.cancel_transfer(transfer, source, destination)
        else:
            cancel()
    dialog.connect("closed", closed)
    def prepared(_value):
        if (state["phase"] != "preparing" or payload.source() is None or destination.epoch != destination_epoch
            or destination.vault.snapshot is not destination_snapshot or not destination.active):
            cancel()
            transfer_views.cancel_transfer(transfer, source, destination)
            dialog.force_close()
            return
        state["phase"] = "review"; dialog.close()
    def failed(message):
        if state["phase"] == "preparing":
            state["phase"] = "failed"; dialog.close(); destination.error(message)
    if not destination.present_dialog(dialog):
        cancel(); return
    if not source.run_job(transfer.prepare, prepared, failed):
        cancel(); dialog.close(); destination.toast("Finish the current source operation before dragging again")
        return
    def watch():
        if state["phase"] != "preparing":
            return False
        if (payload.source() is None or destination.jobs.closed or destination.epoch != destination_epoch
            or destination.vault.snapshot is not destination_snapshot or not destination.active):
            cancel()
            dialog.force_close()
            return False
        return True
    GLib.timeout_add(250, watch)


def _files(value):
    if not isinstance(value, Gdk.FileList):
        return []
    files = value.get_files()
    if not files or len(files) > 32:
        return []
    paths = [file.get_path() for file in files]
    return paths if all(path and len(path) <= 65536 for path in paths) else []


def window_files(session, window):
    target = Gtk.DropTarget.new(Gdk.FileList.__gtype__, Gdk.DragAction.COPY)
    def dropped(_target, value, _x, _y):
        if session.busy or session.dialogs or session.file_requests:
            return False
        paths = _files(value)
        vaults = [path for path in paths if Path(path).suffix.lower() == ".kdbx"]
        if not vaults:
            return False
        def opened():
            for path in vaults:
                session.application.open_database(path)
        if len(vaults) == 1:
            opened()
        else:
            dialog = Adw.AlertDialog(heading="Open Dropped Vaults?", body="\n".join(Path(path).name for path in vaults), body_use_markup=False)
            dialog.add_response("cancel", "Cancel"); dialog.add_response("open", "Open Vaults")
            dialog.set_default_response("cancel"); dialog.set_close_response("cancel")
            dialog.connect("response", lambda _dialog, response: opened() if response == "open" and not session.jobs.closed else None)
            session.present_dialog(dialog)
        return True
    target.connect("drop", dropped); window.add_controller(target)


def attachments(session, widget, entry):
    snapshot = weakref.ref(session.vault.snapshot)
    target = Gtk.DropTarget.new(Gdk.FileList.__gtype__, Gdk.DragAction.COPY)
    def dropped(_target, value, _x, _y):
        paths = _files(value)
        if not paths or not _ready(session) or session.vault.snapshot is not snapshot():
            return False
        identifier, epoch = entry.uuid, session.epoch
        def inspected(review):
            if session.epoch != epoch or not session.vault.unlocked or not session.active:
                return
            dialog = Adw.AlertDialog(heading="Add Dropped Attachments?", body_use_markup=False,
                body=f'Entry: {entry.title}\nTotal: {review["size"]:,} bytes. All files are added in one encrypted transaction.')
            extra = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            listing = Gtk.TextView(editable=False, cursor_visible=False, wrap_mode=Gtk.WrapMode.WORD_CHAR,
                                   left_margin=12, right_margin=12, top_margin=12, bottom_margin=12)
            listing.get_buffer().set_text("\n\n".join(f'{item["name"]} — {item["size"]:,} bytes\n{item["path"]}' for item in review["files"]))
            extra.append(Gtk.ScrolledWindow(child=listing, min_content_height=80, max_content_height=240,
                propagate_natural_height=True, hscrollbar_policy=Gtk.PolicyType.NEVER, css_classes=["card"], overflow=Gtk.Overflow.HIDDEN))
            replace = Gtk.CheckButton(label=f'Replace {review["replacements"]} existing attachments with matching names')
            if review["replacements"]:
                extra.append(replace)
            dialog.set_extra_child(extra)
            dialog.add_response("cancel", "Cancel"); dialog.add_response("add", "Add Attachments")
            dialog.set_default_response("cancel"); dialog.set_close_response("cancel")
            dialog.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)
            dialog.set_response_enabled("add", not review["replacements"])
            replace.connect("toggled", lambda *_: dialog.set_response_enabled("add", replace.get_active()))
            def response(_dialog, answer):
                if answer == "add" and session.epoch == epoch and session.vault.unlocked:
                    replace_existing = replace.get_active()
                    session.run_job(lambda: session.vault.import_attachment_files(identifier, review, replace_existing),
                                    session.window.show_vault)
            dialog.connect("response", response)
            session.present_dialog(dialog)
        session.run_job(lambda: session.vault.inspect_attachment_files(identifier, paths), inspected)
        return True
    target.connect("drop", dropped); widget.add_controller(target)
