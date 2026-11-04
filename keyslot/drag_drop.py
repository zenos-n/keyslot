"""App-local object drags and reviewed local-file drops; no secret field provider."""
from .i18n import tr as _tr, trf as _trf
from pathlib import Path
import weakref
from gi.repository import Adw, Gdk, GLib, GObject, Gtk
from . import transfer_views, trash_views
from .database_views import _dialog
from .transfers import EntryTransfer
from .backend import ordered_entries


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


def cancel(session):
    active = getattr(session, "entry_drag", None)
    if active:
        active.close(cancel_drag=True)


class EntryDrag:
    """Keep metadata in the source column; only a compact card follows external drags."""
    def __init__(self, session, source, drag, row, payload, offset):
        self.session, self.source, self.drag = session, source, drag
        self.payload, self.offset = payload, offset
        self.list = session.window.entries
        self.rows, self.providers = [], []
        child = self.list.get_first_child()
        while child:
            self.rows.append(child)
            child = child.get_next_sibling()
        self.positions = [item.get_allocation().y for item in self.rows]
        self.heights = [item.get_height() for item in self.rows]
        self.chosen = [item for item in self.rows if item.entry.uuid in payload.entries]
        self.indices = {item: index for index, item in enumerate(self.rows)}
        self.offset += sum(self.heights[self.indices[item]] for item in self.chosen[:self.chosen.index(row)])
        self.order = list(self.rows)
        self.styles = [None] * len(self.rows)
        self.selected_indices = {item: index for index, item in enumerate(self.chosen)}
        self.layer = session.window.entry_drag_layer
        self.floating = []
        for item in self.chosen:
            picture = Gtk.Picture(paintable=Gtk.WidgetPaintable.new(item.get_child()),
                                  width_request=item.get_width(), height_request=item.get_height(), can_shrink=False,
                                  can_target=False, css_classes=["card"])
            self.layer.put(picture, 0, 0)
            self.floating.append(picture)
        self.closed = False
        self.tooltips = []
        for item in self.rows:
            provider = Gtk.CssProvider()
            item.get_style_context().add_provider(provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION + 1)
            self.providers.append(provider)
            for widget in (item, getattr(item, "keyslot_grip", None)):
                if widget:
                    self.tooltips.append((widget, widget.get_has_tooltip()))
                    widget.set_has_tooltip(False)
        # The preview uses the already-visible metadata, never a native secret read.
        entry = row.entry
        self.card = Gtk.Box(spacing=10, css_classes=["card"], margin_start=4, margin_end=4,
                            margin_top=4, margin_bottom=4, width_request=220)
        icon = session.icons.image(entry, 24)
        icon.set_margin_start(12)
        self.card.append(icon)
        labels = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2,
                         margin_top=8, margin_bottom=8, margin_end=12, hexpand=True)
        title = Gtk.Label(label=entry.title or _tr("Untitled Entry"), xalign=0, ellipsize=3, max_width_chars=28)
        labels.append(title)
        if entry.username:
            username = "••••••" if session.application.startup.hide_usernames else entry.username
            labels.append(Gtk.Label(label=username, xalign=0, ellipsize=3, max_width_chars=28,
                                    css_classes=["dim-label", "caption"]))
        self.card.append(labels)
        if len(self.chosen) > 1:
            self.card.append(Gtk.Label(label=str(len(self.chosen)), margin_end=10, css_classes=["dim-label"]))
        self.icon = Gtk.DragIcon.get_for_drag(drag)
        drag.set_hotspot(12, 12)
        self.blank = Gtk.Box(width_request=1, height_request=1, opacity=0)
        self.icon.set_child(self.blank)
        session.entry_drag = self
        self.timer = GLib.timeout_add(100, self.watch)
        self.motion(self.positions[self.indices[row]] + offset)

    def watch(self):
        if self.closed:
            return GLib.SOURCE_REMOVE
        if self.payload.source() is None or not _ready(self.session) or not self.list.get_mapped():
            self.timer = 0
            self.close(cancel_drag=True)
            return GLib.SOURCE_REMOVE
        return GLib.SOURCE_CONTINUE

    def outside(self):
        if self.closed:
            return
        self.icon.set_child(self.card)
        for picture in self.floating:
            picture.set_visible(False)
        for index, row in enumerate(self.rows):
            self.style(index, "row {opacity: .4;}" if row in self.selected_indices else "")

    def style(self, index, css):
        if self.styles[index] != css:
            self.providers[index].load_from_string(css)
            self.styles[index] = css

    def motion(self, y, copy=False):
        if self.closed:
            return
        if copy:
            self.outside()
            return
        self.icon.set_child(self.blank)
        valid, bounds = self.list.compute_bounds(self.layer)
        if not valid:
            self.outside()
            return
        selected = set(self.chosen)
        remaining = [row for row in self.rows if row not in selected]
        insertion = sum(self.positions[self.indices[row]] + self.heights[self.indices[row]] / 2 < y
                        for row in remaining)
        self.order = remaining[:insertion] + self.chosen + remaining[insertion:]
        block_height = sum(self.heights[self.indices[row]] for row in self.chosen)
        block_y = max(0, min(y - self.offset, sum(self.heights) - block_height))
        top, selected_top = 0, block_y
        for row in self.order:
            index = self.indices[row]
            is_selected = row in selected
            target = selected_top if is_selected else top
            if is_selected:
                selected_top += self.heights[index]
            offset = target - self.positions[index]
            if is_selected:
                picture = self.floating[self.selected_indices[row]]
                picture.set_visible(True)
                self.layer.move(picture, bounds.get_x(), bounds.get_y() + target)
                style = "row {opacity: 0;}"
            else:
                style = f"row {{ transform: translate(0px, {offset:.2f}px); }}"
            self.style(index, style)
            top += self.heights[index]

    def drop(self):
        if self.closed or self.payload.source() is not self.session or not _ready(self.session):
            return False
        ordered = [row.entry.uuid for row in self.order]
        original = [row.entry.uuid for row in self.rows]
        snapshot = self.session.vault.snapshot
        self.close()
        if ordered == original:
            return True
        # Replace only the visible slots: filtered-out entries keep their relative order.
        visible = set(ordered)
        replacements = iter(ordered)
        all_ids = [next(replacements) if item.uuid in visible else item.uuid for item in ordered_entries(snapshot)]
        return self.session.run_job(lambda: self.session.vault.reorder_entries(all_ids), self.session.window.show_vault)

    def close(self, cancel_drag=False):
        if self.closed:
            return
        self.closed = True
        if self.timer:
            GLib.source_remove(self.timer)
            self.timer = 0
        for picture in self.floating:
            picture.set_paintable(None)
            self.layer.remove(picture)
        self.floating.clear()
        for row, provider in zip(self.rows, self.providers):
            row.get_style_context().remove_provider(provider)
        for widget, enabled in self.tooltips:
            widget.set_has_tooltip(enabled)
        self.icon.set_child(self.blank)
        # A drag surface may outlive the source window; discard its visible metadata now.
        while self.card.get_first_child():
            self.card.remove(self.card.get_first_child())
        if getattr(self.session, "entry_drag", None) is self:
            self.session.entry_drag = None
        if cancel_drag:
            self.source.drag_cancel()


def _source(session, row, entries=None, group=None):
    source = Gtk.DragSource(actions=Gdk.DragAction.MOVE | Gdk.DragAction.COPY)
    prepared = {}
    def prepare(_source, _x, y):
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
                session.toast(_tr("Ambiguous entry identifiers cannot be dragged"))
                return None
            payload = Items(session, chosen)
        prepared.update(payload=payload, y=y)
        return Gdk.ContentProvider.new_for_value(payload)
    def begin(_source, drag):
        cancel(session)
        if group is None:
            EntryDrag(session, source, drag, row, prepared["payload"], prepared["y"])
        else:
            label = Gtk.Label(label=_tr("Move or Copy Group"), margin_start=12, margin_end=12,
                              margin_top=8, margin_bottom=8, css_classes=["card"])
            Gtk.DragIcon.get_for_drag(drag).set_child(label)
    def end(*_):
        active = getattr(session, "entry_drag", None)
        if active and active.source is source:
            active.close()
        source.set_content(None)
        prepared.clear()
    source.connect("prepare", prepare)
    source.connect("drag-begin", begin)
    # Native receipt handling owns move cleanup. GDK's delete_data flag never deletes a vault item.
    source.connect("drag-end", end)
    source.connect("drag-cancel", lambda *_: (end(), True)[1])
    row.add_controller(source)


def entry_row(session, row, entry):
    grip = Gtk.Image(icon_name="list-drag-handle-symbolic", tooltip_text=_tr("Drag Entry or Selected Entries; Hold Ctrl to Copy"),
                     valign=Gtk.Align.CENTER, css_classes=["dim-label"])
    grip.keyslot_drag_handle = True
    row.add_suffix(grip)
    row.keyslot_grip = grip
    _source(session, row, entries=entry)


def group_row(session, row, group):
    if group.identity != session.vault.snapshot.root:
        _source(session, row, group=group.identity)
    _target(session, row, group.identity)


def entry_list(session, widget, viewport):
    _target(session, viewport, None)
    motion = Gtk.DropControllerMotion()
    def moved(controller, x, y):
        active = getattr(session, "entry_drag", None)
        drop = controller.get_drop()
        if not active or not drop or drop.get_drag() != active.drag:
            return
        valid, bounds = widget.compute_bounds(viewport)
        if valid:
            copy = bool(controller.get_current_event_state() & Gdk.ModifierType.CONTROL_MASK)
            active.motion(y - bounds.get_y(), copy)
    motion.connect("enter", moved)
    motion.connect("motion", moved)
    motion.connect("leave", lambda *_: getattr(session, "entry_drag", None) and session.entry_drag.outside())
    viewport.add_controller(motion)


def _target(session, widget, group):
    target = Gtk.DropTarget.new(Items.__gtype__, Gdk.DragAction.COPY | Gdk.DragAction.MOVE)
    target.set_preload(True)
    if group:
        provider = Gtk.CssProvider()
        provider.load_from_string("row.keyslot-drop-before {box-shadow: inset 0 3px @accent_color;} "
                                  "row.keyslot-drop-after {box-shadow: inset 0 -3px @accent_color;}")
        widget.get_style_context().add_provider(provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        widget.set_tooltip_text(_tr("Drop entries or groups here; hold Ctrl to copy. Drop groups near an edge to reorder."))
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
        active = getattr(source, "entry_drag", None)
        if group is None and source is session and move and not payload.group and active and active.payload is payload:
            if "entry-order" not in source.vault.capabilities:
                return False
            valid, bounds = active.list.compute_bounds(widget)
            if not valid:
                return False
            active.motion(y - bounds.get_y())
            return active.drop()
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
            session.toast(_tr("Update the native engine before transferring recycled items"))
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
            session.toast(_tr("These entries are already in that group"))
            return False
        if position >= 0 and ("transfer-position" not in source.vault.capabilities or "transfer-position" not in session.vault.capabilities):
            session.toast(_tr("Update the native engine before positioning groups"))
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
    dialog, header, box = _dialog(_tr("Preparing Transfer"), width=380, height=200)
    box.append(Gtk.Spinner(spinning=True, halign=Gtk.Align.CENTER))
    box.append(Gtk.Label(label=_tr("Preparing an encrypted review…"), wrap=True))
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
        cancel(); dialog.close(); destination.toast(_tr("Finish the current source operation before dragging again"))
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
            dialog = Adw.AlertDialog(heading=_tr("Open Dropped Vaults?"), body="\n".join(Path(path).name for path in vaults), body_use_markup=False)
            dialog.add_response("cancel", _tr("Cancel")); dialog.add_response("open", _tr("Open Vaults"))
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
            dialog = Adw.AlertDialog(heading=_tr("Add Dropped Attachments?"), body_use_markup=False,
                body=_trf('Entry: {arg0}\nTotal: {arg1:,} bytes. All files are added in one encrypted transaction.', arg0=entry.title, arg1=review['size']))
            extra = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            listing = Gtk.TextView(editable=False, cursor_visible=False, wrap_mode=Gtk.WrapMode.WORD_CHAR,
                                   left_margin=12, right_margin=12, top_margin=12, bottom_margin=12)
            listing.get_buffer().set_text("\n\n".join(f'{item["name"]} — {item["size"]:,} bytes\n{item["path"]}' for item in review["files"]))
            extra.append(Gtk.ScrolledWindow(child=listing, min_content_height=80, max_content_height=240,
                propagate_natural_height=True, hscrollbar_policy=Gtk.PolicyType.NEVER, css_classes=["card"], overflow=Gtk.Overflow.HIDDEN))
            replace = Gtk.CheckButton(label=_trf('Replace {arg0} existing attachments with matching names', arg0=review['replacements']))
            if review["replacements"]:
                extra.append(replace)
            dialog.set_extra_child(extra)
            dialog.add_response("cancel", _tr("Cancel")); dialog.add_response("add", _tr("Add Attachments"))
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
