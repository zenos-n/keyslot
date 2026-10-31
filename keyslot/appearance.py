"""Vault-owned icon previews and GNOME icon/appearance editors."""
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from gi.repository import Adw, Gdk, GdkPixbuf, GLib, Gtk
from .backend import Entry, Group, VaultError
from .database_views import _dialog


class IconCache:
    def __init__(self, session):
        self.session = session
        self.epoch = 0
        self.closed = False
        self.owner = session.vault.identity
        self.cache, self.pending = {}, {}
        self.drafts = {}
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="vault-icons")

    def clear(self):
        self.epoch += 1
        self.cache.clear()
        self.pending.clear()

    def close(self):
        self.clear()
        self.drafts.clear()
        self.closed = True
        self.executor.shutdown(wait=False, cancel_futures=True)

    def image(self, item, size=32):
        image = Gtk.Image(icon_name="image-missing-symbolic", pixel_size=size,
                          width_request=size, height_request=size, valign=Gtk.Align.CENTER)
        if self.closed or not self.session.vault.unlocked:
            return image
        if self.owner is not self.session.vault.identity:
            self.clear()
            self.owner = self.session.vault.identity
        key = item.custom_icon or item.icon
        if key in self.cache:
            self._paint(image, self.cache[key], size)
            return image
        if key in self.pending:
            self.pending[key].append((image, size))
            return image
        self.pending[key] = [(image, size)]
        epoch, generation = self.epoch, self.session.vault.generation
        def load():
            if epoch != self.epoch or self.closed:
                return None
            with self.session.vault.operation(generation):
                return self.session.vault.icon(item.icon, item.custom_icon)
        future = self.executor.submit(load)
        def done():
            if self.closed or epoch != self.epoch or not self.session.vault.unlocked:
                return False
            waiting = self.pending.pop(key, [])
            try:
                raw = future.result()
                if raw is None:
                    return False
                loader = GdkPixbuf.PixbufLoader.new_with_type("png")
                loader.write(raw)
                loader.close()
                pixbuf = loader.get_pixbuf()
                if len(self.cache) >= 256:
                    self.cache.pop(next(iter(self.cache)))
                self.cache[key] = pixbuf
                for widget, size in waiting:
                    if widget.get_root() is not None:
                        self._paint(widget, pixbuf, size)
            except (VaultError, GLib.Error, OSError):
                pass
            return False
        future.add_done_callback(lambda *_: GLib.idle_add(done))
        return image

    @staticmethod
    def _paint(image, pixbuf, size):
        width, height = pixbuf.get_width(), pixbuf.get_height()
        scale = size / max(width, height)
        scaled = pixbuf.scale_simple(max(1, round(width * scale)), max(1, round(height * scale)), GdkPixbuf.InterpType.BILINEAR)
        image.set_from_paintable(Gdk.Texture.new_for_pixbuf(scaled))


def choose_icon(session, callback, value=None, offset=0, dialog=None, website=None, current=None):
    if session.busy or not session.vault.unlocked:
        return
    if value is None:
        session.run_job(lambda: session.vault.icons(offset),
                        lambda value: choose_icon(session, callback, value, offset, dialog, website, current))
        return
    if dialog:
        dialog.close()
    dialog, header, box = _dialog("Choose Icon", width=540, height=600)
    def choose(values):
        callback(values)
        dialog.close()
    standard = Adw.PreferencesGroup(title="Standard Icons")
    grid = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, max_children_per_line=8,
                       min_children_per_line=4, row_spacing=4, column_spacing=4, homogeneous=True)
    for icon in value["standard"]:
        item = SimpleNamespace(icon=icon["icon"], custom_icon="")
        button = Gtk.Button(child=session.icons.image(item, 36), tooltip_text=icon["name"],
                            css_classes=["flat"], valign=Gtk.Align.CENTER)
        button.connect("clicked", lambda *_args, number=icon["icon"]: choose({"icon": number, "custom_icon": ""}))
        grid.append(button)
    standard.add(grid)
    box.append(standard)
    custom = Adw.PreferencesGroup(title="Custom Icons")
    for icon in value["custom"]:
        identifier = icon["custom_icon"]
        item = SimpleNamespace(icon=0, custom_icon=identifier)
        row = Adw.ActionRow(title=GLib.markup_escape_text(icon["name"] or "Custom Icon"),
                            subtitle=f"{icon['uses']} entries, groups or saved versions", activatable=True)
        row.add_prefix(session.icons.image(item, 32))
        row.connect("activated", lambda *_args, identifier=identifier: choose({"custom_icon": identifier}))
        export = Gtk.Button(icon_name="document-save-symbolic", tooltip_text="Export Icon", valign=Gtk.Align.CENTER)
        export.connect("clicked", lambda *_args, identifier=identifier:
            session.choose_file(lambda path: session.run_job(lambda: session.vault.export_icon(identifier, path),
                                                            lambda _: session.toast("Icon exported")), save=True, name="Icon.png"))
        row.add_suffix(export)
        remove = Gtk.Button(icon_name="user-trash-symbolic", tooltip_text="Delete Icon", valign=Gtk.Align.CENTER)
        def delete(_button, identifier=identifier):
            alert = Adw.AlertDialog(heading="Delete Custom Icon?",
                body="Entries, groups and saved versions using this icon will use their default icons.")
            alert.add_response("cancel", "Cancel")
            alert.add_response("delete", "Delete")
            alert.set_close_response("cancel")
            alert.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
            def response(_alert, choice):
                if choice == "delete":
                    previous = session.vault.snapshot
                    def done(snapshot):
                        session.icons.clear()
                        session.window.show_vault(snapshot)
                        callback({"removed": identifier, "previous": previous})
                        choose_icon(session, callback, offset=offset, dialog=dialog, website=website, current=current)
                    session.run_job(lambda: session.vault.remove_icon(identifier), done)
            alert.connect("response", response)
            session.present_dialog(alert)
        remove.connect("clicked", delete)
        row.add_suffix(remove)
        custom.add(row)
    box.append(custom)
    if value["total"] > 100:
        page = Gtk.Box(spacing=12, homogeneous=True)
        for label, target in (("Previous", max(0, offset - 100)), ("Next", offset + 100)):
            button = Gtk.Button(label=label, sensitive=target != offset and target < value["total"])
            button.connect("clicked", lambda *_args, target=target: choose_icon(session, callback, offset=target, dialog=dialog, website=website, current=current))
            page.append(button)
        box.append(page)
    def imported(identifier):
        session.window.show_vault(session.vault.snapshot)
        choose({"custom_icon": identifier})
    button = Gtk.Button(label="Import Icon…", valign=Gtk.Align.CENTER)
    button.connect("clicked", lambda *_: session.choose_file(lambda path:
        session.run_job(lambda: session.vault.import_icon(path), imported)))
    header.pack_start(button)
    from . import icon_views
    download = Gtk.Button(label="Download Website Icon…", valign=Gtk.Align.CENTER)
    download.connect("clicked", lambda *_: icon_views.download(session, imported, website() if website else ""))
    box.append(download)
    def cleaned(snapshot):
        session.icons.clear()
        session.window.show_vault(snapshot)
        choose_icon(session, callback, dialog=dialog, website=website, current=current)
    clean = Gtk.Button(label="Remove Unused Icons…", valign=Gtk.Align.CENTER)
    def cleanup(*_):
        keep = {values["custom_icon"] for values in session.icons.drafts.values() if values["custom_icon"]}
        if current and current():
            keep.add(current())
        icon_views.cleanup(session, keep, cleaned)
    clean.connect("clicked", cleanup)
    box.append(clean)
    session.present_dialog(dialog)


def icon_row(session, item, website=None, dialog=None):
    values = {"icon": item.icon, "custom_icon": item.custom_icon}
    if dialog:
        token = object()
        session.icons.drafts[token] = values
        dialog.connect("closed", lambda *_: session.icons.drafts.pop(token, None))
    row = Adw.ActionRow(title="Icon", activatable=True)
    row.target = item
    preview = session.icons.image(item, 32)
    row.add_prefix(preview)
    def chosen(selected):
        nonlocal preview
        if "removed" in selected:
            if isinstance(row.target, Entry):
                previous = next((e for e in selected["previous"].entries if e.uuid == row.target.uuid), None)
                if row.target == previous:
                    row.target = next(e for e in session.vault.snapshot.entries if e.uuid == row.target.uuid)
            if values["custom_icon"] != selected["removed"]:
                return
            selected = {"icon": 48 if isinstance(item, Group) else 0, "custom_icon": ""}
        values.update(selected)
        row.remove(preview)
        preview = session.icons.image(SimpleNamespace(**values), 32)
        row.add_prefix(preview)
    row.connect("activated", lambda *_: choose_icon(session, chosen, website=website, current=lambda: values["custom_icon"]))
    row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
    return row, values


def rgba(value):
    color = Gdk.RGBA()
    if value.startswith("#") and len(value) == 9:  # KeePass stores alpha first.
        value = "#" + value[3:] + value[1:3]
    return color if color.parse(value) else None


def color_row(title, value):
    row = Adw.EntryRow(title=title, text=value)
    picker = Gtk.ColorDialogButton(dialog=Gtk.ColorDialog(with_alpha=True), valign=Gtk.Align.CENTER)
    updating = [False]
    def refresh(*_):
        color = rgba(row.get_text())
        if color is None:
            found, color = row.get_style_context().lookup_color("window_bg_color" if title == "Background Color" else "window_fg_color")
            if not found:
                color = row.get_style_context().get_color()
        updating[0] = True
        picker.set_rgba(color)
        updating[0] = False
    def selected(*_):
        if updating[0]:
            return
        color = picker.get_rgba()
        channels = [max(0, min(255, round(channel * 255))) for channel in (color.red, color.green, color.blue)]
        prefix = f"{round(color.alpha * 255):02x}" if color.alpha < 1 else ""
        row.set_text("#" + prefix + "".join(f"{channel:02x}" for channel in channels))
    picker.connect("notify::rgba", selected)
    row.connect("changed", refresh)
    refresh()
    row.add_suffix(picker)
    clear = Gtk.Button(icon_name="edit-clear-symbolic", tooltip_text="Use Default Color", valign=Gtk.Align.CENTER)
    clear.connect("clicked", lambda *_: row.set_text(""))
    row.add_suffix(clear)
    return row


def style_row(row, entry):
    declarations = []
    for name, value in (("color", entry.foreground), ("background-color", entry.background)):
        if color := rgba(value):
            declarations.append(name + ": " + color.to_string())
    if declarations:
        provider = Gtk.CssProvider()
        provider.load_from_string("row.entry-colored:not(:selected) {" + ";".join(declarations) + ";}")
        row.add_css_class("entry-colored")
        row.get_style_context().add_provider(provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
