"""GNOME presentation of KeePass icon IDs, with portable custom-icon fallback."""
from .i18n import ntrf as _ntrf, tr as _tr, trf as _trf
import os
from gi.repository import Gtk
from .database_views import _dialog
from .passkey_views import _lifetime

# Index is the stable KeePass standard icon ID; only its presentation changes.
STANDARD = (
    "dialog-password-symbolic", "network-workgroup-symbolic", "dialog-warning-symbolic", "network-server-symbolic",
    "edit-paste-symbolic", "preferences-desktop-locale-symbolic", "drive-harddisk-symbolic", "document-edit-symbolic",
    "network-wired-symbolic", "avatar-default-symbolic", "x-office-address-book-symbolic", "camera-photo-symbolic",
    "network-wireless-symbolic", "dialog-password-symbolic", "battery-symbolic", "scanner-symbolic",
    "web-browser-symbolic", "media-optical-symbolic", "video-display-symbolic", "mail-unread-symbolic",
    "preferences-other-symbolic", "x-office-calendar-symbolic", "edit-select-all-symbolic", "image-x-generic-symbolic",
    "network-transmit-receive-symbolic", "folder-documents-symbolic", "document-save-symbolic", "drive-removable-media-symbolic",
    "camera-video-symbolic", "dialog-password-symbolic", "utilities-terminal-symbolic", "printer-symbolic",
    "view-grid-symbolic", "media-playback-start-symbolic", "preferences-system-symbolic", "preferences-desktop-remote-desktop-symbolic",
    "package-x-generic-symbolic", "accessories-calculator-symbolic", "network-workgroup-symbolic", "document-open-recent-symbolic",
    "mail-send-receive-symbolic", "image-x-generic-symbolic", "media-flash-symbolic", "user-trash-symbolic",
    "accessories-text-editor-symbolic", "process-stop-symbolic", "help-browser-symbolic", "package-x-generic-symbolic",
    "folder-symbolic", "folder-open-symbolic", "package-x-generic-symbolic", "changes-allow-symbolic",
    "changes-prevent-symbolic", "emblem-ok-symbolic", "document-edit-symbolic", "image-x-generic-symbolic",
    "x-office-address-book-symbolic", "text-x-generic-symbolic", "security-high-symbolic", "applications-engineering-symbolic",
    "user-home-symbolic", "preferences-system-symbolic", "computer-symbolic", "document-edit-symbolic",
    "computer-symbolic", "computer-symbolic", "wallet-symbolic", "application-certificate-symbolic", "phone-symbolic",
)
PREFIX = "Adwaita:"


def theme():
    result = Gtk.IconTheme.new()
    if directory := os.environ.get("KEYSLOT_ADWAITA_ICONS"):
        result.add_search_path(directory)
    result.set_theme_name("Adwaita")
    return result


def paintable(icon_theme, name, size):
    return icon_theme.lookup_icon(name, [], size, 1, Gtk.TextDirection.NONE, Gtk.IconLookupFlags(0))


def choose(session, callback):
    if session.busy or not session.vault.unlocked:
        return
    icon_theme = session.icons.theme
    names = sorted(name for name in icon_theme.get_icon_names() if name.endswith("-symbolic"))
    dialog, _header, box = _dialog(_tr("Choose Adwaita Icon"), width=540, height=560)
    current = _lifetime(session, dialog)
    box.append(Gtk.Label(label=_tr("Standard equivalents keep their KeePass icon ID. Other icons are embedded in the vault for compatibility with other clients."), wrap=True, xalign=0))
    search = Gtk.SearchEntry(placeholder_text=_tr("Search Adwaita icons"))
    box.append(search)
    grid = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, min_children_per_line=3, max_children_per_line=7,
                       row_spacing=4, column_spacing=4, homogeneous=True, valign=Gtk.Align.START)
    box.append(grid)
    page = [0]
    count = Gtk.Label(xalign=0, css_classes=["dim-label"])
    box.append(count)
    navigation = Gtk.Box(spacing=12, homogeneous=True)
    previous, following = Gtk.Button(label=_tr("Previous")), Gtk.Button(label=_tr("Next"))
    navigation.append(previous); navigation.append(following)
    box.append(navigation)
    def selected(name):
        if not current() or session.busy:
            return
        if name in STANDARD:
            callback({"icon": STANDARD.index(name), "custom_icon": ""})
            dialog.close()
            return
        file = paintable(icon_theme, name, 128).get_file()
        if file is None:
            session.error(_tr("This theme icon has no embeddable image. Choose another icon."))
            return
        def import_icon():
            stream = file.read(None)
            try:
                raw = bytes(stream.read_bytes(8 * 1024 * 1024 + 1, None).get_data())
            finally:
                stream.close(None)
            return session.vault.import_icon_data(raw, PREFIX + name)
        def imported(identifier):
            if current():
                session.icons.clear()
                session.window.show_vault(session.vault.snapshot)
                callback({"custom_icon": identifier})
                dialog.close()
        session.run_job(import_icon, imported)
    def render(*_, reset=False):
        if reset:
            page[0] = 0
        child = grid.get_first_child()
        while child:
            following_child = child.get_next_sibling()
            grid.remove(child)
            child = following_child
        matches = [name for name in names if search.get_text().casefold() in name.casefold()]
        start = page[0] * 70
        for name in matches[start:start + 70]:
            image = Gtk.Image(paintable=paintable(icon_theme, name, 32), pixel_size=32)
            button = Gtk.Button(child=image, tooltip_text=name.removesuffix("-symbolic").replace("-", " "), css_classes=["flat"])
            button.connect("clicked", lambda _button, name=name: selected(name))
            grid.append(button)
        count.set_label(_ntrf('{count} icon', '{count} icons', len(matches)) if matches else _tr("No matching icons"))
        previous.set_sensitive(page[0] > 0)
        following.set_sensitive(start + 70 < len(matches))
    def move(delta):
        page[0] += delta
        render()
    previous.connect("clicked", lambda *_: move(-1))
    following.connect("clicked", lambda *_: move(1))
    search.connect("search-changed", lambda *_: render(reset=True))
    render()
    session.present_dialog(dialog)
