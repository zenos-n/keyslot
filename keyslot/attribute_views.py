"""Optional name-only custom attribute suggestions from the unlocked vault."""
import json
from gi.repository import Adw, GLib, Gtk
from .backend import VaultError
from .passkey_views import _lifetime
from .startup import _write

KEY = "AutocompleteSuggestions"


def setting(startup, value=None):
    if value is not None and type(value) is not bool:
        raise VaultError("Choose whether attribute names should be suggested.")
    profile = startup.storage
    with profile.mutex if profile else startup.mutex:
        if profile:
            request = {"path": profile.paths["global"], "defaults": {KEY: True}}
            before = profile._request(False, [request], timeout=5)[0]["values"]
            if value is None:
                return before[KEY]
            profile._request(True, [request | {"values": {KEY: value}, "expected": before}])
        else:
            path = startup.directory / "keyslot" / "attribute-suggestions.json"
            if value is None:
                result = json.loads(path.read_text()) if path.exists() else True
                if type(result) is not bool:
                    raise VaultError("Saved attribute suggestion settings are invalid.")
                return result
            _write(path, json.dumps(value) + "\n")
    return value


def preferences(session, page, dialog):
    group = Adw.PreferencesGroup(title="Editing")
    row = Adw.SwitchRow(title="Suggest Attribute Names", subtitle="Offer names used by other entries; values are never suggested", sensitive=False)
    updating = [True]
    closed = [False]
    dialog.connect("closed", lambda *_: closed.__setitem__(0, True))
    def loaded(value):
        if closed[0]:
            return
        updating[0] = True
        row.set_active(value)
        row.set_sensitive(True)
        updating[0] = False
    def failed(message):
        if closed[0]:
            return
        row.set_subtitle(message)
        row.set_sensitive(False)
    def changed(*_):
        if updating[0]:
            return
        value = row.get_active()
        if session.busy:
            loaded(not value)
            session.toast("Wait for the current operation to finish")
            return
        row.set_sensitive(False)
        def error(message):
            loaded(not value)
            session.error(message)
        if not session.run_job(lambda: setting(session.application.startup, value), loaded, error):
            loaded(not value)
    row.connect("notify::active", changed)
    group.add(row)
    page.add(group)
    def read():
        if closed[0] or session.jobs.closed:
            return False
        return not session.jobs.run(lambda: setting(session.application.startup), loaded, failed, interactive=False)
    if read():
        GLib.timeout_add(100, read)


def suggestions(session, dialog, entry, field):
    current = _lifetime(session, dialog)
    content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, width_request=300,
                      margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
    search = Gtk.SearchEntry(placeholder_text="Find an attribute name")
    content.append(search)
    rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"], valign=Gtk.Align.START)
    scrolled = Gtk.ScrolledWindow(child=rows, hscrollbar_policy=Gtk.PolicyType.NEVER,
                                  propagate_natural_height=True, max_content_height=300)
    content.append(scrolled)
    status = Gtk.Label(wrap=True, xalign=0, css_classes=["dim-label"])
    content.append(status)
    navigation = Gtk.Box(spacing=8, homogeneous=True)
    previous, following = Gtk.Button(label="Previous"), Gtk.Button(label="Next")
    navigation.append(previous); navigation.append(following)
    content.append(navigation)
    popover = Gtk.Popover(child=content)
    menu = Gtk.MenuButton(icon_name="pan-down-symbolic", tooltip_text="Suggest Attribute Names",
                          popover=popover, valign=Gtk.Align.CENTER)
    field.add_suffix(menu)
    state = {"serial": 0, "offset": 0, "enabled": None}
    def valid(serial):
        return current() and popover.get_visible() and serial == state["serial"]
    def load(*_, reset=False):
        if not current() or not popover.get_visible():
            return
        if reset:
            state["offset"] = 0
        state["serial"] += 1
        serial, offset, query = state["serial"], state["offset"], search.get_text()
        previous.set_sensitive(False); following.set_sensitive(False)
        child = rows.get_first_child()
        while child:
            following_child = child.get_next_sibling(); rows.remove(child); child = following_child
        status.set_label("Looking for names…")
        def operation():
            enabled = state["enabled"] if state["enabled"] is not None else setting(session.application.startup)
            return session.vault.attribute_suggestions(entry, query, offset) if enabled else None
        def done(data):
            if not valid(serial):
                return
            state["enabled"] = data is not None
            if data is None:
                status.set_label("Attribute suggestions are disabled in Preferences.")
                return
            def selected(name):
                if current():
                    field.set_text(name)
                    popover.popdown()
                    field.grab_focus()
            for name in data["names"]:
                row = Adw.ActionRow(title=name, use_markup=False, title_lines=2, activatable=True)
                row.connect("activated", lambda _row, name=name: selected(name))
                rows.append(row)
            message = f'{data["total"]} matching names' if data["total"] else "No unused matching names in this vault. Enter any new name directly."
            if data["omitted"]:
                message += " Some oversized names are not shown."
            status.set_label(message)
            previous.set_sensitive(offset > 0)
            following.set_sensitive(offset + len(data["names"]) < data["total"])
        def failed(message):
            if valid(serial):
                status.set_label(message)
        def start():
            if not valid(serial):
                return False
            return not session.jobs.run(operation, done, failed, interactive=False)
        if start():
            GLib.timeout_add(100, start)
    def opened(*_):
        state["enabled"] = None
        content.set_size_request(max(220, min(300, (session.host_window.get_width() or 1180) - 72)), -1)
        search.set_text(field.get_text())
        load(reset=True)
    def move(delta):
        state["offset"] += delta
        load()
    search.connect("search-changed", lambda *_: load(reset=True))
    previous.connect("clicked", lambda *_: move(-100))
    following.connect("clicked", lambda *_: move(100))
    popover.connect("show", opened)
    popover.connect("closed", lambda *_: state.__setitem__("serial", state["serial"] + 1))
