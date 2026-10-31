"""Group browsing and native search controls; queries and sensitive switches stay ephemeral."""
import json
from gi.repository import Adw, GLib, Gtk
from .backend import VaultError
from .configuration import SEARCH_KEYS
from .startup import _write


class SearchOptions:
    def __init__(self, view):
        self.view, self.session = view, view.app
        startup = self.session.application.startup
        self.storage = getattr(startup, "storage", None)
        self.path = startup.directory / "keyslot" / "search.json"
        self.defaults = {name: default for name, (_key, default) in SEARCH_KEYS.items()}
        problem = ""
        try:
            saved = self.storage.read_search() if self.storage else self.read_file()
        except (OSError, ValueError, VaultError) as error:
            saved, problem = dict(self.defaults), str(error)
        self.saved = dict(saved)
        self.last_query = ""
        self.previous, self.selection = None, set()
        self.state = "idle"
        self.scope = Adw.ComboRow(title="Search Scope", model=Gtk.StringList.new(
            ["Selected Group", "Selected Group and Subgroups", "Entire Vault"]))
        self.scope.set_selected(2 if not saved["limit_group"] else 1 if saved["search_recursive"] else 0)
        self.recursive = Adw.SwitchRow(title="Show Subgroup Entries", active=saved["recursive"])
        self.wait = Adw.SwitchRow(title="Press Enter to Search", active=saved["wait_enter"])
        self.case = Adw.SwitchRow(title="Case Sensitive")
        self.protected = Adw.SwitchRow(title="Search Passwords", subtitle="Also searches protected custom fields", active=True)
        self.recycled = Adw.SwitchRow(title="Include Recycle Bin")
        self.disabled = Adw.SwitchRow(title="Search Disabled Groups", subtitle="Ignore groups' search-exclusion settings")
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18,
                         margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
        browsing = Adw.PreferencesGroup(title="Browsing")
        browsing.add(self.recursive)
        content.append(browsing)
        searching = Adw.PreferencesGroup(title="Searching")
        for row in (self.scope, self.wait, self.case, self.protected, self.recycled, self.disabled):
            searching.add(row)
        content.append(searching)
        content.append(Gtk.Label(label="Queries and the case, protected-field, recycle-bin and disabled-group switches are not remembered.",
                                 wrap=True, xalign=0, css_classes=["dim-label"]))
        syntax = Gtk.Button(label="Search Syntax…", valign=Gtk.Align.CENTER)
        syntax.connect("clicked", self.help)
        content.append(syntax)
        self.problem = Gtk.Label(label=problem, visible=bool(problem), wrap=True, xalign=0, css_classes=["warning"])
        content.append(self.problem)
        self.popover = Gtk.Popover(child=Gtk.ScrolledWindow(child=content, hscrollbar_policy=Gtk.PolicyType.NEVER,
            propagate_natural_height=True, max_content_height=540, min_content_width=320))
        self.button = Gtk.MenuButton(icon_name="view-filter-symbolic", tooltip_text="View and Search Options",
                                     popover=self.popover, valign=Gtk.Align.CENTER)
        self.status = Gtk.Label(xalign=0, wrap=True, visible=False, margin_start=12, margin_end=12,
                                margin_bottom=12, css_classes=["dim-label"])
        self.scope.connect("notify::selected", self.options_changed)
        for control in (self.wait, self.case, self.protected, self.recycled, self.disabled):
            control.connect("notify::active", self.options_changed)
        self.recursive.connect("notify::active", lambda *_: self.view.render_entries())
        self.popover.connect("closed", lambda *_: self.persist())
        view.search.connect("activate", lambda *_: self.changed(force=True))

    def read_file(self):
        if not self.path.exists():
            return dict(self.defaults)
        data = json.loads(self.path.read_text())
        if not isinstance(data, dict) or set(data) != set(self.defaults) or any(type(value) is not bool for value in data.values()):
            raise VaultError("Saved search options are invalid; defaults are active.")
        return data

    def preferences(self):
        scope = self.scope.get_selected()
        return dict(limit_group=scope != 2, search_recursive=scope != 0,
                    recursive=self.recursive.get_active(), wait_enter=self.wait.get_active())

    def persist(self):
        changes = {name: value for name, value in self.preferences().items() if value != self.saved[name]}
        if not changes or self.session.jobs.closed:
            return
        expected = {name: self.saved[name] for name in changes}
        def save():
            if self.storage:
                self.storage.write_search(changes)
            else:
                with self.session.application.startup.mutex:
                    current = self.read_file()
                    if any(current[name] != expected[name] and current[name] != value for name, value in changes.items()):
                        raise VaultError("Search defaults changed in another window. Reopen Keyslot before saving these defaults.")
                    _write(self.path, json.dumps(dict(current, **changes)) + "\n")
        def done(_result):
            self.saved.update(changes)
            self.problem.set_visible(False)
        def failed(message):
            self.problem.set_label("Search options could not be saved: " + message)
            self.problem.set_visible(True)
            self.session.toast("Search options are active but could not be saved")
        if not self.session.jobs.run(save, done, failed, interactive=False):
            failed("The vault is busy. Reopen and close these options to try again.")

    def help(self, *_):
        alert = Adw.AlertDialog(heading="Search Syntax", body_use_markup=False, body=(
            'Words are combined with AND. Put a phrase in double quotes.\n\n'
            'title:mail\nusername:alice\nurl:example.org\ngroup:work\ntag:banking\nis:expired\nhas:totp\n'
            '-tag:archive excludes a term.\n_Account:123 searches a custom field.\n\n'
            'Search Passwords controls password and protected custom-field searches. '
            'Group scope and search-exclusion settings follow the options in this menu.'))
        alert.add_response("close", "Close")
        self.popover.popdown()
        self.session.present_dialog(alert)

    def options_changed(self, *_):
        self.changed(force=not self.wait.get_active())

    def message(self, text="", error=False):
        self.status.set_label(text)
        self.status.set_visible(bool(text))
        (self.status.add_css_class if error else self.status.remove_css_class)("error")

    def clear(self):
        self.view.search_generation += 1
        self.last_query, self.previous, self.selection = "", None, set()
        self.state = "idle"
        self.protected.set_active(True)
        self.recycled.set_active(False)
        self.disabled.set_active(False)
        self.popover.popdown()
        self.message()

    def changed(self, *, passive=False, force=False):
        view = self.view
        view.search_generation += 1
        generation = view.search_generation
        query = view.search.get_text().strip()
        if view.snapshot and view.entry_count:
            self.previous = view.selected_entry.uuid if view.selected_entry else None
            self.selection = {entry.uuid for entry in view.selected_entries()}
        view.search_matches = None
        if not view.snapshot or not query:
            if not view.snapshot:
                self.previous, self.selection = None, set()
            self.last_query = ""
            self.state = "idle"
            self.message()
            view.render_entries(self.previous, self.selection)
            return
        if self.wait.get_active() and not force and (not passive or query != self.last_query):
            self.state = "waiting"
            self.message("Press Enter to search")
            view.render_entries()
            return
        self.last_query = query
        self.state = "pending"
        self.message("Searching…")
        view.render_entries()
        scope = self.scope.get_selected()
        options = dict(group=(view.selected_group or view.snapshot.root) if scope != 2 else "", recursive=scope != 0,
                       case_sensitive=self.case.get_active(), protected=self.protected.get_active(),
                       recycled=self.recycled.get_active(), force=self.disabled.get_active())
        def start():
            if generation != view.search_generation or not view.snapshot or query != view.search.get_text().strip():
                return False
            if self.session.busy:
                GLib.timeout_add(100, start)
                return False
            def search():
                if generation != view.search_generation:
                    return None
                return self.session.vault.search(query, **options)
            def done(matches):
                if generation != view.search_generation or not view.snapshot or matches is None or query != view.search.get_text().strip():
                    return
                view.search_matches = set(matches)
                self.state = "ready"
                self.message()
                view.render_entries(self.previous, self.selection)
            def failed(message):
                if generation == view.search_generation and view.snapshot and query == view.search.get_text().strip():
                    self.state = "error"
                    self.message(message, error=True)
                    view.render_entries()
            accepted = (self.session.jobs.run(search, done, failed, interactive=False) if passive
                        else self.session.run_job(search, done, failed))
            if not accepted:
                GLib.timeout_add(100, start)
            return False
        start()

    def browsing_groups(self):
        selected = self.view.selected_group
        if selected is None:
            return None
        groups = {selected}
        if self.recursive.get_active():
            children = {}
            for group in self.view.snapshot.groups:
                children.setdefault(group.parent, []).append(group.identity)
            pending = [selected]
            while pending:
                for child in children.get(pending.pop(), ()):
                    if child not in groups:
                        groups.add(child)
                        pending.append(child)
        return groups
