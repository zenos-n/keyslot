"""Selected-entry previews: explicit reveal, bounded native values and lock-safe delivery."""
from .i18n import mark as _mark, tr as _tr, trf as _trf
import weakref
from gi.repository import Adw, GLib, Gtk
from .backend import VaultError

MASK = "••••••"


class Field:
    def __init__(self, controller, entry, name, title, hidden, notes=False):
        self.controller, self.entry, self.name, self.title = controller, entry, name, title
        self.automatic = not hidden
        self.wanted, self.loaded, self.closed = not hidden, False, False
        self.serial, self.empty, self.muting = 0, None, False
        self.row = Adw.ActionRow(title=title, use_markup=False)
        if not notes:
            self.row.add_css_class("property")
            if name == "Password":
                self.row.add_css_class("monospace")
        self.toggle = Gtk.ToggleButton(icon_name="view-reveal-symbolic", tooltip_text=_trf("Show {field}", field=title),
                                       valign=Gtk.Align.CENTER, active=not hidden, visible=hidden)
        self.toggle.connect("toggled", self._toggled)
        self.row.add_suffix(self.toggle)
        copy = Gtk.Button(icon_name="edit-copy-symbolic", tooltip_text=_trf("Copy {field}", field=title), valign=Gtk.Align.CENTER)
        copy.connect("clicked", lambda *_: controller.session.run_job(
            lambda: controller.session.vault.attribute(entry, name), controller.session.copy_entry))
        self.row.add_suffix(copy)
        self.buffer = None
        if notes:
            view = Gtk.TextView(editable=False, cursor_visible=False, wrap_mode=Gtk.WrapMode.WORD_CHAR,
                left_margin=12, right_margin=12, top_margin=12, bottom_margin=12,
                monospace=controller.session.application.startup.monospace_notes)
            view.update_property([Gtk.AccessibleProperty.LABEL], [_tr("Notes")])
            self.buffer = view.get_buffer()
            self.buffer.set_enable_undo(False)
            view.connect("copy-clipboard", self._copy_selection, "copy-clipboard")
            view.connect("cut-clipboard", self._copy_selection, "cut-clipboard")
            self.widget = Adw.PreferencesGroup()
            self.widget.add(self.row)
            self.widget.add(Gtk.ScrolledWindow(child=view, min_content_height=72, max_content_height=240,
                propagate_natural_height=True, hscrollbar_policy=Gtk.PolicyType.NEVER,
                css_classes=["card"], overflow=Gtk.Overflow.HIDDEN))
        else:
            self.widget = self.row
        self.mask()
        if self.wanted:
            self._text(_tr("Loading…"))
        controller.add(self)

    def _text(self, value, status=""):
        value = value.replace("\0", "␀")
        if self.buffer is not None:
            self.buffer.set_text(value)
            self.row.set_subtitle(status)
        else:
            self.row.set_subtitle(value + ("\n" + status if status else ""))

    def _copy_selection(self, view, signal):
        # Route explicit note selections through the same owned clipboard deadline as Copy.
        view.stop_emission_by_name(signal)
        if self.closed or not self.wanted or not self.loaded or not self.controller.valid() or not self.buffer.get_has_selection():
            return
        start, end = self.buffer.get_selection_bounds()[-2:]
        self.controller.session.touch()
        self.controller.session.copy(self.buffer.get_text(start, end, False))

    def mask(self):
        placeholder = self.controller.session.application.startup.password_empty_placeholder
        self._text("" if self.name == "Password" and self.empty is True and not placeholder else MASK)

    def _toggled(self, *_):
        if self.closed or self.muting:
            return
        self.controller.session.touch()
        self.serial += 1
        self.wanted, self.loaded = self.toggle.get_active(), False
        self.toggle.set_icon_name("view-conceal-symbolic" if self.wanted else "view-reveal-symbolic")
        self.toggle.set_tooltip_text(_trf("Hide {field}", field=self.title) if self.wanted else _trf("Show {field}", field=self.title))
        self.mask()
        if self.wanted:
            self._text(_tr("Loading…"))
        self.controller.schedule()

    def conceal(self, *, closing=False):
        self.serial += 1
        self.wanted = self.loaded = False
        self.closed = closing
        self.muting = True
        self.toggle.set_active(False)
        self.toggle.set_icon_name("view-reveal-symbolic")
        self.toggle.set_tooltip_text(_trf("Show {field}", field=self.title))
        self.muting = False
        self.mask()

    def display(self, value, truncated):
        self.loaded = True
        self._text(value, "Preview truncated; Copy uses the complete field." if truncated else "")


class Previews:
    def __init__(self, session):
        self.session = session
        self.rows = []
        self.epoch, self.timer = 0, 0
        self.pending = None
        self.closed = False
        self.entry = self.snapshot = None
        self.session_epoch = self.generation = None
        self.meta_needed = True
        if session.host_window:
            session.host_window.connect("notify::visible", lambda window, _prop: self.clear() if not window.get_visible() else None)
            session.host_window.connect("notify::is-active", self._focus)

    def _focus(self, window, _property):
        if self.closed:
            return
        view = self.session.window
        if not window.is_active():
            for row in self.rows:
                if not row.automatic:
                    row.conceal()
        elif not self.rows and view and self.session.vault.unlocked and view.selected_entry and not view.selection_mode:
            view.render_detail(view.selected_entry)

    def clear(self):
        self.epoch += 1
        if self.timer:
            GLib.source_remove(self.timer)
            self.timer = 0
        for row in self.rows:
            row.conceal(closing=True)
        self.rows.clear()
        self.pending = None
        self.entry = self.snapshot = None
        self.meta_needed = True

    def close(self):
        self.closed = True
        self.clear()

    def add(self, row):
        if not self.rows:
            self.entry = row.entry
            self.snapshot = weakref.ref(self.session.vault.snapshot)
            self.session_epoch, self.generation = self.session.epoch, self.session.vault.generation
        self.rows.append(row)
        self.schedule()

    def valid(self):
        return (not self.closed and self.rows and not self.session.jobs.closed and self.session.vault.unlocked
                and self.session.host_window.get_visible() and self.session.epoch == self.session_epoch
                and self.session.vault.generation == self.generation and self.snapshot() is self.session.vault.snapshot
                and self.session.window.selected_entry is self.entry and not self.session.window.selection_mode)

    def schedule(self):
        if not self.closed and self.rows and not self.timer:
            if self.meta_needed or any(row.wanted and not row.loaded for row in self.rows):
                self.timer = GLib.timeout_add(100, self._flush)

    def _flush(self):
        if not self.valid():
            self.timer = 0
            self.clear()
            return GLib.SOURCE_REMOVE
        if self.pending:
            self.timer = 0
            return GLib.SOURCE_REMOVE
        if self.session.jobs.busy:
            return GLib.SOURCE_CONTINUE
        requested = {row: row.serial for row in self.rows if row.wanted and not row.loaded}
        if not requested and not self.meta_needed:
            self.timer = 0
            return GLib.SOURCE_REMOVE
        epoch, entry, token = self.epoch, self.entry, object()
        self.pending = token
        def finished():
            if self.pending is token:
                self.pending = None
            if epoch != self.epoch:
                return False
            if not self.valid():
                self.clear()
                return False
            return True
        def done(data):
            if not finished():
                return
            self.meta_needed = False
            for row in self.rows:
                if row.name == "Password":
                    row.empty = data["password_empty"]
                    row.toggle.set_sensitive(not row.empty)
                    if not row.wanted:
                        row.mask()
            for row, serial in requested.items():
                if not row.closed and row.wanted and row.serial == serial and row.name in data["values"]:
                    row.display(data["values"][row.name], row.name in data["truncated"])
            self.schedule()
        def failed(message):
            if not finished():
                return
            self.meta_needed = False
            explicit = False
            for row in requested:
                if not row.closed and row.wanted:
                    explicit |= not row.automatic
                    row.loaded = True
                    row._text("Preview unavailable")
            if explicit and self.session.active:
                self.session.error(message)
        # Passive previews never refresh the inactivity timer or queue behind an unbounded foreground backlog.
        names = [row.name for row in requested]
        def load():
            if self.pending is not token or epoch != self.epoch:
                raise VaultError("The preview was cancelled.")
            return self.session.vault.preview_fields(entry, names)
        if not self.session.jobs.run(load,
                                     done, failed, interactive=False):
            self.pending = None
            return GLib.SOURCE_CONTINUE
        self.timer = 0
        return GLib.SOURCE_REMOVE

    def field(self, entry, name, title, *, notes=False):
        settings = self.session.application.startup
        hidden = {"UserName": settings.hide_usernames, "Password": settings.hide_password_preview, "Notes": settings.hide_notes}[name]
        return Field(self, entry, name, title, hidden, notes).widget


def refresh(app):
    for session in app.sessions:
        session.previews.clear()
        if session.vault.unlocked and session.window.snapshot is session.vault.snapshot:
            selected = session.window.selected_entry
            selection = {item.uuid for item in session.window.selected_entries()}
            session.window.render_entries(selected.uuid if selected else None, selection)


def preferences(session, page):
    settings = session.application.startup
    group = Adw.PreferencesGroup(title=_tr("Entry Privacy"), description=_tr("Hidden fields can be revealed individually. Password previews stay masked by default."))
    for name, title in (("hide_usernames", _mark("Hide Usernames")), ("hide_notes", _mark("Hide Notes")),
                        ("hide_password_preview", _mark("Hide Password Previews")), ("monospace_notes", _mark("Use Monospace for Notes")),
                        ("password_empty_placeholder", _mark("Mask Empty Passwords"))):
        row = Adw.SwitchRow(title=_tr(title), active=getattr(settings, name))
        changing = [False]
        def changed(row, _property, name=name, changing=changing):
            if changing[0]:
                return
            previous = getattr(settings, name)
            try:
                settings.save(settings.remember, settings.login, settings.vault, **{name: row.get_active()})
                refresh(session.application)
            except (OSError, ValueError, VaultError) as exc:
                changing[0] = True
                row.set_active(previous)
                changing[0] = False
                session.error(str(exc))
        row.connect("notify::active", changed)
        group.add(row)
    page.add(group)
