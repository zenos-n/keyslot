"""New-entry preferences and cancellable use of the saved native generator."""
from .i18n import mark as _mark, tr as _tr
import threading

from gi.repository import Adw, Gio, Gtk

from .backend import VaultError
from . import generator_views


def preferences(session, page):
    settings = session.application.startup
    group = Adw.PreferencesGroup(title=_tr("New Entries"))
    updating = False
    for field, title, subtitle in (
        ("inherit_group_icon", _mark("Use the Group Icon"), _mark("Use the selected group's icon until you choose another")),
        ("generate_password_on_create", _mark("Generate a Password Automatically"), _mark("Use your saved password or passphrase generator settings"))):
        row = Adw.SwitchRow(title=_tr(title), subtitle=_tr(subtitle), active=getattr(settings, field))
        def changed(row, _property, field=field):
            nonlocal updating
            if updating:
                return
            try:
                settings.save(settings.remember, settings.login, settings.vault, **{field: row.get_active()})
            except (OSError, ValueError, VaultError) as exc:
                updating = True
                row.set_active(getattr(settings, field))
                updating = False
                session.error(str(exc))
        row.connect("notify::active", changed)
        group.add(row)
    page.add(group)


class Generation:
    def __init__(self, session, dialog, secret, save, box):
        self.session, self.dialog, self.secret, self.save = session, dialog, secret, save
        self.epoch, self.identity = session.epoch, session.vault.identity
        self.generation = session.vault.generation
        self.revision = 0
        self.closed = self.blocked = False
        self.cancelled = threading.Event()
        self.options = None
        self.status = Gtk.Label(xalign=0, wrap=True, visible=False, css_classes=["caption"])
        box.append(self.status)
        menu = Gio.Menu()
        menu.append(_tr("Generator Options…"), "entry-generator.options")
        actions = Gio.SimpleActionGroup()
        action = Gio.SimpleAction.new("options", None)
        action.connect("activate", lambda *_: self.configure())
        actions.add_action(action)
        dialog.insert_action_group("entry-generator", actions)
        self.button = Adw.SplitButton(icon_name="view-refresh-symbolic", menu_model=menu,
            tooltip_text=_tr("Generate Password"), dropdown_tooltip="Generator Options", valign=Gtk.Align.CENTER)
        self.button.connect("clicked", lambda *_: self.request())
        secret.add_suffix(self.button)
        secret.connect("changed", self.changed)
        dialog._clear_sensitive_fields = self.cancel
        dialog.connect("closed", self.on_closed)
        dialog.connect("close-attempt", self.close_attempt)

    def changed(self, *_):
        self.revision += 1
        self.status.set_visible(False)

    def current(self, active=True):
        return (not self.closed and not self.session.jobs.closed and self.session.vault.unlocked
                and self.session.epoch == self.epoch and self.session.vault.identity is self.identity
                and self.session.vault.generation == self.generation
                and (not active or self.session.active))

    def busy(self, value):
        self.blocked = value
        self.save.set_sensitive(not value)
        self.button.set_sensitive(not value)
        self.dialog.set_can_close(not value)

    def message(self, value, warning=False):
        self.status.set_label(value)
        self.status.set_visible(bool(value))
        if warning:
            self.status.add_css_class("warning")
        else:
            self.status.remove_css_class("warning")

    def cancel(self):
        self.closed = True
        self.cancelled.set()
        if self.options:
            child, self.options = self.options, None
            from .application import clear_dialog_fields
            clear_dialog_fields(child)
            child.force_close()

    def on_closed(self, dialog):
        from .application import clear_dialog_fields
        clear_dialog_fields(dialog)

    def close_attempt(self, *_):
        from .application import clear_dialog_fields
        clear_dialog_fields(self.dialog)
        self.dialog.force_close()

    def apply(self, value, revision):
        if not self.current():
            return False
        if self.revision != revision:
            self.message("Kept your edited password. Generate again to replace it.")
            return False
        self.secret.set_text(value)
        return True

    def failed(self, message):
        if self.current(False):
            self.busy(False)
            self.message(message)

    def request(self):
        if not self.current() or self.blocked or self.session.busy:
            return
        revision, cancelled = self.revision, self.cancelled
        self.message("")
        self.busy(True)
        def perform():
            settings = generator_views.saved_settings(self.session.application.startup, strict=True)
            if cancelled.is_set():
                raise VaultError("Password generation was cancelled.")
            return self.session.vault.generate(**generator_views.parameters(settings), details=True)
        def generated(data):
            if not self.current(False):
                return
            self.busy(False)
            if self.apply(data["value"], revision) and data.get("wordlist_valid") is False:
                self.message("This word list contains fewer than 1296 distinct words. Review Generator Options.", warning=True)
        if not self.session.run_job(perform, generated, self.failed):
            self.busy(False)

    def configure(self):
        if not self.current() or self.blocked or self.session.busy:
            return
        revision = self.revision
        self.busy(True)
        def applied(value):
            child, self.options = self.options, None
            if self.current(False):
                self.busy(False)
                if value is not None:
                    self.apply(value, revision)
            if value is not None and child:
                from .application import clear_dialog_fields
                clear_dialog_fields(child)
                child.force_close()
        self.options = generator_views.show(self.session, on_apply=applied)
        if self.options is None:
            self.busy(False)
