from __future__ import annotations

from collections import Counter
from pathlib import Path
from types import SimpleNamespace
import sys

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk

from . import APP_ID, ICON_NAME, VERSION
from .backend import VaultError
from .core_backend import Vault, EngineError
from .session import SessionJobs
from . import database_views, passkey_views, ssh_views, autotype_views, keeshare_views, appearance, url_views, history_views, totp_views, reference_views, generator_views

INTERFACE = "com.neg_zero.keyslot.Vault1"
OBJECT_PATH = "/com/neg_zero/keyslot/Vault1"
DBUS_XML = f'''<node><interface name="{INTERFACE}">
  <method name="Show"/><method name="Lock"/><method name="Quit"/><method name="AutoType"/>
  <property name="Locked" type="b" access="read"/>
  <property name="Busy" type="b" access="read"/>
  <property name="Background" type="b" access="read"/>
</interface></node>'''


def button(icon, tooltip, callback, css=None):
    b = Gtk.Button(icon_name=icon, tooltip_text=tooltip, valign=Gtk.Align.CENTER)
    b.connect("clicked", lambda *_: callback())
    if css:
        b.add_css_class(css)
    return b


def margins(widget, size=18):
    for edge in ("top", "bottom", "start", "end"):
        getattr(widget, "set_margin_" + edge)(size)
    return widget


def scroll(widget, natural=False):
    return Gtk.ScrolledWindow(child=widget, hscrollbar_policy=Gtk.PolicyType.NEVER,
                              vexpand=True, propagate_natural_height=natural,
                              max_content_height=640 if natural else -1)


def clear(box):
    while box.get_first_child():
        box.remove(box.get_first_child())


def clear_dialog_fields(dialog):
    # shortcut: these dialogs save explicitly; register dedicated clearers before adding live-bound preferences.
    if clearer := getattr(dialog, "_clear_sensitive_fields", None):
        clearer()
    widgets = [dialog]
    while widgets:
        widget = widgets.pop()
        child = widget.get_first_child()
        while child:
            widgets.append(child)
            child = child.get_next_sibling()
        if isinstance(widget, Gtk.Editable):
            if widget.find_property("enable-undo"):
                widget.set_property("enable-undo", False)
            widget.set_text("")
        elif isinstance(widget, Gtk.TextView):
            buffer = widget.get_buffer()
            buffer.set_enable_undo(False)
            buffer.set_text("")
        elif isinstance(widget, Gtk.Label):
            widget.set_label("")


def group_labels(groups):
    counts = Counter(g.path for g in groups)
    return [g.path + (f" · {g.uuid[:8]}" if counts[g.path] > 1 else "")
            for g in groups]


class VaultSession:
    def __init__(self, application, vault=None, host_window=None):
        self.application = application
        self.host_window = host_window
        self.needs_attention = False
        self.vault = vault or Vault()
        self.requested_path = None
        self.pending_unlock = None
        self.pending_errors = []
        self.view_epoch = 0
        self.clipboard_provider = None
        self.clipboard_timer = 0
        self.dialogs = []
        self.file_requests = set()
        self.credential_request = None
        self.quick_blob = None
        self.quick_path = None
        self.quick_attempts = 0
        self.window = None
        self.icons = appearance.IconCache(self)
        self.jobs = SessionJobs(self.vault, GLib.idle_add, self._changed, self._clear, self.error)
        self.urls = url_views.UrlController(self)
        self.totp = totp_views.TotpController(self)
        self.window = DatabaseView(self)

    @property
    def busy(self):
        return self.jobs.busy and self.jobs.interactive

    @property
    def epoch(self):
        return self.jobs.epoch

    @property
    def active(self):
        return self.application.active_session is self and self.host_window.get_visible()

    @property
    def path(self):
        return self.requested_path or self.vault.path

    def touch(self, *_):
        self.application.touch()

    def emit_state(self):
        self.application.update_session(self)

    def _changed(self):
        if self.window:
            self.window.set_busy(self.busy)
        self.emit_state()

    def _clear(self):
        self.totp.clear()
        self.urls.clear()
        self.icons.clear()
        if self.credential_request:
            self.credential_request.cancel()
            self.credential_request = None
        self.view_epoch += 1
        self.cancel_file_requests()
        self.clear_clipboard()
        self.close_dialogs()
        if self.window:
            self.window.set_busy(False)
            self.window.show_locked()

    def run_job(self, job, done=None, failed=None):
        self.touch()
        return self.jobs.run(job, done, failed)

    def run_keyring_job(self, operation, done=None, failed=None):
        if self.busy:
            return False
        request = Gio.Cancellable()
        self.credential_request = request
        def perform():
            try:
                return operation(request)
            except GLib.Error as exc:
                raise VaultError("The GNOME login keyring operation failed. Unlock its login keyring in Passwords and Keys and try again.") from exc
        return self.run_job(perform, done, failed)

    def remember_unlocked(self, credentials):
        settings = self.application.startup
        storage = getattr(settings, "storage", None)
        if not settings.remember and not storage:
            return
        path = self.vault.path
        def remember(request):
            if settings.login:
                self.application.login_keyring().store(path, credentials, request)
            request.set_error_if_cancelled()
            if storage:
                storage.remember_components(path, credentials["keyfile"], credentials["yubikey"])
            settings.opened(path)
        self.run_keyring_job(remember)

    def unlock_at_login(self, path):
        def unlock(request):
            credentials = self.application.login_keyring().lookup(path, request)
            request.set_error_if_cancelled()
            return self.vault.unlock(path, **credentials)
        self.run_keyring_job(unlock, self.window.show_vault)

    def lock(self):
        self.jobs.lock()

    def shutdown(self):
        self.totp.clear()
        self.urls.clear()
        self.quick_blob = None
        self.jobs.close()
        self.icons.close()

    def deactivate(self):
        self.totp.clear()
        self.view_epoch += 1
        self.cancel_file_requests()
        self.clear_clipboard()
        self.close_dialogs()

    def activate(self):
        if not self.active or self.jobs.closed:
            return
        self.needs_attention = False
        if self.pending_unlock:
            path, create, options, *key = self.pending_unlock
            self.pending_unlock = None
            self._unlock_dialog(path, create, options, keyfile=key[0] if key else None)
        elif self.pending_errors:
            self.error(self.pending_errors.pop(0))

    def close_dialogs(self):
        for dialog in list(self.dialogs):
            # Clear before the closing animation, including editable undo history.
            clear_dialog_fields(dialog)
            dialog.force_close()
        self.dialogs.clear()

    def present_dialog(self, dialog):
        if not self.active or self.jobs.closed:
            clear_dialog_fields(dialog)
            return
        self.dialogs.append(dialog)
        dialog.connect("closed", lambda d: self.dialogs.remove(d) if d in self.dialogs else None)
        dialog.present(self.host_window)

    def error(self, message):
        if not self.active:
            self.pending_errors.append(message)
            self.needs_attention = True
            self.emit_state()
            return
        dialog = Adw.AlertDialog(heading="Could Not Complete Operation", body=message)
        dialog.add_response("close", "Close")
        self.present_dialog(dialog)

    def toast(self, message):
        self.window.toasts.add_toast(Adw.Toast(title=message))

    def copy(self, value):
        if not self.active or self.jobs.closed:
            return
        if self.clipboard_timer:
            GLib.source_remove(self.clipboard_timer)
            self.clipboard_timer = 0
        clipboard = self.window.get_clipboard()
        self.clipboard_provider = Gdk.ContentProvider.new_for_value(value)
        clipboard.set_content(self.clipboard_provider)
        seconds = self.application.startup.clipboard_seconds
        if seconds:
            self.clipboard_timer = GLib.timeout_add_seconds(seconds, self.clear_clipboard)
        self.toast(f"Copied · clipboard clears in {seconds} seconds" if seconds else "Copied")

    def clear_clipboard(self):
        if self.clipboard_timer:
            GLib.source_remove(self.clipboard_timer)
            self.clipboard_timer = 0
        if self.window and self.clipboard_provider:
            clipboard = self.window.get_clipboard()
            if clipboard.get_content() == self.clipboard_provider:
                clipboard.set_content(None)
        self.clipboard_provider = None
        return GLib.SOURCE_REMOVE

    def choose_file(self, callback, save=False, name=None, kdbx=False, folder=False):
        if not self.active or self.jobs.closed:
            return
        epoch, view_epoch = self.epoch, self.view_epoch
        cancellable = Gio.Cancellable()
        self.file_requests.add(cancellable)
        chooser = Gtk.FileDialog(title="Select Folder" if folder else "Save File" if save else "Open File")
        if name:
            chooser.set_initial_name(name)
        if kdbx:
            file_filter = Gtk.FileFilter(name="KeePass Databases")
            file_filter.add_pattern("*.kdbx")
            filters = Gio.ListStore.new(Gtk.FileFilter)
            filters.append(file_filter)
            chooser.set_filters(filters)

        def selected(dialog, result):
            try:
                file = dialog.select_folder_finish(result) if folder else dialog.save_finish(result) if save else dialog.open_finish(result)
                if epoch == self.epoch and view_epoch == self.view_epoch and not self.jobs.closed and file and file.get_path():
                    callback(file.get_path())
            except GLib.Error:
                pass
            finally:
                self.file_requests.discard(cancellable)
        (chooser.select_folder if folder else chooser.save if save else chooser.open)(self.host_window, cancellable, selected)

    def cancel_file_requests(self):
        for request in list(self.file_requests):
            request.cancel()
        self.file_requests.clear()

    def choose_database(self):
        if self.busy:
            return
        self.choose_file(self.unlock_dialog, kdbx=True)

    def new_database(self):
        if self.busy:
            return
        self.choose_file(lambda p: self.unlock_dialog(p, create=True), save=True,
                         name="Passwords.kdbx", kdbx=True)

    def unlock_dialog(self, path, create=False, import_options=None):
        self.application.open_database(path, create, import_options, preferred=self)

    def _unlock_dialog(self, path, create=False, import_options=None, use_quick=True, keyfile=None):
        if use_quick and not keyfile and not create and not import_options and self.quick_blob and Path(path).resolve() == self.quick_path:
            return self._quick_unlock_dialog(path)
        components = {"keyfile": "", "yubikey": ""}
        storage = getattr(self.application.startup, "storage", None)
        if storage and not create and not import_options:
            try:
                components = storage.key_components(path)
            except (OSError, ValueError, VaultError) as exc:
                self.toast(str(exc))
        keyfile = components["keyfile"] if keyfile is None else keyfile
        self.lock()
        dialog = Adw.Dialog(title="Import Database" if import_options else "New Database" if create else "Unlock Database", content_width=440)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18), 24)
        box.append(Gtk.Image(icon_name="changes-prevent-symbolic", pixel_size=64))
        box.append(Gtk.Label(label=Path(path).name, css_classes=["title-2"], wrap=True))
        group = Adw.PreferencesGroup()
        password = Adw.PasswordEntryRow(title="Master Password")
        group.add(password)
        repeat = Adw.PasswordEntryRow(title="Repeat Password") if create else None
        if repeat:
            group.add(repeat)
        box.append(group)
        advanced = Adw.ExpanderRow(title="Additional Unlock Options", expanded=bool(keyfile or components["yubikey"]))
        selected_key = [keyfile]
        keyfile = Adw.ActionRow(title="Key File", subtitle=Path(keyfile).name if keyfile else "None selected")
        def set_key(p):
            selected_key[0] = p
            keyfile.set_subtitle(Path(p).name if p else "None selected")
        keyfile.add_suffix(button("document-open-symbolic", "Choose Key File", lambda: self.choose_file(set_key)))
        if create:
            def generate_keyfile():
                self.choose_file(lambda target: self.run_job(lambda: self.vault.generate_keyfile(target),
                                                            lambda _: set_key(target)), save=True, name="Passwords.keyx")
            keyfile.add_suffix(button("list-add-symbolic", "Generate Key File", generate_keyfile))
        keyfile.add_suffix(button("edit-clear-symbolic", "Clear Key File", lambda: set_key("")))
        advanced.add_row(keyfile)
        slot = Adw.EntryRow(title="Hardware Key Slot (1 or 2, optional :serial)", text=components["yubikey"])
        no_password = Adw.SwitchRow(title="Key File / Hardware Key Only")
        advanced.add_row(slot)
        advanced.add_row(no_password)
        def password_mode_changed(*_):
            password.set_sensitive(not no_password.get_active())
            if repeat:
                repeat.set_sensitive(not no_password.get_active())
        no_password.connect("notify::active", password_mode_changed)
        advanced_group = Adw.PreferencesGroup()
        advanced_group.add(advanced)
        box.append(advanced_group)
        action = Gtk.Button(label="Import Database" if import_options else "Create Database" if create else "Unlock", css_classes=["suggested-action", "pill"])
        box.append(action)
        seconds = self.application.startup.lock_seconds
        duration = f"{seconds // 60} minutes" if seconds % 60 == 0 else f"{seconds} seconds"
        lock_notice = f"Locks after {duration} of inactivity." if seconds else "Inactivity locking is disabled."
        notice = Gtk.Label(label="Database contents stay on this computer.\n" + lock_notice,
                           wrap=True, css_classes=["dim-label", "caption"])
        box.append(notice)

        def submit(*_):
            if self.busy:
                return
            secret = password.get_text()
            if repeat and not no_password.get_active() and secret != repeat.get_text():
                self.error("The master passwords do not match.")
                return
            key = selected_key[0]
            hardware, key_only = slot.get_text(), no_password.get_active()
            if key_only:
                secret = ""
            password.set_text("")
            if repeat:
                repeat.set_text("")
            dialog.close()
            operation = (lambda: self.vault.create(path, secret, key, hardware, key_only)) if create else (
                lambda: self.vault.unlock(path, secret, key, hardware, key_only))
            if import_options:
                operation = lambda: self.vault.import_database(path, password=secret, keyfile=key, yubikey=hardware,
                                                               no_password=key_only, **import_options)
            def unlocked(snapshot):
                self.window.show_vault(snapshot)
                self.remember_unlocked({"password": secret, "keyfile": key,
                                        "yubikey": hardware, "no_password": key_only})
            self.run_job(operation, unlocked)
        action.connect("clicked", submit)
        password.connect("entry-activated", submit)
        if repeat:
            repeat.connect("entry-activated", submit)
        toolbar.set_content(scroll(box, natural=True))
        dialog.set_child(toolbar)
        dialog.connect("closed", lambda *_: (password.set_text(""), repeat.set_text("") if repeat else None))
        self.present_dialog(dialog)
        password.grab_focus()

    def _quick_unlock_dialog(self, path):
        self.lock()
        dialog = Adw.Dialog(title="Quick Unlock", content_width=440)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18), 24)
        box.append(Gtk.Label(label=Path(path).name, css_classes=["title-2"], wrap=True))
        password = Adw.PasswordEntryRow(title="Short Password")
        group = Adw.PreferencesGroup()
        group.add(password)
        box.append(group)
        unlock = Gtk.Button(label="Unlock", css_classes=["suggested-action", "pill"])
        full = Gtk.Button(label="Use Master Password", css_classes=["pill"])
        box.append(unlock)
        box.append(full)
        def submit(*_):
            if self.busy:
                return
            short = password.get_text()
            password.set_text("")
            blob = self.quick_blob
            dialog.close()
            def open_vault():
                try:
                    return self.vault.quick_unlock(path, blob, short)
                except EngineError as exc:
                    if exc.code == "quick_password":
                        self.quick_attempts += 1
                        remaining = 5 - self.quick_attempts
                        if not remaining:
                            self.quick_blob = None
                            raise VaultError("Quick unlock is disabled after five failed attempts. Use the master password.") from None
                        raise VaultError(f"The short password is incorrect. {remaining} attempts remain.") from None
                    if exc.code == "key_error":
                        self.quick_blob = None
                    raise
            def opened(snapshot):
                self.quick_attempts = 0
                self.window.show_vault(snapshot)
            self.run_job(open_vault, opened)
        def use_full(*_):
            dialog.close()
            self._unlock_dialog(path, use_quick=False)
        unlock.connect("clicked", submit)
        password.connect("entry-activated", submit)
        full.connect("clicked", use_full)
        dialog.connect("closed", lambda *_: password.set_text(""))
        toolbar.set_content(scroll(box, natural=True))
        dialog.set_child(toolbar)
        self.present_dialog(dialog)
        password.grab_focus()

    def focus_search(self):
        if self.vault.unlocked:
            self.window.search.grab_focus()

    def refresh(self):
        if self.vault.unlocked:
            self.run_job(self.vault.refresh, self.window.show_vault)

    def edit_entry(self, entry=None, values=None):
        if not self.vault.unlocked or self.busy:
            return
        if entry and values is None:
            self.run_job(lambda: self.vault.editable_fields(entry), lambda result: self.edit_entry(entry, result))
            return
        values = values or {}
        dialog = Adw.Dialog(title="Edit Entry" if entry else "New Entry", content_width=520, content_height=600)
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        save = Gtk.Button(label="Save", css_classes=["suggested-action"])
        header.pack_end(save)
        toolbar.add_top_bar(header)
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24), 24)
        fields = Adw.PreferencesGroup(title="Login Details")
        title = Adw.EntryRow(title="Title", text=entry.title if entry else "")
        username = Adw.EntryRow(title="Username", text=values.get("UserName", self.vault.snapshot.default_username if not entry else ""))
        url = Adw.EntryRow(title="Website", text=values.get("URL", ""))
        secret = Adw.PasswordEntryRow(title="New Password" if entry else "Password")
        dirty_password = [False]
        secret.connect("changed", lambda *_: dirty_password.__setitem__(0, True))
        secret.add_suffix(button("view-refresh-symbolic", "Generate Password",
            lambda: self.run_job(lambda: self.vault.generate(24), lambda value: secret.set_text(value))))
        for row in (title, username, url, secret):
            fields.add(row)
        box.append(fields)
        if entry:
            fields.set_description("Leave the password unchanged to keep the current one.")
        groups = [g for g in self.vault.snapshot.groups if g.addressable and not g.recycled]
        group = Adw.ComboRow(title="Group", model=Gtk.StringList.new(group_labels(groups)))
        selected = entry.group if entry else (self.window.selected_group or self.vault.snapshot.root)
        group.set_selected(next((i for i, g in enumerate(groups) if g.identity == selected), 0))
        location = Adw.PreferencesGroup()
        location.add(group)
        box.append(location)
        inherited = groups[group.get_selected()]
        initial_icon = inherited.icon if inherited.custom_icon or inherited.icon not in (48, 49) else 0
        icon, decoration = appearance.icon_row(self, entry or SimpleNamespace(icon=initial_icon, custom_icon=inherited.custom_icon))
        visual = Adw.PreferencesGroup(title="Appearance")
        visual.add(icon)
        foreground = appearance.color_row("Text Color", entry.foreground if entry else "")
        background = appearance.color_row("Background Color", entry.background if entry else "")
        visual.add(foreground)
        visual.add(background)
        box.append(visual)
        notes_group = Adw.PreferencesGroup(title="Notes")
        notes = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD_CHAR, top_margin=12, bottom_margin=12,
                             left_margin=12, right_margin=12, height_request=120)
        notes.get_buffer().set_text(values.get("Notes", ""))
        notes_group.add(Gtk.ScrolledWindow(child=notes, css_classes=["card"], overflow=Gtk.Overflow.HIDDEN,
                                            hscrollbar_policy=Gtk.PolicyType.NEVER, min_content_height=120))
        box.append(notes_group)
        advanced = Adw.PreferencesGroup(title="Entry Options")
        tags = Adw.EntryRow(title="Tags (separated by semicolons)", text=entry.tags if entry else "")
        expires = Adw.SwitchRow(title="Expires", active=entry.expires if entry else False)
        expiry = Adw.EntryRow(title="Expiry (ISO 8601)", text=entry.expiry if entry else "")
        override = Adw.EntryRow(title="URL Override", text=entry.override_url if entry else "")
        exclude = Adw.SwitchRow(title="Exclude from Password Reports", active=entry.exclude_reports if entry else False)
        for row in (tags, expires, expiry, override, exclude):
            advanced.add(row)
        box.append(advanced)
        def reference_notes(text):
            buffer = notes.get_buffer()
            buffer.delete_selection(True, True)
            buffer.insert_at_cursor(text, -1)
            notes.grab_focus()
        reference_views.menu(self, dialog, header, [
            ("Title", "T", lambda text: reference_views.insert_text(title, text)),
            ("Username", "U", lambda text: reference_views.insert_text(username, text)),
            ("Password", "P", lambda text: reference_views.insert_text(secret, text)),
            ("Website", "A", lambda text: reference_views.insert_text(url, text)),
            ("Notes", "N", reference_notes),
            ("URL Override", "A", lambda text: reference_views.insert_text(override, text)),
        ], entry)

        def submit(*_):
            if self.busy:
                return
            buf = notes.get_buffer()
            fields = (groups[group.get_selected()].identity, title.get_text(), username.get_text(),
                      url.get_text(), buf.get_text(buf.get_start_iter(), buf.get_end_iter(), True),
                      secret.get_text() if not entry or dirty_password[0] else None, icon.target if entry else None)
            options = {"tags": tags.get_text(), "expires": expires.get_active(), **decoration,
                       "foreground": foreground.get_text(), "background": background.get_text(),
                       "override_url": override.get_text(), "exclude_reports": exclude.get_active()}
            if expires.get_active():
                options["expiry"] = expiry.get_text()
            self.run_job(lambda: self.vault.save_entry(*fields, **options),
                lambda snapshot: (dialog.close(), self.window.show_vault(snapshot), self.toast("Entry saved")))
        save.connect("clicked", submit)
        toolbar.set_content(scroll(box, natural=True))
        dialog.set_child(toolbar)
        dialog.connect("closed", lambda *_: (secret.set_text(""), notes.get_buffer().set_text(""),
                                              title.set_text(""), username.set_text(""), url.set_text("")))
        self.present_dialog(dialog)

    def new_group(self):
        if not self.vault.unlocked or self.busy:
            return
        dialog = Adw.AlertDialog(heading="New Group", body="Create a group inside the selected group.")
        name = Gtk.Entry(placeholder_text="Group name", activates_default=True)
        dialog.set_extra_child(name)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("create", "Create")
        dialog.set_response_appearance("create", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("create")
        parent = self.window.selected_group or self.vault.snapshot.root
        def respond(_dialog, response):
            if response == "create":
                value = name.get_text()
                self.run_job(lambda: self.vault.add_group(parent, value), self.window.show_vault)
        dialog.connect("response", respond)
        self.present_dialog(dialog)

    def delete_entry(self, entry):
        dialog = Adw.AlertDialog(heading="Move Entry to Recycle Bin?", body=entry.title)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Move to Recycle Bin")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.connect("response", lambda _d, response: self.run_job(
            lambda: self.vault.delete_entry(entry), self.window.show_vault) if response == "delete" else None)
        self.present_dialog(dialog)

    def delete_entries(self, entries):
        entries = list(entries)
        if self.busy or not entries or any(entry.recycled for entry in entries):
            return
        heading = "Move Entry to Recycle Bin?" if len(entries) == 1 else f"Move {len(entries)} Entries to Recycle Bin?"
        names = "\n".join(entry.title for entry in entries[:10])
        if len(entries) > 10:
            names += f"\n…and {len(entries) - 10} more"
        dialog = Adw.AlertDialog(heading=heading, body=names, body_use_markup=False)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("recycle", "Move to Recycle Bin")
        dialog.set_close_response("cancel")
        dialog.set_response_appearance("recycle", Adw.ResponseAppearance.DESTRUCTIVE)
        def done(snapshot):
            self.window.set_selection_mode(False)
            self.window.show_vault(snapshot)
        dialog.connect("response", lambda _d, response: self.run_job(
            lambda: self.vault.recycle_entries(entries), done) if response == "recycle" else None)
        self.present_dialog(dialog)

    def move_entries(self, entries):
        entries = list(entries)
        if entries:
            from .transfer_views import choose
            choose(self, entries)

    def move_group(self, group):
        from .transfer_views import choose
        choose(self, source_group=group.identity)

    def move_entry(self, entry):
        if not entry.recycled:
            from .transfer_views import choose
            choose(self, [entry])
            return
        groups = [g for g in self.vault.snapshot.groups if g.addressable and not g.recycled and g.identity != entry.group]
        if not groups:
            self.toast("Create another group first")
            return
        dialog = Adw.AlertDialog(heading="Restore Entry", body="Choose a destination group.")
        dropdown = Gtk.DropDown.new_from_strings(group_labels(groups))
        dialog.set_extra_child(dropdown)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("move", "Move")
        dialog.set_response_appearance("move", Adw.ResponseAppearance.SUGGESTED)
        def respond(_dialog, response):
            if response == "move":
                destination = groups[dropdown.get_selected()].identity
                self.run_job(lambda: self.vault.move_entry(entry, destination), self.window.show_vault)
        dialog.connect("response", respond)
        self.present_dialog(dialog)

    def open_entry_url(self, entry=None, override=False):
        entry = entry or self.window.selected_entry
        if entry:
            self.urls.open(entry, override)

    def confirm_change(self, heading, body, label, operation):
        if self.busy:
            return
        dialog = Adw.AlertDialog(heading=heading, body=body)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("apply", label)
        dialog.set_response_appearance("apply", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.connect("response", lambda _d, response: self.run_job(operation, self.window.show_vault)
                       if response == "apply" else None)
        self.present_dialog(dialog)

    def edit_group(self):
        if not self.vault.unlocked or self.busy:
            return
        selected = self.window.selected_group or self.vault.snapshot.root
        current = next(g for g in self.vault.snapshot.groups if g.identity == selected)
        dialog = Adw.Dialog(title="Edit Group", content_width=480)
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        save = Gtk.Button(label="Save", css_classes=["suggested-action"])
        header.pack_end(save)
        toolbar.add_top_bar(header)
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24), 24)
        fields = Adw.PreferencesGroup()
        name = Adw.EntryRow(title="Name", text=current.name)
        fields.add(name)
        groups = [g for g in self.vault.snapshot.groups if not g.recycled and g.identity != selected]
        parent = Adw.ComboRow(title="Parent Group", model=Gtk.StringList.new(group_labels(groups)))
        parent.set_selected(next((i for i, g in enumerate(groups) if g.identity == current.parent), 0))
        parent.set_sensitive(bool(current.parent))
        fields.add(parent)
        icon, decoration = appearance.icon_row(self, current)
        fields.add(icon)
        box.append(fields)
        options = Adw.PreferencesGroup(title="Group Options")
        tags = Adw.EntryRow(title="Tags (separated by semicolons)", text=current.tags)
        searching = Adw.ComboRow(title="Search Entries", model=Gtk.StringList.new(["Inherit", "Enabled", "Disabled"]))
        searching.set_selected(current.searching)
        expires = Adw.SwitchRow(title="Expires", active=current.expires)
        expiry = Adw.EntryRow(title="Expiry (ISO 8601)", text=current.expiry)
        for option in (tags, searching, expires, expiry):
            options.add(option)
        box.append(options)
        notes = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD_CHAR, height_request=120,
                             left_margin=12, right_margin=12, top_margin=12, bottom_margin=12)
        notes.get_buffer().set_text(current.notes)
        notes_group = Adw.PreferencesGroup(title="Notes")
        notes_group.add(Gtk.ScrolledWindow(child=notes, css_classes=["card"], overflow=Gtk.Overflow.HIDDEN,
                                            hscrollbar_policy=Gtk.PolicyType.NEVER, min_content_height=120))
        box.append(notes_group)
        auto_type = Gtk.Button(label="Auto-Type Settings…")
        auto_type.connect("clicked", lambda *_: autotype_views.settings(self, group=current.identity))
        box.append(auto_type)
        sharing = Gtk.Button(label="KeeShare Settings…", sensitive=not current.recycled)
        sharing.connect("clicked", lambda *_: keeshare_views.settings(self, current.identity))
        box.append(sharing)
        if current.parent and not current.recycled:
            transfer = Gtk.Button(label="Copy or Move Group…")
            transfer.connect("clicked", lambda *_: (dialog.close(), self.move_group(current)))
            box.append(transfer)
        def submit(*_):
            buf = notes.get_buffer()
            values = (current.identity, name.get_text(), buf.get_text(buf.get_start_iter(), buf.get_end_iter(), True),
                      groups[parent.get_selected()].identity if current.parent else None)
            advanced = {**decoration, "tags": tags.get_text(), "searching": searching.get_selected(),
                        "expires": expires.get_active()}
            if expires.get_active():
                advanced["expiry"] = expiry.get_text()
            self.run_job(lambda: self.vault.save_group(*values, **advanced),
                         lambda snapshot: (dialog.close(), self.window.show_vault(snapshot)))
        save.connect("clicked", submit)
        if current.parent and not current.recycled and self.vault.snapshot.recycle_bin_enabled:
            recycle = Gtk.Button(label="Move Group to Recycle Bin…", css_classes=["destructive-action"])
            recycle.connect("clicked", lambda *_: (dialog.close(), self.confirm_change(
                "Recycle Group and Its Contents?", current.name, "Move to Recycle Bin",
                lambda: self.vault.recycle_group(current.identity))))
            box.append(recycle)
        toolbar.set_content(scroll(box, natural=True))
        dialog.set_child(toolbar)
        dialog.connect("closed", lambda *_: (name.set_text(""), notes.get_buffer().set_text("")))
        self.present_dialog(dialog)

    def edit_attribute(self, entry, name=None, info=None):
        if self.busy:
            return
        if name is not None and info is None:
            self.run_job(lambda: self.vault.attribute_info(entry, name, review=True),
                         lambda result: self.edit_attribute(entry, name, result))
            return
        info = info or {}
        dialog = Adw.Dialog(title="Custom Attribute", content_width=440)
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        save = Gtk.Button(label="Save", css_classes=["suggested-action"])
        header.pack_end(save)
        toolbar.add_top_bar(header)
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18), 24)
        fields = Adw.PreferencesGroup()
        key = Adw.EntryRow(title="Name", text=name or "")
        value = Adw.PasswordEntryRow(title="Value", text=info.get("value", ""))
        protected = Adw.SwitchRow(title="Protect Value", active=info.get("protected", True))
        for row in (key, value, protected):
            fields.add(row)
        box.append(fields)
        reference_views.menu(self, dialog, header, [
            ("Value", "P", lambda text: reference_views.insert_text(value, text)),
        ])
        def submit(*_):
            params = (entry, key.get_text(), value.get_text(), protected.get_active())
            self.run_job(lambda: self.vault.set_attribute(*params, original_name=name or "", revision=info.get("revision")),
                         lambda snapshot: (dialog.close(), self.window.show_vault(snapshot)))
        save.connect("clicked", submit)
        if name is not None:
            remove = Gtk.Button(label="Delete Attribute…", css_classes=["destructive-action"])
            remove.connect("clicked", lambda *_: (dialog.close(), self.confirm_change(
                "Delete Custom Attribute?", name, "Delete", lambda: self.vault.remove_attribute(entry, name, revision=info.get("revision")))))
            box.append(remove)
        toolbar.set_content(box)
        dialog.set_child(toolbar)
        dialog.connect("closed", lambda *_: value.set_text(""))
        self.present_dialog(dialog)

    def setup_totp(self, entry, settings=None):
        self.totp.setup(entry, settings)

    def show_history(self, entry, history=None):
        history_views.show(self, entry, history)

    def import_attachment(self, entry, source):
        if not self.vault.unlocked or self.busy:
            return
        if Path(source).name in entry.attachments:
            self.confirm_change("Replace Existing Attachment?", Path(source).name, "Replace",
                lambda: self.vault.import_attachment(entry, source, replace=True))
        else:
            self.run_job(lambda: self.vault.import_attachment(entry, source), self.window.show_vault)

    def generator(self, on_apply=None):
        return generator_views.show(self, on_apply)

    def shortcuts(self):
        dialog = Adw.ShortcutsDialog()
        section = Adw.ShortcutsSection(title="Database")
        for title, accelerator in [("Open Database", "<Control>o"), ("New Database", "<Control><Shift>n"),
                                   ("New Entry", "<Control>n"), ("Search", "<Control>f"), ("Open Entry URL", "<Control>u"),
                                   ("Lock Database", "<Control>l"), ("Lock All Databases", "<Control><Shift>l"),
                                   ("Password Generator", "<Control>g"), ("Refresh", "<Control>r"),
                                   ("Save Database Copy", "<Control><Shift>s"), ("Preferences", "<Control>comma"),
                                   ("Select All Entries (Entry List)", "<Control>a"),
                                   ("Deselect All Entries (Entry List)", "<Control><Shift>a"),
                                   ("Leave Entry Selection", "Escape"),
                                   ("Close Window", "<Control>w")]:
            section.add(Adw.ShortcutsItem(title=title, accelerator=accelerator))
        dialog.add(section)
        self.present_dialog(dialog)

    def about(self):
        dialog = Adw.AboutDialog(application_name="Keyslot", application_icon=ICON_NAME,
            developer_name="Keyslot Contributors", version=VERSION,
            comments="A native GNOME client for KeePassXC databases.\nEarly development · feature parity is incomplete.",
            license_type=Gtk.License.GPL_3_0,
            developers=["Keyslot Contributors"], copyright="© 2026 Keyslot Contributors")
        self.present_dialog(dialog)


class DatabaseView(Gtk.Box):
    def __init__(self, app):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, vexpand=True, hexpand=True)
        self.app = app
        self.selected_group = None
        self.selected_entry = None
        self.snapshot = None
        self.search_matches = None
        self.search_generation = 0
        self.selection_mode = False
        self.rendering_entries = False
        self.refreshing_groups = False
        self.entry_count = 0
        self.selection_anchor = None
        self.set_size_request(360, 360)
        self.toasts = Adw.ToastOverlay()
        self.stack = Gtk.Stack()
        self.toasts.set_child(self.stack)
        self.breakpoints = Adw.BreakpointBin(vexpand=True, hexpand=True, child=self.toasts,
                                             width_request=360, height_request=360)
        self.append(self.breakpoints)
        self._build_locked()
        self._build_vault()
        self.stack.set_visible_child_name("locked")

    def _build_locked(self):
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.set_title_widget(Adw.WindowTitle(title="Keyslot"))
        header.pack_end(self.app.host_window.menu())
        toolbar.add_top_bar(header)
        self.welcome = Adw.StatusPage(icon_name=ICON_NAME, title="Your Passwords, Safely Kept",
                                     description="Open a KeePass database to get started.")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, halign=Gtk.Align.CENTER)
        open_button = Gtk.Button(label="Open Database…", css_classes=["suggested-action", "pill"], action_name="win.open")
        create_button = Gtk.Button(label="New Database…", css_classes=["pill"], action_name="win.new")
        self.unlock_button = Gtk.Button(label="Unlock Database", css_classes=["suggested-action", "pill"], visible=False)
        self.unlock_button.connect("clicked", lambda *_: self.app.unlock_dialog(str(self.app.path)))
        self.locked_spinner = Gtk.Spinner(visible=False, halign=Gtk.Align.CENTER)
        box.append(self.locked_spinner)
        box.append(self.unlock_button)
        box.append(open_button)
        box.append(create_button)
        self.welcome.set_child(box)
        toolbar.set_content(self.welcome)
        self.stack.add_named(toolbar, "locked")

    def _build_vault(self):
        self.outer = Adw.OverlaySplitView(min_sidebar_width=200, max_sidebar_width=240)
        sidebar = Adw.ToolbarView()
        head = Adw.HeaderBar(show_start_title_buttons=True, show_end_title_buttons=False)
        head.set_title_widget(Adw.WindowTitle(title="Groups"))
        sidebar.add_top_bar(head)
        side_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.groups = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE, css_classes=["navigation-sidebar"])
        self.groups.connect("row-selected", self._select_group)
        side_content.append(scroll(self.groups))
        new_group = Gtk.Button(label="New Group", margin_start=12,
                               margin_end=12, margin_bottom=12)
        new_group.connect("clicked", lambda *_: self.app.new_group())
        side_content.append(new_group)
        edit_group = Gtk.Button(label="Edit / Move Group…", margin_start=12, margin_end=12, margin_bottom=12)
        edit_group.connect("clicked", lambda *_: self.app.edit_group())
        side_content.append(edit_group)
        sidebar.set_content(side_content)
        self.outer.set_sidebar(sidebar)
        self.inner = Adw.NavigationSplitView(min_sidebar_width=280, max_sidebar_width=380, sidebar_width_fraction=0.42)
        list_toolbar = Adw.ToolbarView()
        list_header = Adw.HeaderBar(show_start_title_buttons=True, show_end_title_buttons=False)
        self.list_header = list_header
        self.list_title = Adw.WindowTitle(title="All Entries", subtitle="0 entries")
        list_header.set_title_widget(self.list_title)
        list_header.pack_start(button("sidebar-show-symbolic", "Show Groups", lambda: self.outer.set_show_sidebar(not self.outer.get_show_sidebar())))
        self.new_entry_button = button("list-add-symbolic", "New Entry (Ctrl+N)", self.app.edit_entry)
        list_header.pack_end(self.new_entry_button)
        self.selection_toggle = Gtk.ToggleButton(icon_name="selection-mode-symbolic", tooltip_text="Select Entries",
                                                 valign=Gtk.Align.CENTER)
        self.selection_toggle.connect("toggled", lambda toggle: self.set_selection_mode(toggle.get_active()))
        list_header.pack_end(self.selection_toggle)
        self.selection_cancel = Gtk.Button(label="Cancel", visible=False, valign=Gtk.Align.CENTER)
        self.selection_cancel.connect("clicked", lambda *_: self.set_selection_mode(False))
        list_header.pack_end(self.selection_cancel)
        list_menu = self.app.host_window.menu()
        list_menu.set_visible(False)
        list_header.pack_end(list_menu)
        list_toolbar.add_top_bar(list_header)
        entries_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.search = Gtk.SearchEntry(placeholder_text="Search passwords", margin_top=12,
                                     margin_start=12, margin_end=12, margin_bottom=12)
        self.search.connect("search-changed", self._search_changed)
        entries_box.append(self.search)
        self.entries = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE, css_classes=["boxed-list"], valign=Gtk.Align.START)
        self.entries.connect("row-selected", self._select_entry)
        self.entries.connect("selected-rows-changed", self._selection_changed)
        self.entries.connect("row-activated", lambda *_: self.inner.set_show_content(True) if not self.selection_mode else None)
        keys = Gtk.EventControllerKey()
        keys.connect("key-pressed", self._entry_keys)
        self.entries.add_controller(keys)
        clicks = Gtk.GestureClick(button=1, propagation_phase=Gtk.PropagationPhase.CAPTURE)
        clicks.connect("pressed", self._entry_clicked)
        self.entries.add_controller(clicks)
        secondary = Gtk.GestureClick(button=3, propagation_phase=Gtk.PropagationPhase.CAPTURE)
        secondary.connect("pressed", self._entry_secondary)
        self.entries.add_controller(secondary)
        long_press = Gtk.GestureLongPress(touch_only=True, propagation_phase=Gtk.PropagationPhase.CAPTURE)
        long_press.connect("pressed", lambda gesture, x, y: self._entry_secondary(gesture, 1, x, y))
        self.entries.add_controller(long_press)
        entries_box.append(scroll(margins(self.entries, 12)))
        self.empty_label = Gtk.Label(label="No entries found", visible=False, margin_bottom=24, css_classes=["dim-label"])
        entries_box.append(self.empty_label)
        list_toolbar.set_content(entries_box)
        self.selection_bar = Gtk.ActionBar(revealed=False)
        self.select_all = button("edit-select-all-symbolic", "Select All", self.toggle_all)
        self.selection_bar.pack_start(self.select_all)
        self.bulk_transfer = Gtk.Button(label="Copy or Move…", valign=Gtk.Align.CENTER)
        self.bulk_transfer.connect("clicked", lambda *_: self.app.move_entries(self.selected_entries()))
        self.selection_bar.set_center_widget(self.bulk_transfer)
        self.bulk_recycle = button("user-trash-symbolic", "Move Selected Entries to Recycle Bin",
                                   lambda: self.app.delete_entries(self.selected_entries()))
        self.selection_bar.pack_end(self.bulk_recycle)
        list_toolbar.add_bottom_bar(self.selection_bar)
        self.inner.set_sidebar(Adw.NavigationPage(title="Entries", child=list_toolbar))
        detail_toolbar = Adw.ToolbarView()
        detail_header = Adw.HeaderBar(show_start_title_buttons=False, show_end_title_buttons=True)
        self.database_title = Adw.WindowTitle(title="Keyslot")
        detail_header.set_title_widget(self.database_title)
        detail_header.pack_end(self.app.host_window.menu())
        self.spinner = Gtk.Spinner(visible=False)
        detail_header.pack_end(self.spinner)
        detail_header.pack_end(button("changes-prevent-symbolic", "Lock Database (Ctrl+L)", self.app.lock))
        detail_toolbar.add_top_bar(detail_header)
        self.detail = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        detail_toolbar.set_content(scroll(Adw.Clamp(child=margins(self.detail, 24), maximum_size=620)))
        self.inner.set_content(Adw.NavigationPage(title="Entry Details", child=detail_toolbar))
        self.outer.set_content(self.inner)
        self.stack.add_named(self.outer, "vault")
        for width, target in [(950, self.outer), (650, self.inner)]:
            breakpoint = Adw.Breakpoint.new(Adw.BreakpointCondition.parse(f"max-width: {width}sp"))
            breakpoint.add_setter(target, "collapsed", True)
            if width == 650:
                breakpoint.add_setter(self.outer, "collapsed", True)
                breakpoint.add_setter(list_header, "show-end-title-buttons", True)
                breakpoint.add_setter(list_menu, "visible", True)
            self.breakpoints.add_breakpoint(breakpoint)
        self._empty_detail()

    def set_busy(self, busy):
        self.spinner.set_visible(busy)
        self.spinner.set_spinning(busy)
        self.locked_spinner.set_visible(busy)
        self.locked_spinner.set_spinning(busy)
        for widget in (self.groups, self.entries, self.detail, self.selection_toggle, self.selection_cancel, self.selection_bar):
            widget.set_sensitive(not busy)

    def show_locked(self):
        self.snapshot = None
        self.set_selection_mode(False)
        self.selected_entry = None
        self.selected_group = None
        self.search_matches = None
        self.search_generation += 1
        self.search.set_text("")
        clear(self.entries)
        self.entry_count = 0
        clear(self.groups)
        self._empty_detail()
        self.database_title.set_title("Keyslot")
        has_path = self.app.path is not None
        self.welcome.set_title("Database Locked" if has_path else "Your Passwords, Safely Kept")
        self.welcome.set_description("Unlock your database to access your passwords." if has_path else "Open a KeePass database to get started.")
        self.unlock_button.set_visible(has_path)
        self.stack.set_visible_child_name("locked")
        self.app.emit_state()

    def show_vault(self, snapshot):
        previous = self.selected_entry.uuid if self.selected_entry else None
        selection = {entry.uuid for entry in self.selected_entries()}
        self.snapshot = snapshot
        self.database_title.set_title(snapshot.name or self.app.vault.path.stem)
        self.stack.set_visible_child_name("vault")
        old_group = self.selected_group
        self.refreshing_groups = True
        clear(self.groups)
        all_row = Adw.ActionRow(title="All Entries")
        all_row.group_path = None
        all_row.add_prefix(Gtk.Image(icon_name="view-list-symbolic"))
        self.groups.append(all_row)
        selected = all_row
        for group in snapshot.groups:
            row = Adw.ActionRow(title=GLib.markup_escape_text(group.name or "Database"))
            row.add_prefix(self.app.icons.image(group, 24))
            row.set_margin_start(min(group.depth, 6) * 10)
            row.group_path = group.identity
            row.group_name = group.name
            self.groups.append(row)
            if old_group == group.identity:
                selected = row
        self.groups.select_row(selected)
        self.refreshing_groups = False
        self.render_entries(previous, selection)
        if self.search.get_text().strip():
            self._search_changed()
        self.app.emit_state()

    def _select_group(self, _list, row):
        if not row:
            return
        self.selected_group = row.group_path
        self.list_title.set_title("All Entries" if row.group_path is None else row.group_name)
        if self.refreshing_groups:
            return
        self.render_entries()
        if self.outer.get_collapsed():
            self.outer.set_show_sidebar(False)

    def render_entries(self, previous=None, selection=None):
        if not self.snapshot:
            return
        previous = previous or (self.selected_entry.uuid if self.selected_entry else None)
        if selection is None:
            selection = {entry.uuid for entry in self.selected_entries()}
        self.rendering_entries = True
        clear(self.entries)
        self.selected_entry = None
        query = self.search.get_text().casefold().strip()
        rows = []
        for entry in sorted(self.snapshot.entries, key=lambda e: e.title.casefold()):
            if self.selected_group is None and entry.recycled:
                continue
            if self.selected_group is not None and entry.group != self.selected_group:
                continue
            if query and self.search_matches is not None and entry.uuid not in self.search_matches:
                continue
            row = Adw.ActionRow(title=GLib.markup_escape_text(entry.title or "Untitled Entry"),
                subtitle=GLib.markup_escape_text(entry.username or entry.url or entry.group_path or entry.group))
            row.entry = entry
            check = Gtk.CheckButton(valign=Gtk.Align.CENTER)
            check.update_property([Gtk.AccessibleProperty.LABEL], ["Select " + (entry.title or "Untitled Entry")])
            check.connect("toggled", self._toggle_entry, row)
            row.selection_check = check
            avatar = self.app.icons.image(entry, 32)
            prefix = Gtk.Stack(valign=Gtk.Align.CENTER, width_request=32)
            prefix.add_named(avatar, "icon")
            prefix.add_named(check, "check")
            prefix.set_visible_child_name("check" if self.selection_mode else "icon")
            row.add_prefix(prefix)
            hover = Gtk.EventControllerMotion()
            hover.connect("enter", lambda *_args, prefix=prefix: prefix.set_visible_child_name("check"))
            hover.connect("leave", lambda *_args, prefix=prefix: prefix.set_visible_child_name("check" if self.selection_mode else "icon"))
            row.add_controller(hover)
            appearance.style_row(row, entry)
            if entry.totp:
                row.add_suffix(Gtk.Image(icon_name="alarm-symbolic", tooltip_text="One-Time Password Available"))
            row.set_activatable(True)
            self.entries.append(row)
            rows.append(row)
        self.list_title.set_subtitle(f"{len(rows)} entries")
        self.entry_count = len(rows)
        self.empty_label.set_visible(not rows)
        if self.selection_mode:
            for row in rows:
                if row.entry.uuid in selection:
                    self.entries.select_row(row)
        elif rows:
            selected = next((r for r in rows if r.entry.uuid == previous), rows[0])
            self.entries.select_row(selected)
        self.rendering_entries = False
        if self.selection_mode:
            self._selection_changed()
        elif rows:
            self._select_entry(self.entries, self.entries.get_selected_row())
        else:
            self._empty_detail()

    def selected_entries(self):
        return [row.entry for row in self.entries.get_selected_rows()]

    def set_selection_mode(self, enabled):
        if enabled and (not self.snapshot or self.app.busy):
            self.selection_toggle.set_active(False)
            return
        if self.selection_mode == enabled:
            return
        selection = {entry.uuid for entry in self.selected_entries()}
        previous = next(iter(selection), None)
        self.selection_mode = enabled
        self.selection_toggle.set_active(enabled)
        self.selection_toggle.set_visible(not enabled)
        self.selection_cancel.set_visible(enabled)
        self.new_entry_button.set_visible(not enabled)
        (self.list_header.add_css_class if enabled else self.list_header.remove_css_class)("selection-mode")
        if not enabled:
            self.selection_anchor = None
        self.selection_toggle.set_tooltip_text("Finish Selecting Entries" if enabled else "Select Entries")
        self.selection_bar.set_revealed(enabled)
        self.entries.set_selection_mode(Gtk.SelectionMode.MULTIPLE if enabled else Gtk.SelectionMode.SINGLE)
        if self.snapshot:
            self.list_title.set_title("All Entries" if self.selected_group is None else next(
                (item.name for item in self.snapshot.groups if item.identity == self.selected_group), "Entries"))
        self.render_entries(previous, selection)

    def _toggle_entry(self, check, row):
        if self.rendering_entries:
            return
        if not self.selection_mode:
            if check.get_active():
                self.begin_selection(row.entry.uuid)
            return
        if check.get_active() == row.is_selected():
            return
        (self.entries.select_row if check.get_active() else self.entries.unselect_row)(row)

    def begin_selection(self, identifier, gesture=None):
        if self.app.busy:
            return
        if gesture:
            gesture.set_state(Gtk.EventSequenceState.CLAIMED)
        if not self.selection_mode:
            self.set_selection_mode(True)
            self.entries.unselect_all()
        row = self.entries.get_first_child()
        while row:
            if row.entry.uuid == identifier:
                self.entries.select_row(row)
                self.selection_anchor = identifier
                break
            row = row.get_next_sibling()

    def _entry_clicked(self, gesture, _presses, _x, y):
        if not self.selection_mode or self.app.busy:
            return
        row = self.entries.get_row_at_y(int(y))
        if not row:
            return
        gesture.set_state(Gtk.EventSequenceState.CLAIMED)
        state = gesture.get_current_event_state()
        if state & Gdk.ModifierType.SHIFT_MASK and self.selection_anchor:
            rows = []
            child = self.entries.get_first_child()
            while child:
                rows.append(child)
                child = child.get_next_sibling()
            anchor = next((item for item in rows if item.entry.uuid == self.selection_anchor), row)
            first, last = sorted((anchor.get_index(), row.get_index()))
            self.rendering_entries = True
            if not state & Gdk.ModifierType.CONTROL_MASK:
                self.entries.unselect_all()
            for item in rows[first:last + 1]:
                self.entries.select_row(item)
            self.rendering_entries = False
            self._selection_changed()
        else:
            self.selection_anchor = row.entry.uuid
            (self.entries.unselect_row if row.is_selected() else self.entries.select_row)(row)

    def _entry_secondary(self, gesture, _presses, _x, y):
        row = self.entries.get_row_at_y(int(y))
        if row:
            self.begin_selection(row.entry.uuid, gesture)

    def toggle_all(self):
        if not self.selection_mode:
            return
        count = len(self.selected_entries())
        total = self.entry_count
        (self.entries.unselect_all if count == total else self.entries.select_all)()

    def _selection_changed(self, *_):
        if not self.selection_mode or self.rendering_entries:
            return
        entries = self.selected_entries()
        count = len(entries)
        self.selected_entry = None
        self.list_title.set_title(f"{count} Selected")
        self.select_all.set_tooltip_text("Deselect All" if count == self.entry_count else "Select All")
        self.select_all.set_sensitive(self.entry_count > 0)
        eligible = bool(entries) and all(not entry.recycled for entry in entries)
        self.bulk_transfer.set_sensitive(eligible)
        self.bulk_recycle.set_sensitive(eligible and bool(self.snapshot and self.snapshot.recycle_bin_enabled))
        row = self.entries.get_first_child()
        while row:
            if check := getattr(row, "selection_check", None):
                check.set_active(row.is_selected())
            row = row.get_next_sibling()
        clear(self.detail)
        noun = "Entry" if count == 1 else "Entries"
        self.detail.append(Adw.StatusPage(title=f"{count} {noun} Selected" if count else "Select Entries",
            icon_name="edit-select-all-symbolic", description="Use the actions below the entry list to copy, move or recycle your selection."))

    def _entry_keys(self, _keys, keyval, _code, state):
        if keyval == Gdk.KEY_Escape and self.selection_mode:
            self.set_selection_mode(False)
            return True
        if keyval in (Gdk.KEY_Menu, Gdk.KEY_F10) and (keyval == Gdk.KEY_Menu or state & Gdk.ModifierType.SHIFT_MASK):
            selected = self.selected_entries()
            if selected:
                self.begin_selection(selected[0].uuid)
                return True
        if keyval in (Gdk.KEY_a, Gdk.KEY_A) and state & Gdk.ModifierType.CONTROL_MASK:
            self.set_selection_mode(True)
            if state & Gdk.ModifierType.SHIFT_MASK:
                self.entries.unselect_all()
            else:
                self.entries.select_all()
            return True
        return False

    def _search_changed(self, *_):
        self.search_generation += 1
        generation = self.search_generation
        query = self.search.get_text()
        self.search_matches = None
        if not self.snapshot or not query.strip():
            self.render_entries()
            return
        def start():
            if generation != self.search_generation or not self.snapshot:
                return GLib.SOURCE_REMOVE
            if self.app.busy:
                GLib.timeout_add(100, start)
                return GLib.SOURCE_REMOVE
            def received(matches):
                if generation == self.search_generation and self.snapshot:
                    self.search_matches = set(matches)
                    self.render_entries()
            self.app.run_job(lambda: self.app.vault.search(query), received)
            return GLib.SOURCE_REMOVE
        start()

    def _select_entry(self, _list, row):
        if row and not self.selection_mode and not self.rendering_entries:
            self.selected_entry = row.entry
            self.render_detail(row.entry)

    def _empty_detail(self):
        self.app.totp.clear()
        clear(self.detail)
        self.detail.append(Adw.StatusPage(title="Select an Entry", icon_name="dialog-password-symbolic",
                                         description="Your login details will appear here."))

    def render_detail(self, entry):
        self.app.totp.clear()
        clear(self.detail)
        hero = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, halign=Gtk.Align.CENTER)
        hero.append(self.app.icons.image(entry, 72))
        hero.append(Gtk.Label(label=entry.title, wrap=True, css_classes=["title-1"]))
        hero.append(Gtk.Label(label=entry.group_path or entry.group, wrap=True, css_classes=["dim-label"]))
        self.detail.append(hero)
        fields = Adw.PreferencesGroup()
        username = Adw.ActionRow(title="Username", subtitle=GLib.markup_escape_text(entry.username or "—"))
        username.add_suffix(button("edit-copy-symbolic", "Copy Username", lambda: self.app.run_job(
            lambda: self.app.vault.attribute(entry, "UserName"), self.app.copy)))
        fields.add(username)
        password = Adw.ActionRow(title="Password", subtitle="••••••••••••")
        password.add_suffix(button("edit-copy-symbolic", "Copy Password", lambda: self.app.run_job(
            lambda: self.app.vault.attribute(entry), self.app.copy)))
        fields.add(password)
        if entry.url:
            website = Adw.ActionRow(title="Website", subtitle=GLib.markup_escape_text(entry.url))
            website.add_suffix(button("adw-external-link-symbolic", "Open Entry URL", lambda: self.app.open_entry_url(entry)))
            fields.add(website)
        if entry.override_url:
            override = Adw.ActionRow(title="URL Override", subtitle=GLib.markup_escape_text(entry.override_url))
            override.add_suffix(button("adw-external-link-symbolic", "Open URL Override", lambda: self.app.open_entry_url(entry, True)))
            fields.add(override)
        if entry.command_approved:
            permission = Adw.ActionRow(title="Command Approval", subtitle="This entry can run a previously approved command")
            permission.add_suffix(button("edit-delete-symbolic", "Forget Command Approval", lambda: self.app.run_job(
                lambda: self.app.vault.url_forget(entry), self.show_vault)))
            fields.add(permission)
        if entry.totp:
            fields.add(self.app.totp.row(entry))
        self.detail.append(fields)
        passkeys = Adw.PreferencesGroup(title="Passkey")
        passkey = Adw.ActionRow(title="Passkey Details…" if entry.passkey else "Import Passkey…", activatable=True,
            subtitle="View, export or remove this passkey" if entry.passkey else "Attach a passkey to this entry")
        passkey.connect("activated", lambda *_: passkey_views.show_info(self.app, entry) if entry.passkey
                        else passkey_views.choose_import(self.app, entry))
        passkey.set_sensitive(entry.passkey or not entry.recycled)
        passkeys.add(passkey)
        self.detail.append(passkeys)
        ssh = Adw.PreferencesGroup(title="SSH Key")
        settings = Adw.ActionRow(title="SSH Key Settings…", activatable=True, subtitle="Configure an attached or external key")
        settings.set_sensitive(not entry.recycled)
        settings.connect("activated", lambda *_: ssh_views.entry_settings(self.app, entry))
        ssh.add(settings)
        self.detail.append(ssh)
        auto_type = Adw.PreferencesGroup(title="Auto-Type")
        settings = Adw.ActionRow(title="Auto-Type Settings…", subtitle="Sequences and window associations", activatable=True)
        settings.connect("activated", lambda *_: autotype_views.settings(self.app, entry=entry))
        auto_type.add(settings)
        type_entry = Adw.ActionRow(title="Type Entry…", activatable=True, sensitive=not entry.recycled)
        type_entry.connect("activated", lambda *_: autotype_views.choose(self.app, entry))
        auto_type.add(type_entry)
        self.detail.append(auto_type)
        if entry.notes:
            group = Adw.PreferencesGroup(title="Notes")
            group.add(margins(Gtk.Label(label=entry.notes, wrap=True, selectable=True, xalign=0), 12))
            self.detail.append(group)
        custom = Adw.PreferencesGroup(title="Custom Attributes")
        for name in entry.attributes:
            row = Adw.ActionRow(title=GLib.markup_escape_text(name), subtitle="Copy or edit this attribute")
            row.add_suffix(button("edit-copy-symbolic", "Copy " + name, lambda n=name: self.app.run_job(
                lambda: self.app.vault.attribute(entry, n), self.app.copy)))
            row.add_suffix(button("document-edit-symbolic", "Edit " + name, lambda n=name: self.app.edit_attribute(entry, n)))
            custom.add(row)
        custom_add = Adw.ActionRow(title="Add Custom Attribute…", activatable=True)
        custom_add.connect("activated", lambda *_: self.app.edit_attribute(entry))
        custom.add(custom_add)
        self.detail.append(custom)
        otp_settings = Gtk.Button(label="Configure One-Time Password…")
        otp_settings.connect("clicked", lambda *_: self.app.setup_totp(entry))
        otp_actions = Gtk.Box(spacing=12, homogeneous=True)
        otp_actions.append(otp_settings)
        if entry.totp:
            qr = Gtk.Button(label="Show Authenticator QR Code…")
            qr.connect("clicked", lambda *_: self.app.totp.show_qr(entry))
            otp_actions.append(qr)
        self.detail.append(otp_actions)
        attachments = Adw.PreferencesGroup(title="Attachments")
        for name in entry.attachments:
            row = Adw.ActionRow(title=GLib.markup_escape_text(name))
            row.add_suffix(button("document-save-symbolic", "Save Attachment", lambda n=name: self.app.choose_file(
                lambda dest: self.app.run_job(lambda: self.app.vault.export_attachment(entry, n, dest),
                                             lambda _: self.app.toast("Attachment saved")), save=True, name=Path(n).name)))
            row.add_suffix(button("user-trash-symbolic", "Remove Attachment", lambda n=name: self.app.confirm_change(
                "Remove Attachment?", n, "Remove", lambda: self.app.vault.remove_attachment(entry, n))))
            attachments.add(row)
        add = Adw.ActionRow(title="Add Attachment…", activatable=True)
        add.add_prefix(Gtk.Image(icon_name="list-add-symbolic"))
        add.connect("activated", lambda *_: self.app.choose_file(lambda source: self.app.import_attachment(entry, source)))
        attachments.add(add)
        self.detail.append(attachments)
        if entry.history_count:
            history = Gtk.Button(label=f"View History ({entry.history_count} Versions)")
            history.connect("clicked", lambda *_: self.app.show_history(entry))
            self.detail.append(history)
        actions = Gtk.Box(spacing=12, homogeneous=True)
        edit = Gtk.Button(label="Edit Entry", css_classes=["suggested-action"])
        edit.connect("clicked", lambda *_: self.app.edit_entry(entry))
        move = Gtk.Button(label="Restore…" if entry.recycled else "Copy or Move…")
        move.connect("clicked", lambda *_: self.app.move_entry(entry))
        delete = button("user-trash-symbolic", "Move to Recycle Bin", lambda: self.app.delete_entry(entry))
        delete.set_sensitive(self.snapshot.recycle_bin_enabled)
        for widget in (edit, move, delete):
            widget.set_sensitive(widget.get_sensitive() and entry.addressable and not entry.recycled)
            actions.append(widget)
        move.set_sensitive(entry.addressable)
        self.detail.append(actions)
        if not entry.addressable:
            self.detail.append(Gtk.Label(label="This entry has an ambiguous path. Rename it in KeePassXC to enable actions here.",
                                         wrap=True, css_classes=["warning"]))

def main():
    from .app import Keyslot
    Gtk.init_check()
    application = None
    try:
        application = Keyslot()
        return application.run(sys.argv)
    except KeyboardInterrupt:
        # PyGObject has already quit the application and run its lock/cleanup hooks.
        return 130
    except VaultError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        if application is not None:
            from .command_line import restore_echo
            restore_echo(application)
