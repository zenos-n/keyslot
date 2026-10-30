from __future__ import annotations

from collections import Counter
from pathlib import Path
import sys
from urllib.parse import urlparse

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk

from . import APP_ID, ICON_NAME, VERSION
from .backend import VaultError
from .core_backend import Vault, EngineError
from .session import SessionJobs
from . import database_views, passkey_views, ssh_views

INTERFACE = "com.neg_zero.keyslot.Vault1"
OBJECT_PATH = "/com/neg_zero/keyslot/Vault1"
DBUS_XML = f'''<node><interface name="{INTERFACE}">
  <method name="Show"/><method name="Lock"/><method name="Quit"/>
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
        self.jobs = SessionJobs(self.vault, GLib.idle_add, self._changed, self._clear, self.error)
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
        if not settings.remember:
            return
        path = self.vault.path
        def remember(request):
            if settings.login:
                self.application.login_keyring().store(path, credentials, request)
            request.set_error_if_cancelled()
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
        self.quick_blob = None
        self.jobs.close()

    def deactivate(self):
        self.view_epoch += 1
        self.cancel_file_requests()
        self.clear_clipboard()
        self.close_dialogs()

    def activate(self):
        if not self.active or self.jobs.closed:
            return
        self.needs_attention = False
        if self.pending_unlock:
            path, create, options = self.pending_unlock
            self.pending_unlock = None
            self._unlock_dialog(path, create, options)
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
        self.clear_clipboard()
        clipboard = self.window.get_clipboard()
        self.clipboard_provider = Gdk.ContentProvider.new_for_value(value)
        clipboard.set_content(self.clipboard_provider)
        self.clipboard_timer = GLib.timeout_add_seconds(20, self.clear_clipboard)
        self.toast("Copied · clipboard clears in 20 seconds")

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

    def _unlock_dialog(self, path, create=False, import_options=None, use_quick=True):
        if use_quick and not create and not import_options and self.quick_blob and Path(path).resolve() == self.quick_path:
            return self._quick_unlock_dialog(path)
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
        advanced = Adw.ExpanderRow(title="Additional Unlock Options")
        keyfile = Adw.ActionRow(title="Key File", subtitle="None selected")
        selected_key = [""]
        def set_key(p):
            selected_key[0] = p
            keyfile.set_subtitle(Path(p).name)
        keyfile.add_suffix(button("document-open-symbolic", "Choose Key File", lambda: self.choose_file(set_key)))
        if create:
            def generate_keyfile():
                self.choose_file(lambda target: self.run_job(lambda: self.vault.generate_keyfile(target),
                                                            lambda _: set_key(target)), save=True, name="Passwords.keyx")
            keyfile.add_suffix(button("list-add-symbolic", "Generate Key File", generate_keyfile))
        keyfile.add_suffix(button("edit-clear-symbolic", "Clear Key File", lambda: set_key("")))
        advanced.add_row(keyfile)
        slot = Adw.EntryRow(title="Hardware Key Slot (1 or 2, optional :serial)")
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
        minutes = self.application.startup.lock_minutes
        lock_notice = f"Locks after {minutes} minutes of inactivity." if minutes else "Inactivity locking is disabled."
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
        for row in (tags, expires, expiry):
            advanced.add(row)
        box.append(advanced)

        def submit(*_):
            if self.busy:
                return
            buf = notes.get_buffer()
            fields = (groups[group.get_selected()].identity, title.get_text(), username.get_text(),
                      url.get_text(), buf.get_text(buf.get_start_iter(), buf.get_end_iter(), True),
                      secret.get_text() if not entry or dirty_password[0] else None, entry)
            options = {"tags": tags.get_text(), "expires": expires.get_active()}
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

    def move_entry(self, entry):
        groups = [g for g in self.vault.snapshot.groups if g.addressable and not g.recycled and g.identity != entry.group]
        if not groups:
            self.toast("Create another group first")
            return
        dialog = Adw.AlertDialog(heading="Move Entry", body="Choose a destination group.")
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
        box.append(fields)
        notes = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD_CHAR, height_request=120,
                             left_margin=12, right_margin=12, top_margin=12, bottom_margin=12)
        notes.get_buffer().set_text(current.notes)
        notes_group = Adw.PreferencesGroup(title="Notes")
        notes_group.add(Gtk.ScrolledWindow(child=notes, css_classes=["card"], overflow=Gtk.Overflow.HIDDEN,
                                            hscrollbar_policy=Gtk.PolicyType.NEVER, min_content_height=120))
        box.append(notes_group)
        def submit(*_):
            buf = notes.get_buffer()
            values = (current.identity, name.get_text(), buf.get_text(buf.get_start_iter(), buf.get_end_iter(), True),
                      groups[parent.get_selected()].identity if current.parent else None)
            self.run_job(lambda: self.vault.save_group(*values),
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
            self.run_job(lambda: self.vault.attribute_info(entry, name),
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
        key = Adw.EntryRow(title="Name", text=name or "", editable=name is None)
        value = Adw.PasswordEntryRow(title="Value", text=info.get("value", ""))
        protected = Adw.SwitchRow(title="Protect Value", active=info.get("protected", True))
        for row in (key, value, protected):
            fields.add(row)
        box.append(fields)
        def submit(*_):
            params = (entry, key.get_text(), value.get_text(), protected.get_active())
            self.run_job(lambda: self.vault.set_attribute(*params),
                         lambda snapshot: (dialog.close(), self.window.show_vault(snapshot)))
        save.connect("clicked", submit)
        if name is not None:
            remove = Gtk.Button(label="Delete Attribute…", css_classes=["destructive-action"])
            remove.connect("clicked", lambda *_: (dialog.close(), self.confirm_change(
                "Delete Custom Attribute?", name, "Delete", lambda: self.vault.remove_attribute(entry, name))))
            box.append(remove)
        toolbar.set_content(box)
        dialog.set_child(toolbar)
        dialog.connect("closed", lambda *_: value.set_text(""))
        self.present_dialog(dialog)

    def setup_totp(self, entry, settings=None):
        if self.busy:
            return
        if settings is None:
            self.run_job(lambda: self.vault.totp_settings(entry), lambda value: self.setup_totp(entry, value))
            return
        dialog = Adw.Dialog(title="Set Up One-Time Password", content_width=480)
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        save = Gtk.Button(label="Save", css_classes=["suggested-action"])
        header.pack_end(save)
        toolbar.add_top_bar(header)
        fields = Adw.PreferencesGroup(description="Paste an otpauth:// TOTP URI. Clear it to remove TOTP from this entry.")
        value = Adw.PasswordEntryRow(title="TOTP URI", text=settings)
        fields.add(value)
        def submit(*_):
            secret = value.get_text()
            self.run_job(lambda: self.vault.set_totp(entry, secret),
                         lambda snapshot: (dialog.close(), self.window.show_vault(snapshot)))
        save.connect("clicked", submit)
        toolbar.set_content(margins(fields, 24))
        dialog.set_child(toolbar)
        dialog.connect("closed", lambda *_: value.set_text(""))
        self.present_dialog(dialog)

    def show_history(self, entry, history=None):
        if self.busy:
            return
        if history is None:
            self.run_job(lambda: self.vault.history(entry), lambda items: self.show_history(entry, items))
            return
        dialog = Adw.Dialog(title="Entry History", content_width=520, content_height=440)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"], valign=Gtk.Align.START)
        for item in reversed(history):
            row = Adw.ActionRow(title=GLib.markup_escape_text(item["title"]), subtitle=item["modified"])
            def restore(index=item["index"]):
                self.run_job(lambda: self.vault.restore_history(entry, index),
                             lambda snapshot: (dialog.close(), self.window.show_vault(snapshot)))
            row.add_suffix(button("edit-undo-symbolic", "Restore This Version", restore))
            def remove(index=item["index"]):
                dialog.close()
                self.confirm_change("Delete History Version?", "This saved version will be removed from the database.",
                                    "Delete", lambda: self.vault.remove_history(entry, index))
            row.add_suffix(button("user-trash-symbolic", "Delete This Version", remove))
            rows.append(row)
        toolbar.set_content(scroll(margins(rows, 18)))
        dialog.set_child(toolbar)
        self.present_dialog(dialog)

    def import_attachment(self, entry, source):
        if not self.vault.unlocked or self.busy:
            return
        if Path(source).name in entry.attachments:
            self.confirm_change("Replace Existing Attachment?", Path(source).name, "Replace",
                lambda: self.vault.import_attachment(entry, source, replace=True))
        else:
            self.run_job(lambda: self.vault.import_attachment(entry, source), self.window.show_vault)

    def generator(self, on_apply=None):
        if self.busy:
            return
        dialog = Adw.Dialog(title="Password Generator", content_width=440)
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        toolbar.add_top_bar(header)
        box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24), 24)
        output = Adw.PasswordEntryRow(title="Generated Password")
        result_group = Adw.PreferencesGroup()
        result_group.add(output)
        box.append(result_group)
        options = Adw.PreferencesGroup()
        words = Adw.SwitchRow(title="Use a Passphrase")
        length = Adw.SpinRow.new_with_range(1, 128, 1)
        length.set_title("Length")
        length.set_value(24)
        options.add(words)
        options.add(length)
        box.append(options)
        characters = Adw.PreferencesGroup(title="Characters")
        rows = {}
        for key, title in [("lowercase", "Lowercase (a–z)"), ("uppercase", "Uppercase (A–Z)"),
                           ("numbers", "Numbers (0–9)"), ("symbols", "Symbols (!@#$…) ")]:
            row = Adw.SwitchRow(title=title.strip(), active=True)
            characters.add(row)
            rows[key] = row
        box.append(characters)
        advanced_group = Adw.PreferencesGroup()
        advanced = Adw.ExpanderRow(title="More Character Options")
        for key, title, active in [("exclude_lookalike", "Exclude Look-alike Characters", False),
                                   ("every_group", "Require Each Character Group", True),
                                   ("extended_ascii", "Extended ASCII Characters", False)]:
            row = Adw.SwitchRow(title=title, active=active)
            advanced.add_row(row)
            rows[key] = row
        symbol_rows = []
        for key, title in [("braces", "Brackets: ()[]{}"), ("punctuation", "Punctuation: .,:;"),
                           ("quotes", "Quotes"), ("dashes", "Dashes and Slashes"),
                           ("math", "Math Symbols"), ("logograms", "Other Symbols")]:
            row = Adw.SwitchRow(title=title, active=True)
            advanced.add_row(row)
            rows[key] = row
            symbol_rows.append(row)
        additional = Adw.EntryRow(title="Additional Characters")
        excluded = Adw.EntryRow(title="Excluded Characters")
        advanced.add_row(additional)
        advanced.add_row(excluded)
        advanced_group.add(advanced)
        box.append(advanced_group)
        actions = Gtk.Box(spacing=12, homogeneous=True)
        generate = Gtk.Button(label="Generate", css_classes=["suggested-action"])
        copy = Gtk.Button(label="Use Password" if on_apply else "Copy", sensitive=False)
        actions.append(generate)
        if on_apply:
            generate.remove_css_class("suggested-action")
            copy.add_css_class("suggested-action")
            copy.set_valign(Gtk.Align.CENTER)
            header.pack_end(copy)
        else:
            actions.append(copy)
        box.append(actions)
        state = {"revision": 0, "closed": False, "applied": False}
        def invalidate(*_):
            state["revision"] += 1
            output.set_text("")
            copy.set_sensitive(False)
        def mode_changed(*_):
            active = words.get_active()
            length.get_adjustment().set_lower(4 if active else 1)
            length.get_adjustment().set_upper(20 if active else 128)
            length.set_value(6 if active else 24)
            length.set_title("Words" if active else "Length")
            output.set_title("Generated Passphrase" if active else "Generated Password")
            characters.set_visible(not active)
            advanced_group.set_visible(not active)
            invalidate()
        words.connect("notify::active", mode_changed)
        length.connect("notify::value", invalidate)
        for row in rows.values():
            row.connect("notify::active", invalidate)
        additional.connect("changed", invalidate)
        excluded.connect("changed", invalidate)
        def symbols_changed(*_):
            for row in symbol_rows:
                row.set_sensitive(rows["symbols"].get_active())
        rows["symbols"].connect("notify::active", symbols_changed)
        def request(*_, initial=False):
            if self.busy:
                return
            invalidate()
            revision = state["revision"]
            params = {"length": int(length.get_value()), "passphrase": words.get_active()}
            if not words.get_active():
                params.update({key: row.get_active() for key, row in rows.items()})
                params.update(additional=additional.get_text(), excluded=excluded.get_text())
            def generated(value):
                if not state["closed"] and revision == state["revision"]:
                    output.set_text(value)
                    copy.set_sensitive(bool(value))
            if on_apply and initial:
                self.jobs.run(lambda: self.vault.generate(**params), generated, interactive=False)
            else:
                self.run_job(lambda: self.vault.generate(**params), generated)
        generate.connect("clicked", request)
        def use(*_):
            if state["closed"] or state["applied"] or not output.get_text():
                return
            if on_apply:
                state["applied"] = True
                on_apply(output.get_text())
            else:
                self.copy(output.get_text())
        copy.connect("clicked", use)
        toolbar.set_content(scroll(box, natural=True))
        dialog.set_child(toolbar)
        def closed(*_):
            state["closed"] = True
            invalidate()
            if on_apply and not state["applied"]:
                on_apply(None)
        dialog.connect("closed", closed)
        self.present_dialog(dialog)
        request(initial=True)
        return dialog

    def shortcuts(self):
        dialog = Adw.ShortcutsDialog()
        section = Adw.ShortcutsSection(title="Database")
        for title, accelerator in [("Open Database", "<Control>o"), ("New Database", "<Control><Shift>n"),
                                   ("New Entry", "<Control>n"), ("Search", "<Control>f"),
                                   ("Lock Database", "<Control>l"), ("Lock All Databases", "<Control><Shift>l"),
                                   ("Password Generator", "<Control>g"), ("Refresh", "<Control>r"),
                                   ("Save Database Copy", "<Control><Shift>s"), ("Preferences", "<Control>comma"),
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
        self.list_title = Adw.WindowTitle(title="All Entries", subtitle="0 entries")
        list_header.set_title_widget(self.list_title)
        list_header.pack_start(button("sidebar-show-symbolic", "Show Groups", lambda: self.outer.set_show_sidebar(not self.outer.get_show_sidebar())))
        list_header.pack_end(button("list-add-symbolic", "New Entry (Ctrl+N)", self.app.edit_entry))
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
        self.entries.connect("row-activated", lambda *_: self.inner.set_show_content(True))
        entries_box.append(scroll(margins(self.entries, 12)))
        self.empty_label = Gtk.Label(label="No entries found", visible=False, margin_bottom=24, css_classes=["dim-label"])
        entries_box.append(self.empty_label)
        list_toolbar.set_content(entries_box)
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
        for widget in (self.groups, self.entries, self.detail):
            widget.set_sensitive(not busy)

    def show_locked(self):
        self.snapshot = None
        self.selected_entry = None
        self.selected_group = None
        self.search_matches = None
        self.search_generation += 1
        self.search.set_text("")
        clear(self.entries)
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
        self.snapshot = snapshot
        self.database_title.set_title(snapshot.name or self.app.vault.path.stem)
        self.stack.set_visible_child_name("vault")
        old_group = self.selected_group
        clear(self.groups)
        all_row = Adw.ActionRow(title="All Entries")
        all_row.group_path = None
        all_row.add_prefix(Gtk.Image(icon_name="view-list-symbolic"))
        self.groups.append(all_row)
        selected = all_row
        for group in snapshot.groups:
            row = Adw.ActionRow(title=GLib.markup_escape_text(group.name or "Database"))
            row.add_prefix(Gtk.Image(icon_name="user-trash-symbolic" if group.recycled else "folder-symbolic"))
            row.set_margin_start(min(group.depth, 6) * 10)
            row.group_path = group.identity
            row.group_name = group.name
            self.groups.append(row)
            if old_group == group.identity:
                selected = row
        self.groups.select_row(selected)
        self.render_entries(previous)
        if self.search.get_text().strip():
            self._search_changed()
        self.app.emit_state()

    def _select_group(self, _list, row):
        if not row:
            return
        self.selected_group = row.group_path
        self.list_title.set_title("All Entries" if row.group_path is None else row.group_name)
        self.render_entries()
        if self.outer.get_collapsed():
            self.outer.set_show_sidebar(False)

    def render_entries(self, previous=None):
        if not self.snapshot:
            return
        previous = previous or (self.selected_entry.uuid if self.selected_entry else None)
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
            row.add_prefix(Adw.Avatar(size=32, text=entry.title, show_initials=True))
            if entry.totp:
                row.add_suffix(Gtk.Image(icon_name="alarm-symbolic", tooltip_text="One-Time Password Available"))
            row.set_activatable(True)
            self.entries.append(row)
            rows.append(row)
        self.list_title.set_subtitle(f"{len(rows)} entries")
        self.empty_label.set_visible(not rows)
        if rows:
            selected = next((r for r in rows if r.entry.uuid == previous), rows[0])
            self.entries.select_row(selected)
        else:
            self._empty_detail()

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
        if row:
            self.selected_entry = row.entry
            self.render_detail(row.entry)

    def _empty_detail(self):
        clear(self.detail)
        self.detail.append(Adw.StatusPage(title="Select an Entry", icon_name="dialog-password-symbolic",
                                         description="Your login details will appear here."))

    def render_detail(self, entry):
        clear(self.detail)
        hero = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, halign=Gtk.Align.CENTER)
        hero.append(Adw.Avatar(size=72, text=entry.title, show_initials=True))
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
            website.add_suffix(button("adw-external-link-symbolic", "Open Website", lambda: self._open_url(entry.url)))
            fields.add(website)
        if entry.totp:
            otp = Adw.ActionRow(title="One-Time Password", subtitle="Copy the current verification code")
            otp.add_suffix(button("edit-copy-symbolic", "Copy One-Time Password", lambda: self.app.run_job(
                lambda: self.app.vault.attribute(entry, totp=True), self.app.copy)))
            fields.add(otp)
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
        self.detail.append(otp_settings)
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
        move = Gtk.Button(label="Restore…" if entry.recycled else "Move…")
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

    def _open_url(self, uri):
        if urlparse(uri).scheme not in ("https", "http"):
            self.app.error("Only HTTP and HTTPS website links can be opened here.")
            return
        Gtk.UriLauncher.new(uri).launch(self.app.host_window, None, None)


def main():
    from .app import Keyslot
    Gtk.init_check()
    if Gdk.Display.get_default() is None:
        print("Keyslot requires a graphical session with GTK4 display access.", file=sys.stderr)
        return 1
    try:
        Gio.bus_get_sync(Gio.BusType.SESSION, None)
    except GLib.Error:
        print("Keyslot requires access to the session D-Bus.", file=sys.stderr)
        return 1
    try:
        return Keyslot().run(sys.argv)
    except KeyboardInterrupt:
        # PyGObject has already quit the application and run its lock/cleanup hooks.
        return 130
    except VaultError as exc:
        print(str(exc), file=sys.stderr)
        return 1
