"""Reviewed remote commands; native KeePassXC retains all vault keys and merges."""
from pathlib import Path
from gi.repository import Adw, GLib, Gtk
from .database_views import _dialog, _save, _spin
from .passkey_views import _lifetime, _confirm


def _cancel(session, token, epoch):
    def submit():
        if session.epoch != epoch or session.jobs.closed or not session.vault.unlocked:
            return False
        return not session.jobs.run(lambda: session.vault.remote_step("cancel", token), failed=lambda _message: None,
                                    interactive=False)
    if submit():
        GLib.timeout_add(100, submit)


def show(session, data=None):
    if not session.vault.unlocked or session.busy:
        return
    if data is None:
        session.run_job(session.vault.remote_locations, lambda value: show(session, value))
        return
    dialog, header, box = _dialog("Remote Synchronization", width=560, height=500)
    current = _lifetime(session, dialog)
    box.append(Gtk.Label(label="Synchronize this vault using your transfer tools, such as curl, scp, or rclone. "
                         "Locations and credentials are saved inside the encrypted vault.", wrap=True, xalign=0))
    rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"], valign=Gtk.Align.START)
    box.append(rows)
    def add(*_):
        if current() and not session.busy:
            dialog.close()
            edit(session, {"profile": {}, "revision": data["revision"]})
    add_row = Gtk.Button(label="Add Remote Location…", valign=Gtk.Align.CENTER)
    add_row.connect("clicked", add)
    box.append(add_row)
    def edit_location(name):
        if not current() or session.busy:
            return
        def loaded(value):
            if current():
                dialog.close(); edit(session, value)
        session.run_job(lambda: session.vault.remote_locations(name), loaded)
    def remove(name):
        if not current():
            return
        dialog.close()
        _confirm(session, "Remove Remote Location?", f'Remove “{name}” from this vault? The remote file will remain.',
                 "Remove", lambda: session.run_job(lambda: session.vault.remote_edit(name, data["revision"]),
                     lambda snapshot: (session.window.show_vault(snapshot), show(session))))
    def synchronize(name):
        if not current() or session.busy:
            return
        def prepared(plan):
            if current():
                dialog.close(); review(session, plan)
            else:
                _cancel(session, plan["token"], session.epoch)
        session.run_job(lambda: session.vault.remote_prepare(name, data["revision"]), prepared)
    for item in data["locations"]:
        name = item["name"]
        direction = "Download, merge, and upload" if item["download"] and item["upload"] else "Download and merge" if item["download"] else "Upload local vault"
        row = Adw.ActionRow(title=name, subtitle=direction, use_markup=False, title_lines=2)
        for icon, label, callback in (("media-playback-start-symbolic", "Synchronize", synchronize),
                                      ("document-edit-symbolic", "Edit Location", edit_location),
                                      ("user-trash-symbolic", "Remove Location", remove)):
            button = Gtk.Button(icon_name=icon, tooltip_text=label, valign=Gtk.Align.CENTER)
            button.connect("clicked", lambda _button, callback=callback, name=name: callback(name))
            row.add_suffix(button)
        rows.append(row)
    if not data["locations"]:
        box.append(Gtk.Label(label="No remote locations configured.", css_classes=["dim-label"]))
    session.present_dialog(dialog)


def edit(session, data):
    profile = data["profile"]
    original = profile.get("name", "")
    dialog, header, box = _dialog("Remote Location", width=580, height=700)
    current = _lifetime(session, dialog)
    group = Adw.PreferencesGroup()
    name = Adw.EntryRow(title="Name", text=original)
    group.add(name); box.append(group)
    box.append(Gtk.Label(label="Commands run directly, without a shell. Use double quotes for arguments containing spaces. "
                         "Include {TEMP_DATABASE} where the encrypted transfer file belongs. Installed transfer tools use your normal environment.",
                         wrap=True, xalign=0))
    fields = {}
    for prefix, title in (("download", "Download"), ("upload", "Upload")):
        group = Adw.PreferencesGroup(title=title, description="Leave the command empty to skip this direction.")
        command = Adw.PasswordEntryRow(title="Command", text=profile.get(prefix + "Command", ""))
        duration = _spin("Timeout (Seconds)", profile.get(prefix + "TimeoutMsec", 10000) / 1000, 0.1, 3600, 0.1, 1)
        group.add(command); group.add(duration)
        expander = Adw.ExpanderRow(title="Standard Input (Sensitive)", subtitle="Optional; sent with a final newline, then closed")
        text = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD_CHAR, left_margin=12, right_margin=12,
                            top_margin=12, bottom_margin=12, monospace=True)
        buffer = text.get_buffer(); buffer.set_enable_undo(False)
        buffer.set_text(profile.get(prefix + "CommandInput", ""))
        scrolled = Gtk.ScrolledWindow(child=text, hscrollbar_policy=Gtk.PolicyType.NEVER,
                                      min_content_height=110, max_content_height=180, propagate_natural_height=True,
                                      margin_start=12, margin_end=12, margin_top=8, margin_bottom=12,
                                      css_classes=["card"], overflow=Gtk.Overflow.HIDDEN)
        expander.add_row(scrolled)
        group.add(expander); box.append(group)
        fields[prefix] = command, duration, buffer
    def submit(*_):
        if not current() or session.busy:
            return
        values = {"name": name.get_text()}
        for prefix, (command, duration, buffer) in fields.items():
            values[prefix + "Command"] = command.get_text()
            values[prefix + "TimeoutMsec"] = round(duration.get_value() * 1000)
            values[prefix + "CommandInput"] = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True)
        def saved(snapshot):
            if current():
                dialog.close(); session.window.show_vault(snapshot); show(session)
        session.run_job(lambda: session.vault.remote_edit(original, data["revision"], values), saved)
    def clear(*_):
        profile.clear()
        name.set_text("")
        for command, _duration, buffer in fields.values():
            command.set_text(""); buffer.set_text("")
    dialog._clear_sensitive_fields = clear
    dialog.connect("closed", clear)
    _save(header, submit)
    session.present_dialog(dialog)


def review(session, plan):
    token, epoch = plan["token"], session.epoch
    profile = plan.pop("profile")
    dialog, header, box = _dialog("Review Synchronization", width=580, height=600)
    current = _lifetime(session, dialog)
    started = [False]
    box.append(Gtk.Label(label=profile["name"], css_classes=["title-2"], wrap=True))
    box.append(Gtk.Label(label="These commands have your user account's access. Only approve commands you trust, "
                         "including those configured by another vault client. Reveal and inspect each command before continuing.", wrap=True, xalign=0))
    commands = []
    download, upload = bool(profile.get("downloadCommand", "").strip()), bool(profile.get("uploadCommand", "").strip())
    for prefix, title in (("download", "Download"), ("upload", "Upload")):
        if not profile.get(prefix + "Command", "").strip():
            continue
        group = Adw.PreferencesGroup(title=title)
        command = Adw.PasswordEntryRow(title="Command", text=profile[prefix + "Command"], editable=False)
        commands.append(command); group.add(command)
        group.add(Adw.ActionRow(title="Timeout", subtitle=f'{profile.get(prefix + "TimeoutMsec", 10000) / 1000:g} seconds'))
        group.add(Adw.ActionRow(title="Standard Input", subtitle="Configured (hidden; inspect in Edit Location)" if profile.get(prefix + "CommandInput") else "Empty; input is closed immediately"))
        box.append(group)
    message = "Synchronization saves the local vault, including any unsaved edits. "
    if download and upload:
        message += "The download command runs twice: first for the merge, then to check for a remote change before upload. "
    if upload:
        message += "Transfer commands control remote write atomicity. A concurrent change after the final check can still race an upload; a failed or cancelled upload may have changed the remote file."
    box.append(Gtk.Label(label=message, wrap=True, xalign=0))
    approved = Gtk.CheckButton(label="I have reviewed and trust these commands")
    box.append(approved)
    def proceed(*_):
        if not current() or session.busy or not approved.get_active():
            return
        started[0] = True
        dialog.close()
        synchronize(session, token)
    button = _save(header, proceed, "Synchronize")
    button.set_sensitive(False)
    approved.connect("toggled", lambda *_: button.set_sensitive(approved.get_active()))
    def closed(*_):
        profile.clear()
        for command in commands:
            command.set_text("")
        if not started[0]:
            _cancel(session, token, epoch)
    dialog._clear_sensitive_fields = lambda: closed()
    dialog.connect("closed", closed)
    session.present_dialog(dialog)


def synchronize(session, token):
    epoch = session.epoch
    dialog, header, box = _dialog("Synchronizing Vault", width=460, height=520)
    alive = _lifetime(session, dialog)
    stopping = [False]
    current = lambda: alive() and not stopping[0]
    dialog.set_can_close(False)
    status = Gtk.Label(label="Starting…", wrap=True, xalign=0)
    box.append(status)
    spinner = Gtk.Spinner(spinning=True, halign=Gtk.Align.CENTER)
    box.append(spinner)
    credentials = Adw.PreferencesGroup(title="Remote Vault Unlock", visible=False,
        description="The downloaded vault needs a different unlock key. Its encryption settings will be preserved.")
    password = Adw.PasswordEntryRow(title="Remote Master Password")
    key_only = Adw.SwitchRow(title="Key File / Hardware Key Only")
    slot = Adw.EntryRow(title="Hardware Slot (1 or 2, optional :serial)")
    key = Adw.ActionRow(title="Remote Key File", subtitle="None selected")
    selected = [""]
    def choose(path):
        if current():
            selected[0] = path; key.set_subtitle(Path(path).name if path else "None selected")
    for icon, label, callback in (("document-open-symbolic", "Choose Remote Key File", lambda *_: session.choose_file(choose)),
                                  ("edit-clear-symbolic", "Clear Remote Key File", lambda *_: choose(""))):
        button = Gtk.Button(icon_name=icon, tooltip_text=label, valign=Gtk.Align.CENTER)
        button.connect("clicked", callback); key.add_suffix(button)
    for row in (password, key_only, key, slot):
        credentials.add(row)
    box.append(credentials)
    unlock = Gtk.Button(label="Unlock and Merge", valign=Gtk.Align.CENTER, visible=False, css_classes=["suggested-action"])
    box.append(unlock)
    finished = [False]
    last_phase = ["review"]
    def execute(operation, **options):
        if not current():
            return
        unlock.set_sensitive(False)
        def start():
            if not current():
                return False
            return not session.jobs.run(lambda: session.vault.remote_step(operation, token, **options), received, failed)
        if start():
            GLib.timeout_add(100, start)
    def failed(message):
        if not current():
            return
        if last_phase[0] == "uploading" and "unknown" not in message.lower():
            message += "\n\nUpload had begun, so the remote file may have changed. Inspect it before retrying."
        status.set_label(message)
        spinner.set_spinning(False)
        credentials.set_visible(False); unlock.set_visible(False)
        _cancel(session, token, epoch)
        finished[0] = True
        cancel.set_label("Close")
        if session.vault.snapshot:
            session.window.show_vault(session.vault.snapshot)
    def received(value):
        if not current():
            return
        phase = value["state"]
        last_phase[0] = phase
        if phase in {"downloading", "verifying", "uploading"}:
            status.set_label({"downloading": "Downloading the encrypted remote vault…", "verifying": "Local vault saved. Checking the remote file before upload…",
                              "uploading": "Local vault saved. Uploading the encrypted merged vault…"}[phase])
            GLib.timeout_add(150, lambda: execute("poll"))
        elif phase == "ready_merge":
            status.set_label("Unlocking and merging the remote vault…")
            execute("merge")
        elif phase == "credentials_required":
            status.set_label(value.get("message", "The remote vault could not be unlocked with that key. Enter its master credential."))
            spinner.set_spinning(False)
            credentials.set_visible(True); unlock.set_visible(True); unlock.set_sensitive(True)
            password.grab_focus()
        elif phase == "ready_upload":
            credentials.set_visible(False); unlock.set_visible(False)
            spinner.set_spinning(True)
            execute("upload")
        elif phase == "done":
            finished[0] = True
            _cancel(session, token, epoch)
            dialog.close()
            session.window.show_vault(session.vault.snapshot)
            session.toast("Vault synchronization completed")
    def merge(*_):
        values = {"credentials": True, "password": "" if key_only.get_active() else password.get_text(),
                  "no_password": key_only.get_active(), "keyfile": selected[0], "yubikey": slot.get_text()}
        password.set_text("")
        credentials.set_visible(False); unlock.set_visible(False); spinner.set_spinning(True)
        status.set_label("Unlocking and merging the remote vault…")
        execute("merge", **values)
    unlock.connect("clicked", merge)
    key_only.connect("notify::active", lambda *_: password.set_sensitive(not key_only.get_active()))
    def clear(*_):
        password.set_text(""); slot.set_text(""); selected[0] = ""
    def close(*_):
        clear()
        if not finished[0] and not stopping[0]:
            _cancel(session, token, epoch)
    def request_close(*_):
        if stopping[0]:
            return
        # Stop delivery immediately, before the closing animation can schedule another transfer phase.
        stopping[0] = True
        clear()
        if not finished[0]:
            _cancel(session, token, epoch)
            session.toast("Synchronization cancelled; a completed local merge stays saved. Check the remote file if upload had begun.")
        dialog.force_close()
    cancel = Gtk.Button(label="Cancel", valign=Gtk.Align.CENTER)
    cancel.connect("clicked", request_close); header.pack_start(cancel)
    dialog.connect("close-attempt", request_close)
    dialog._clear_sensitive_fields = request_close
    dialog.connect("closed", close)
    session.present_dialog(dialog)
    execute("start", approved=True)
