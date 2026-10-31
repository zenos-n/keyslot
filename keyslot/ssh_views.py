"""KeeAgent entry settings and explicit SSH-agent actions."""
from .database_views import Adw, Gtk, GLib, _dialog, _save, _spin
from .passkey_views import _lifetime
from .backend import VaultError
from gi.repository import Pango


def _entry(session, identifier):
    entry = next((entry for entry in session.vault.snapshot.entries if entry.uuid == identifier), None)
    if entry is None:
        raise VaultError("This entry no longer exists. Select it again before continuing.")
    return entry


def _configure(session):
    app = session.application
    if not app.startup.ssh or not app.ssh.ready:
        raise VaultError("Enable SSH Agent in Preferences and wait for it to start.")
    session.vault.ssh_configure(app.ssh.manager, app.startup.ssh_socket, app.startup.ssh_provider)


def entry_settings(session, entry, data=None):
    if not session.vault.unlocked or session.busy or entry.recycled:
        return
    if data is None:
        session.run_job(lambda: session.vault.ssh_settings(entry), lambda value: entry_settings(session, entry, value))
        return
    dialog, header, box = _dialog("SSH Key Settings", height=640)
    current = _lifetime(session, dialog)
    box.append(Gtk.Label(label=entry.title or "Untitled Entry", css_classes=["title-2"], wrap=True))
    source = Adw.PreferencesGroup(title="Private Key",
        description="The entry password unlocks an encrypted SSH key.")
    kind = Adw.ComboRow(title="Source", model=Gtk.StringList.new(["Attachment", "External File"]))
    kind.set_selected(1 if data["source_type"] == "file" else 0)
    attachments = data["attachments"]
    attachment = Adw.ComboRow(title="Attachment", model=Gtk.StringList.new(attachments or ["No Attachments"]))
    attachment.set_selected(attachments.index(data["attachment"]) if data["attachment"] in attachments else 0)
    path = Adw.EntryRow(title="Key File", text=data["file"])
    choose = Gtk.Button(icon_name="document-open-symbolic", tooltip_text="Choose SSH Key File", valign=Gtk.Align.CENTER)
    choose.connect("clicked", lambda *_: session.choose_file(lambda value: path.set_text(value) if current() else None) if current() else None)
    path.add_suffix(choose)
    def source_changed(*_):
        attachment.set_visible(kind.get_selected() == 0)
        attachment.set_sensitive(bool(attachments))
        path.set_visible(kind.get_selected() == 1)
    kind.connect("notify::selected", source_changed)
    for row in (kind, attachment, path):
        source.add(row)
    source_changed()
    box.append(source)
    options = Adw.PreferencesGroup(title="Agent Policy")
    auto = Adw.SwitchRow(title="Add When Vault Unlocks", active=data["auto_add"])
    remove = Adw.SwitchRow(title="Remove When Vault Locks", active=data["remove_on_lock"])
    confirm = Adw.SwitchRow(title="Confirm Every Use", active=data["confirm"],
        subtitle="Your SSH agent must provide its own confirmation prompt")
    lifetime = Adw.SwitchRow(title="Limit Key Lifetime", active=data["lifetime"])
    seconds = _spin("Lifetime (Seconds)", max(1, data["seconds"]), 1, 2147483647)
    seconds.set_sensitive(lifetime.get_active())
    lifetime.connect("notify::active", lambda *_: seconds.set_sensitive(lifetime.get_active()))
    for row in (auto, remove, confirm, lifetime, seconds):
        options.add(row)
    box.append(options)
    box.append(Gtk.Label(label="Preview, Add and Generate use the saved key settings. Save changes first. Automatic loading requires SSH Agent in Preferences.",
                         wrap=True, xalign=0, css_classes=["dim-label"]))
    actions = Gtk.Box(spacing=12, homogeneous=True)
    preview = Gtk.Button(label="Preview Saved Key", sensitive=data["configured"])
    preview.connect("clicked", lambda *_: preview_key(session, entry) if current() else None)
    add = Gtk.Button(label="Add Saved Key…", sensitive=data["configured"] and session.application.startup.ssh)
    add.connect("clicked", lambda *_: (dialog.close(), add_key(session, entry)) if current() else None)
    actions.append(preview)
    actions.append(add)
    box.append(actions)
    generate = Gtk.Button(label="Generate New SSH Key…")
    generate.connect("clicked", lambda *_: (dialog.close(), generate_key(session, entry)) if current() else None)
    box.append(generate)
    def save(*_):
        if not current() or session.busy:
            return
        values = dict(source_type="file" if kind.get_selected() else "attachment", file=path.get_text(),
                      attachment=attachments[attachment.get_selected()] if attachments else "", auto_add=auto.get_active(),
                      remove_on_lock=remove.get_active(), confirm=confirm.get_active(), lifetime=lifetime.get_active(),
                      seconds=int(seconds.get_value()))
        def saved(snapshot):
            if current():
                dialog.close()
                session.window.show_vault(snapshot)
                if session.vault.ssh_warning:
                    session.error(session.vault.ssh_warning)
                else:
                    session.toast("SSH key settings saved")
        session.run_job(lambda: session.vault.save_ssh_settings(_entry(session, entry.uuid), **values), saved)
    _save(header, save)
    session.present_dialog(dialog)


def _cancel_generation(session, token):
    if session.vault.unlocked and not session.jobs.closed:
        session.jobs.run(lambda: session.vault.cancel_generated_ssh_key(token), failed=lambda _message: None, interactive=False)


def generate_key(session, entry, info=None):
    if not session.vault.unlocked or session.busy or entry.recycled:
        return
    if info is None:
        session.run_job(lambda: session.vault.ssh_generation_info(_entry(session, entry.uuid)),
                        lambda value: generate_key(session, entry, value))
        return
    dialog, header, box = _dialog("Generate SSH Key", width=500, height=560)
    current = _lifetime(session, dialog)
    box.append(Gtk.Label(label=entry.title or "Untitled Entry", css_classes=["title-2"], wrap=True))
    options = Adw.PreferencesGroup(title="Key")
    algorithm = Adw.ComboRow(title="Type", model=Gtk.StringList.new(["Ed25519", "RSA", "ECDSA"]))
    bits = Adw.ComboRow(title="Key Size (Bits)")
    sizes = {0: [256], 1: [2048, 3072, 4096], 2: [256, 384, 521]}
    def changed_type(*_):
        index = algorithm.get_selected()
        bits.set_model(Gtk.StringList.new([str(value) for value in sizes[index]]))
        bits.set_selected(1 if index == 1 else 0)
        bits.set_visible(index != 0)
    algorithm.connect("notify::selected", changed_type)
    changed_type()
    comment = Adw.EntryRow(title="Comment", text=entry.username)
    name = Adw.EntryRow(title="Private Key Attachment Name", text=info["attachment"])
    for row in (algorithm, bits, comment, name):
        options.add(row)
    box.append(options)
    passphrase = Adw.PreferencesGroup(title="Passphrase", description="The entry password stays unchanged.")
    encrypt = Adw.SwitchRow(title="Protect With Entry Password", active=info["has_password"], sensitive=info["has_password"],
        subtitle="Use the entry's current password" if info["has_password"] else "Set an entry password first to protect the private key")
    passphrase.add(encrypt)
    box.append(passphrase)
    box.append(Gtk.Label(label="Review the public key before saving. A private key and a .pub attachment will be added to this entry. Existing attachments and external files are kept.", wrap=True, xalign=0))
    def submit(*_):
        if not current() or session.busy:
            return
        index = algorithm.get_selected()
        values = dict(algorithm=["ed25519", "rsa", "ecdsa"][index], bits=sizes[index][bits.get_selected()],
                      comment=comment.get_text(), attachment=name.get_text(), encrypt=encrypt.get_active())
        def prepared(value):
            if not current():
                _cancel_generation(session, value["token"])
                return
            dialog.close()
            _review_generation(session, entry, value)
        session.run_job(lambda: session.vault.generate_ssh_key(_entry(session, entry.uuid), **values), prepared)
    _save(header, submit, "Generate…")
    session.present_dialog(dialog)


def _review_generation(session, entry, data):
    dialog, header, box = _dialog("Save Generated SSH Key", width=560, height=580)
    current = _lifetime(session, dialog)
    token, epoch, identity = data["token"], session.epoch, session.vault.identity
    phase = ["review"]
    def release():
        if phase[0] == "review":
            phase[0] = "released"
            if session.epoch == epoch and session.vault.identity is identity:
                _cancel_generation(session, token)
        return False
    dialog.connect("closed", lambda *_: GLib.idle_add(release))
    summary = "This becomes the entry's selected SSH key. Existing attachments and external files are kept. Loaded agent keys are unchanged."
    if data["configured"]:
        summary += " It replaces the currently selected key source."
    box.append(Gtk.Label(label=summary, wrap=True, xalign=0))
    group = Adw.PreferencesGroup(title="Public Key")
    for title, value in (("Type", data["type"]), ("SHA256 Fingerprint", data["fingerprint"]),
                         ("Comment", data["comment"] or "—"), ("Private Attachment", data["attachment"]),
                         ("Public Attachment", data["attachment"] + ".pub"),
                         ("Passphrase", "Current entry password" if data["encrypted"] else "None — protected by the encrypted vault only")):
        group.add(Adw.ActionRow(title=title, subtitle=value, use_markup=False, subtitle_lines=2))
    box.append(group)
    public = Gtk.Label(label=data["public_key"], wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR,
                       max_width_chars=48, selectable=True, xalign=0, css_classes=["monospace"])
    box.append(public)
    copy = Gtk.Button(label="Copy Public Key")
    copy.connect("clicked", lambda *_: session.copy(data["public_key"]) if current() else None)
    box.append(copy)
    box.append(Gtk.Label(label="This review expires after two minutes or when the vault changes. Saving keeps the existing SSH-agent policy.",
                         wrap=True, xalign=0, css_classes=["dim-label"]))
    def submit(*_):
        if not current() or session.busy or phase[0] != "review":
            return
        phase[0] = "saving"
        def saved(snapshot):
            phase[0] = "saved"
            session.apply_refreshed(snapshot)
            session.toast("SSH key saved")
        def failed(message):
            phase[0] = "failed"
            _cancel_generation(session, token)
            dialog.close()
            session.error(message)
        if not session.run_job(lambda: session.vault.save_generated_ssh_key(_entry(session, entry.uuid), token), saved, failed):
            phase[0] = "review"
    _save(header, submit, "Save Key")
    if not session.present_dialog(dialog):
        release()


def preview_key(session, entry, data=None, decrypt=False):
    if not session.vault.unlocked or session.busy:
        return
    if data is None:
        session.run_job(lambda: session.vault.ssh_key_info(_entry(session, entry.uuid), decrypt),
                        lambda value: preview_key(session, entry, value))
        return
    dialog, header, box = _dialog("SSH Public Key", height=440)
    current = _lifetime(session, dialog)
    group = Adw.PreferencesGroup()
    for title, value in (("Type", data["type"]), ("SHA256 Fingerprint", data["fingerprint"]),
                         ("MD5 Fingerprint", data["md5"]), ("Comment", data["comment"])):
        row = Adw.ActionRow(title=title, subtitle=value or "—", use_markup=False, subtitle_lines=2)
        group.add(row)
    box.append(group)
    public = Gtk.Label(label=data["public_key"], wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR,
                       max_width_chars=48, selectable=True, xalign=0, css_classes=["monospace"])
    box.append(public)
    copy = Gtk.Button(label="Copy Public Key")
    copy.connect("clicked", lambda *_: session.copy(data["public_key"]) if current() else None)
    box.append(copy)
    if data["encrypted"]:
        decrypt_button = Gtk.Button(label="Verify Key Password")
        decrypt_button.connect("clicked", lambda *_: (dialog.close(), preview_key(session, entry, decrypt=True)) if current() else None)
        box.append(decrypt_button)
    session.present_dialog(dialog)


def add_key(session, entry, data=None):
    if not session.vault.unlocked or session.busy:
        return
    if data is None:
        def prepare():
            _configure(session)
            return session.vault.ssh_prepare(_entry(session, entry.uuid))
        session.run_job(prepare, lambda value: add_key(session, entry, value))
        return
    if data["other_vault"]:
        session.error("Another open vault manages this SSH key. Remove it from that vault first.")
        return
    if data["loaded"] and not data["owned"]:
        session.toast("This key is already loaded outside Keyslot; its settings and ownership were preserved")
        session.run_job(lambda: session.vault.ssh_add(data["token"], approved=False))
        return
    body = f'{data["title"]}\n{data["type"]}\n{data["fingerprint"]}\n\nAgent: {data["socket"]}\n'
    body += "Confirmation required for every use.\n" if data["confirm"] else "The agent can use this key without confirmation.\n"
    body += f'Lifetime: {data["seconds"]} seconds.\n' if data["lifetime"] else "No lifetime limit.\n"
    body += "Removed when this vault locks." if data["remove_on_lock"] else "Remains loaded after this vault locks."
    epoch = session.epoch
    dialog = Adw.AlertDialog(heading="Add SSH Key?", body=body, body_use_markup=False)
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("add", "Add Key")
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)
    def response(_dialog, choice):
        if session.epoch != epoch or not session.vault.unlocked or session.jobs.closed:
            return
        session.run_job(lambda: session.vault.ssh_add(data["token"], approved=choice == "add"),
                        lambda result: session.toast("SSH key added" if result.get("added") else "SSH key was not added"))
    dialog.connect("response", response)
    session.present_dialog(dialog)


def manage(session, data=None, query="", only_owned=False):
    if not session.vault.unlocked or session.busy:
        return
    if data is None:
        def load():
            _configure(session)
            return session.vault.ssh_agent_keys()
        session.run_job(load, lambda value: manage(session, value, query, only_owned))
        return
    keys = data["keys"]
    dialog, header, box = _dialog("SSH Agent Keys", width=600, height=min(640, 280 + len(keys) * 82))
    current = _lifetime(session, dialog)
    box.append(Gtk.Label(label="Agent: " + data["socket"], wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR, xalign=0))
    clear = Gtk.Button(label="Clear Agent…", valign=Gtk.Align.CENTER, sensitive=bool(keys))
    clear.connect("clicked", lambda *_: (dialog.close(), review_removal(session, clear=True)) if current() else None)
    header.pack_start(clear)
    refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Refresh Agent Keys", valign=Gtk.Align.CENTER)
    refresh.connect("clicked", lambda *_: (dialog.close(), manage(session, query=search.get_text(), only_owned=owned.get_active())) if current() else None)
    header.pack_start(refresh)
    selected = Gtk.Button(label="Remove Selected…", valign=Gtk.Align.CENTER, sensitive=False)
    header.pack_end(selected)
    search = Gtk.SearchEntry(placeholder_text="Search SSH keys", text=query)
    box.append(search)
    owned = Gtk.CheckButton(label="Only This Vault", active=only_owned)
    box.append(owned)
    rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"], valign=Gtk.Align.START)
    box.append(rows)
    checks = {}
    def update(*_):
        selected.set_sensitive(any(check.get_active() for check in checks.values()))
    if not keys:
        box.append(Adw.StatusPage(title="No SSH Keys", icon_name="dialog-password-symbolic"))
    for info in keys:
        who = "Cleanup Pending" if info["cleanup_pending"] else "This Vault" if info["owned"] else "Another Vault" if info["other_vault"] else "External Key"
        row = Adw.ActionRow(title=info["comment"] or info["type"], subtitle=who + " · " + info["fingerprint"],
                            title_lines=2, subtitle_lines=2, use_markup=False)
        row.info = info
        check = Gtk.CheckButton(valign=Gtk.Align.CENTER)
        check.update_property([Gtk.AccessibleProperty.LABEL], ["Select " + (info["comment"] or info["fingerprint"])])
        check.connect("toggled", update)
        checks[info["fingerprint"]] = check
        row.add_prefix(check)
        row.set_activatable_widget(check)
        remove = Gtk.Button(icon_name="list-remove-symbolic", tooltip_text="Remove SSH Key", valign=Gtk.Align.CENTER)
        def clicked(_button, info=info):
            if not current():
                return
            dialog.close()
            review_removal(session, [info["fingerprint"]])
        remove.connect("clicked", clicked)
        row.add_suffix(remove)
        copy = Gtk.Button(icon_name="edit-copy-symbolic", tooltip_text="Copy Public Key", valign=Gtk.Align.CENTER)
        copy.connect("clicked", lambda _button, info=info: session.copy(info["public_key"]) if current() else None)
        row.add_suffix(copy)
        rows.append(row)
    def visible(info):
        return (not owned.get_active() or info["owned"]) and search.get_text().casefold() in " ".join(
            (info["comment"], info["type"], info["fingerprint"])).casefold()
    def filter_changed(*_):
        for info in keys:
            if not visible(info):
                checks[info["fingerprint"]].set_active(False)
        rows.invalidate_filter()
    rows.set_filter_func(lambda row: visible(row.info))
    search.connect("search-changed", filter_changed)
    owned.connect("toggled", filter_changed)
    selected.connect("clicked", lambda *_: (dialog.close(), review_removal(session,
        [fingerprint for fingerprint, check in checks.items() if check.get_active()])) if current() else None)
    session.present_dialog(dialog)


def review_removal(session, fingerprints=(), clear=False, data=None):
    if not session.vault.unlocked or session.busy:
        return
    if data is None:
        def prepare():
            _configure(session)
            return session.vault.ssh_review_removal(fingerprints, clear)
        session.run_job(prepare, lambda value: review_removal(session, data=value))
        return
    dialog, header, box = _dialog("Clear SSH Agent" if data["clear"] else "Remove SSH Keys", width=600,
                                  height=min(640, 270 + len(data["keys"]) * 82))
    current = _lifetime(session, dialog)
    box.append(Gtk.Label(label=("Remove all the keys shown below from this agent?" if data["clear"] else "Remove the selected keys from this agent?")
        + " Other applications and vaults may lose access. Key files and vault entries are kept.", wrap=True, xalign=0))
    box.append(Gtk.Label(label="Agent: " + data["socket"], wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR, xalign=0, css_classes=["dim-label"]))
    count = len(data["keys"])
    group = Adw.PreferencesGroup(title=f'{count} Key' + ("" if count == 1 else "s"))
    for info in data["keys"]:
        who = "This Vault" if info["owned"] else "Another Vault" if info["other_vault"] else "External Key"
        group.add(Adw.ActionRow(title=info["comment"] or info["type"], subtitle=who + " · " + info["fingerprint"],
                               use_markup=False, title_lines=2, subtitle_lines=2))
    box.append(group)
    decision = [None]
    cancel = Gtk.Button(label="Cancel", valign=Gtk.Align.CENTER)
    def cancelled(*_):
        if decision[0] is None:
            decision[0] = False
            dialog.close()
    cancel.connect("clicked", cancelled)
    header.pack_start(cancel)
    def closed(*_):
        if decision[0] is not True and session.vault.unlocked and not session.jobs.closed:
            decision[0] = False
            session.jobs.run(lambda: session.vault.ssh_finish_removal(data["token"], approved=False),
                             failed=lambda _message: None, interactive=False)
    dialog.connect("closed", closed)
    def finish(result):
        if not result["confirmed"]:
            session.error("SSH key removal could not be confirmed. Review the agent before trying again.")
        elif not result["complete"]:
            session.error(f'Removed {result["removed"]} of {result["total"]} reviewed keys. '
                f'The agent now contains {result["agent_remaining"]} keys. Open Agent Keys again to review the remaining keys.')
        else:
            session.toast(f'Removed {result["removed"]} SSH keys')
            manage(session)
    def remove(*_):
        if decision[0] is not None or not current() or session.busy:
            return
        decision[0] = True
        dialog.close()
        session.run_job(lambda: session.vault.ssh_finish_removal(data["token"], approved=True), finish)
    apply = Gtk.Button(label="Clear Agent" if data["clear"] else "Remove Key" if len(data["keys"]) == 1 else "Remove Keys",
                       css_classes=["destructive-action"], valign=Gtk.Align.CENTER, sensitive=bool(data["keys"]))
    apply.connect("clicked", remove)
    header.pack_end(apply)
    session.present_dialog(dialog)
    cancel.grab_focus()


def add_preferences(session, page, dialog):
    app, settings = session.application, session.application.startup
    group = Adw.PreferencesGroup(title="SSH Agent",
        description="Use your session’s existing SSH agent. Saved entry policies control automatic loading and removal.")
    enabled = Adw.SwitchRow(title="Enable SSH Agent", active=settings.ssh)
    socket = Adw.EntryRow(title="Agent Socket (blank = SSH_AUTH_SOCK)", text=settings.ssh_socket, show_apply_button=True)
    provider = Adw.EntryRow(title="Security Key Provider (blank = default)", text=settings.ssh_provider, show_apply_button=True)
    status = Adw.ActionRow(title="Status", use_markup=False, subtitle_lines=3)
    updating = [False]
    def apply(*_, fields=False):
        if updating[0] or closed[0]:
            return
        try:
            app.set_ssh(enabled.get_active(), socket.get_text() if fields else None, provider.get_text() if fields else None)
        except (OSError, ValueError, VaultError) as exc:
            session.error(str(exc))
            updating[0] = True
            enabled.set_active(settings.ssh)
            updating[0] = False
    enabled.connect("notify::active", apply)
    socket.connect("apply", lambda *_: apply(fields=True))
    provider.connect("apply", lambda *_: apply(fields=True))
    retry = Gtk.Button(label="Retry", valign=Gtk.Align.CENTER)
    retry.connect("clicked", lambda *_: app.ssh.restart() if settings.ssh else None)
    cleanup = Gtk.Button(label="Retry Cleanup", valign=Gtk.Align.CENTER)
    cleanup.connect("clicked", lambda *_: app.ssh.check(retry=True))
    status.add_suffix(retry)
    status.add_suffix(cleanup)
    keys = Adw.ActionRow(title="Agent Keys…", activatable=True,
                        subtitle="View keys, remove selected keys or clear the agent")
    keys.connect("activated", lambda *_: (dialog.close(), manage(session)))
    closed = [False]
    dialog.connect("closed", lambda *_: closed.__setitem__(0, True))
    def update():
        if closed[0] or session.jobs.closed:
            return False
        status.set_subtitle(app.ssh.error or ("Starting…" if app.ssh.starting else "Running" if app.ssh.ready else "Disabled" if not settings.ssh else "Stopped"))
        socket.set_sensitive(settings.ssh)
        provider.set_sensitive(settings.ssh)
        retry.set_sensitive(settings.ssh and not app.ssh.starting)
        cleanup.set_sensitive(app.ssh.ready)
        keys.set_sensitive(session.vault.unlocked and app.ssh.ready)
        return True
    for row in (enabled, socket, provider, status, keys):
        group.add(row)
    page.add(group)
    update()
    GLib.timeout_add(500, update)
