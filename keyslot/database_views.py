"""Native database workflows. Backend calls run through the application's worker."""
from pathlib import Path

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk


def _dialog(title, width=520, height=620):
    dialog = Adw.Dialog(title=title, content_width=width, content_height=height)
    toolbar = Adw.ToolbarView()
    header = Adw.HeaderBar()
    toolbar.add_top_bar(header)
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24,
                  margin_top=24, margin_bottom=24, margin_start=24, margin_end=24)
    toolbar.set_content(Gtk.ScrolledWindow(child=box, hscrollbar_policy=Gtk.PolicyType.NEVER))
    dialog.set_child(toolbar)
    return dialog, header, box


def _save(header, callback, label="Save"):
    button = Gtk.Button(valign=Gtk.Align.CENTER, label=label, css_classes=["suggested-action"])
    button.connect("clicked", callback)
    header.pack_end(button)
    return button


def _spin(title, value, minimum, maximum, step=1, digits=0):
    row = Adw.SpinRow.new_with_range(minimum, maximum, step)
    row.set_title(title)
    row.set_digits(digits)
    row.set_value(value)
    return row


def import_database(app):
    if app.busy:
        return
    formats = [("keepass1", "KeePass 1 (.kdb)"), ("xml", "KeePass XML"),
               ("bitwarden", "Bitwarden JSON"), ("1pux", "1Password (.1pux)"),
               ("opvault", "1Password OPVault Folder"), ("protonpass", "Proton Pass JSON"), ("csv", "CSV")]
    dialog, header, box = _dialog("Import Database", height=520)
    box.append(Gtk.Label(label="Import into a new encrypted database. Choose the source first, then a new database file and unlock key.", wrap=True))
    group = Adw.PreferencesGroup(title="Import Source")
    format_row = Adw.ComboRow(title="Format", model=Gtk.StringList.new([label for _, label in formats]))
    source_row = Adw.ActionRow(title="Source", subtitle="None selected")
    password = Adw.PasswordEntryRow(title="Source Password")
    key_row = Adw.ActionRow(title="Source Key File", subtitle="None selected")
    selected = {"source": "", "keyfile": ""}
    def source_selected(path, index):
        if index != format_row.get_selected():
            return
        selected["source"] = path
        source_row.set_subtitle(Path(path).name)
    choose = Gtk.Button(valign=Gtk.Align.CENTER, icon_name="document-open-symbolic", tooltip_text="Choose Import Source")
    def choose_source(*_):
        index = format_row.get_selected()
        app.choose_file(lambda path: source_selected(path, index), folder=formats[index][0] == "opvault")
    choose.connect("clicked", choose_source)
    source_row.add_suffix(choose)
    def key_selected(path):
        selected["keyfile"] = path
        key_row.set_subtitle(Path(path).name if path else "None selected")
    key_choose = Gtk.Button(valign=Gtk.Align.CENTER, icon_name="document-open-symbolic", tooltip_text="Choose Source Key File")
    key_choose.connect("clicked", lambda *_: app.choose_file(key_selected))
    key_clear = Gtk.Button(valign=Gtk.Align.CENTER, icon_name="edit-clear-symbolic", tooltip_text="Clear Source Key File")
    key_clear.connect("clicked", lambda *_: key_selected(""))
    key_row.add_suffix(key_choose)
    key_row.add_suffix(key_clear)
    def format_changed(*_):
        selected["source"] = ""
        source_row.set_subtitle("None selected")
        password.set_text("")
        format = formats[format_row.get_selected()][0]
        password.set_visible(format in {"keepass1", "bitwarden", "opvault"})
        key_row.set_visible(format == "keepass1")
        key_selected("")
    format_row.connect("notify::selected", format_changed)
    format_changed()
    for row in (format_row, source_row, password, key_row):
        group.add(row)
    box.append(group)
    def submit(*_):
        if not selected["source"]:
            app.error("Choose an import source first.")
            return
        options = {"source": selected["source"], "source_format": formats[format_row.get_selected()][0],
                   "source_password": password.get_text(), "source_keyfile": selected["keyfile"]}
        password.set_text("")
        dialog.close()
        if options["source_format"] == "csv":
            csv_import(app, options["source"])
        else:
            review_import(app, options)
    _save(header, submit, "Continue")
    dialog.connect("closed", lambda *_: password.set_text(""))
    app.present_dialog(dialog)


CSV_FIELDS = [("group", "Group"), ("title", "Title"), ("username", "Username"), ("password", "Password"),
              ("url", "URL"), ("tags", "Tags"), ("notes", "Notes"), ("totp", "TOTP"), ("icon", "Icon"),
              ("modified", "Last Modified"), ("created", "Created")]


def review_import(app, options, data=None):
    if app.busy:
        return
    if data is None:
        app.run_job(lambda: app.vault.inspect_import(**options), lambda value: review_import(app, options, value))
        return
    options = {**options, "source_fingerprint": data["source_fingerprint"]}
    dialog, header, box = _dialog("Review Import", height=640)
    box.append(Gtk.Label(label=f"{data['entries']} entries in {data['groups']} groups. Passwords are hidden.", wrap=True))
    entries = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
    box.append(entries)
    controls = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER)
    previous = Gtk.Button(valign=Gtk.Align.CENTER, icon_name="go-previous-symbolic", tooltip_text="Previous Entries")
    next_page = Gtk.Button(valign=Gtk.Align.CENTER, icon_name="go-next-symbolic", tooltip_text="Next Entries")
    position = Gtk.Label()
    for widget in (previous, position, next_page):
        controls.append(widget)
    box.append(controls)
    state = {"start": 0, "closed": False}
    def render(value):
        if state["closed"]:
            return
        while entries.get_first_child():
            entries.remove(entries.get_first_child())
        start = value["row_start"]
        state["start"] = start
        for item in value["preview"]:
            entries.append(Adw.ActionRow(title=item["title"] or "Untitled",
                subtitle=" · ".join(part for part in (item["group"], item["username"]) if part)))
        position.set_label(f"{start + 1 if value['entries'] else 0}–{start + len(value['preview'])} of {value['entries']}")
        previous.set_sensitive(start > 0)
        next_page.set_sensitive(start + len(value["preview"]) < value["entries"])
    def page(offset):
        if app.busy:
            return
        target = max(0, state["start"] + offset)
        app.run_job(lambda: app.vault.inspect_import(**options, row_start=target), render)
    previous.connect("clicked", lambda *_: page(-200))
    next_page.connect("clicked", lambda *_: page(200))
    render(data)
    def submit(*_):
        if app.busy:
            return
        dialog.close()
        app.choose_file(lambda path: app.unlock_dialog(path, create=True, import_options=options),
                        save=True, name="Imported Passwords.kdbx", kdbx=True)
    _save(header, submit, "Choose New Database…")
    dialog.connect("closed", lambda *_: state.update(closed=True))
    app.present_dialog(dialog)


def csv_import(app, source):
    if app.busy:
        return
    dialog, header, box = _dialog("Import CSV", height=700)
    box.append(Gtk.Label(label=Path(source).name, wrap=True, css_classes=["title-3"]))
    group = Adw.PreferencesGroup(title="File Format")
    codec = Adw.EntryRow(title="Text Encoding", text="UTF-8")
    separators = [(",", "Comma"), (";", "Semicolon"), ("\t", "Tab"), ("-", "Hyphen"), (":", "Colon"), (".", "Period")]
    quotes = [('"', 'Double Quote (\")'), ("'", "Single Quote (')"), (":", "Colon"), (".", "Period"), ("|", "Vertical Bar"), ("", "None")]
    comments = [("#", "#"), (";", ";"), (":", ":"), ("@", "@"), ("", "None")]
    separator = Adw.ComboRow(title="Field Separator", model=Gtk.StringList.new([label for _, label in separators]))
    quote = Adw.ComboRow(title="Text Quotes", model=Gtk.StringList.new([label for _, label in quotes]))
    comment = Adw.ComboRow(title="Comment Prefix", model=Gtk.StringList.new([label for _, label in comments]))
    backslash = Adw.SwitchRow(title="Backslash Escapes")
    has_header = Adw.SwitchRow(title="First Row Contains Column Names", active=True)
    skip = _spin("Skip First Rows", 1, 1, 2147483647)
    for row in (codec, separator, quote, comment, backslash, has_header, skip):
        group.add(row)
    box.append(group)
    load = Gtk.Button(valign=Gtk.Align.CENTER, label="Read Columns")
    raw = Gtk.Button(valign=Gtk.Align.CENTER, label="Preview Source Values…", sensitive=False)
    buttons = Gtk.Box(spacing=12)
    buttons.append(load)
    buttons.append(raw)
    box.append(buttons)
    status = Gtk.Label(label="Read the columns, then select the field for each column.", wrap=True)
    box.append(status)
    mappings = Adw.PreferencesGroup(title="Field Mapping", description="Not Present leaves the field empty.")
    box.append(mappings)
    allow_empty = Adw.SwitchRow(title="Allow Entries Without Titles",
        subtitle="Entries without titles can be difficult to tell apart")
    title_options = Adw.PreferencesGroup()
    title_options.add(allow_empty)
    box.append(title_options)
    state = {"data": None, "parsed": None, "closed": False}
    rows = {}
    def parameters():
        return {"codec": codec.get_text(), "separator": separators[separator.get_selected()][0],
                "qualifier": quotes[quote.get_selected()][0], "comment": comments[comment.get_selected()][0],
                "backslash": backslash.get_active(), "has_header": has_header.get_active(), "skip_rows": int(skip.get_value())}
    def collect():
        return {**parameters(), "mapping": {key: int(row.get_selected()) - 1 for key, row in rows.items()},
                "allow_empty_title": allow_empty.get_active()}
    def valid():
        return state["data"] is not None and state["parsed"] == parameters()
    def loaded(data, params):
        if state["closed"]:
            return
        if params != parameters():
            app.toast("CSV settings changed; read columns again")
            return
        previous_mapping = {key: int(row.get_selected()) - 1 for key, row in rows.items()}
        old = state["data"]
        same_columns = old and old["columns"] == data["columns"] and old["headers"] == data["headers"]
        for row in rows.values():
            mappings.remove(row)
        rows.clear()
        labels = ["Not Present"] + [f"{index + 1} · {data['headers'][index]}" if index < len(data["headers"]) else f"Column {index + 1}"
                                      for index in range(data["columns"])]
        for key, label in CSV_FIELDS:
            row = Adw.ComboRow(title=label, model=Gtk.StringList.new(labels))
            row.set_selected((previous_mapping if same_columns else data["mapping"]).get(key, -1) + 1)
            mappings.add(row)
            rows[key] = row
        state.update(data=data, parsed=params)
        status.set_label(f"{data['rows'] - data['skip_rows']} data rows · {data['columns']} columns")
        raw.set_sensitive(True)
        review.set_sensitive(True)
    def read(*_):
        if app.busy:
            return
        params = parameters()
        app.run_job(lambda: app.vault.inspect_csv(source, params), lambda data: loaded(data, params))
    def changed(*_):
        ready = valid()
        raw.set_sensitive(ready)
        review.set_sensitive(ready)
    for row, signal in [(codec, "changed"), (separator, "notify::selected"), (quote, "notify::selected"),
                        (comment, "notify::selected"), (backslash, "notify::active"), (skip, "notify::value")]:
        row.connect(signal, changed)
    def header_changed(*_):
        skip.get_adjustment().set_lower(1 if has_header.get_active() else 0)
        changed()
    has_header.connect("notify::active", header_changed)
    def preview(*_):
        if app.busy or not valid():
            return
        options = collect()
        fingerprint = state["data"]["source_fingerprint"]
        app.run_job(lambda: app.vault.inspect_csv(source, options, reveal=True, source_fingerprint=fingerprint),
                    lambda data: csv_preview(app, source, options, data) if not state["closed"] else None)
    def submit(*_):
        if app.busy or not valid():
            return
        options = {"source": source, "source_format": "csv", "csv_options": collect(),
                   "source_fingerprint": state["data"]["source_fingerprint"]}
        app.run_job(lambda: app.vault.inspect_import(**options),
                    lambda data: review_import(app, options, data) if not state["closed"] else None)
    review = _save(header, submit, "Review")
    review.set_sensitive(False)
    load.connect("clicked", read)
    raw.connect("clicked", preview)
    dialog.connect("closed", lambda *_: state.update(closed=True))
    app.present_dialog(dialog)


def csv_preview(app, source, options, data):
    dialog, _header, box = _dialog("CSV Source Values", width=760, height=620)
    box.append(Gtk.Label(label="Long values are shortened in this preview. Full values are imported.", wrap=True))
    row = _spin("First Row", data["row_start"] + 1, 1, data["rows"])
    column = _spin("First Column", data["column_start"] + 1, 1, data["columns"])
    controls = Adw.PreferencesGroup()
    controls.add(row)
    controls.add(column)
    box.append(controls)
    update = Gtk.Button(valign=Gtk.Align.CENTER, label="Update Preview")
    box.append(update)
    position = Gtk.Label(wrap=True)
    box.append(position)
    grid = Gtk.Grid(column_spacing=18, row_spacing=12, margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
    box.append(Gtk.ScrolledWindow(child=grid, hscrollbar_policy=Gtk.PolicyType.AUTOMATIC, min_content_height=240))
    state = {"closed": False}
    def wipe():
        while grid.get_first_child():
            child = grid.get_first_child()
            if isinstance(child, Gtk.Label):
                child.set_label("")
            grid.remove(child)
    def render(value):
        if state["closed"]:
            return
        wipe()
        for index, label in enumerate(value["preview_headers"]):
            grid.attach(Gtk.Label(label=f"{value['column_start'] + index + 1} · {label}", css_classes=["heading"]), index, 0, 1, 1)
        for y, values in enumerate(value["preview"], 1):
            for x, text in enumerate(values):
                grid.attach(Gtk.Label(label=text, selectable=True, xalign=0, yalign=0, wrap=True, max_width_chars=32), x, y, 1, 1)
        position.set_label(f"Rows {value['row_start'] + 1}–{value['row_start'] + len(value['preview'])} of {value['rows']} · "
                           f"Columns {value['column_start'] + 1}–{value['column_start'] + len(value['preview_headers'])} of {value['columns']}")
    def refresh(*_):
        if app.busy:
            return
        first_row, first_column = int(row.get_value()) - 1, int(column.get_value()) - 1
        app.run_job(lambda: app.vault.inspect_csv(source, options, first_row, first_column, True, data["source_fingerprint"]), render)
    update.connect("clicked", refresh)
    def closed(*_):
        state["closed"] = True
        wipe()
        data["preview"].clear()
    dialog._clear_sensitive_fields = closed
    dialog.connect("closed", closed)
    render(data)
    app.present_dialog(dialog)


def settings(app, data=None):
    if not app.vault.unlocked or app.busy:
        return
    if data is None:
        app.run_job(app.vault.settings, lambda value: settings(app, value))
        return
    dialog, header, box = _dialog("Database Settings")
    general = Adw.PreferencesGroup(title="General")
    name = Adw.EntryRow(title="Name", text=data["name"])
    username = Adw.EntryRow(title="Default Username", text=data["default_username"])
    recycle = Adw.SwitchRow(title="Use Recycle Bin", active=data["recycle_bin"])
    compression = Adw.SwitchRow(title="Compress Database", active=data["compression"])
    for row in (name, username, recycle, compression):
        general.add(row)
    box.append(general)
    browser = Adw.PreferencesGroup(title="Browser Integration")
    connections = Adw.ActionRow(title="Connected Browsers", subtitle="Review and revoke this database’s browser connections")
    manage = Gtk.Button(icon_name="go-next-symbolic", tooltip_text="Manage Browser Connections", valign=Gtk.Align.CENTER)
    manage.connect("clicked", lambda *_: (dialog.close(), browser_connections(app)))
    connections.add_suffix(manage)
    connections.set_activatable_widget(manage)
    browser.add(connections)
    box.append(browser)
    description = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD_CHAR, height_request=100,
        left_margin=12, right_margin=12, top_margin=12, bottom_margin=12)
    description.get_buffer().set_text(data["description"])
    details = Adw.PreferencesGroup(title="Description")
    details.add(Gtk.ScrolledWindow(child=description, css_classes=["card"], overflow=Gtk.Overflow.HIDDEN,
                                  min_content_height=100, hscrollbar_policy=Gtk.PolicyType.NEVER))
    box.append(details)
    history = Adw.PreferencesGroup(title="History", description="Reducing a limit removes older saved versions.")
    versions = _spin("Maximum Versions (−1 = Unlimited)", data["history_items"], -1, 2147483647)
    limited = Adw.SwitchRow(title="Limit History Size", active=data["history_size"] >= 0)
    size = _spin("Maximum History Size (MiB)", max(0, data["history_size"]) / 1048576,
                 0, 2047.99, step=1, digits=2)
    size.set_sensitive(limited.get_active())
    limited.connect("notify::active", lambda *_: size.set_sensitive(limited.get_active()))
    for row in (versions, limited, size):
        history.add(row)
    box.append(history)
    encryption = Adw.PreferencesGroup(title="Encryption",
        description="Key derivation settings control the cost of unlocking the database.")
    ciphers, kdfs = data["ciphers"], data["kdfs"]
    cipher = Adw.ComboRow(title="Cipher", model=Gtk.StringList.new([c["name"] for c in ciphers]))
    cipher.set_selected(next(i for i, c in enumerate(ciphers) if c["id"] == data["cipher"]))
    kdf = Adw.ComboRow(title="Key Derivation", model=Gtk.StringList.new([k["name"] for k in kdfs]))
    kdf.set_selected(next(i for i, k in enumerate(kdfs) if k["id"] == data["kdf"]))
    rounds = _spin("Iterations", data["rounds"], 1, 2147483647)
    memory = _spin("Memory (MiB)", data.get("memory_kib", 65536) / 1024, 1, 4194303)
    parallel = _spin("Parallelism", data.get("parallelism", 4), 1, 16777215)
    def algorithm_changed(*_, initial=False):
        selected = kdfs[kdf.get_selected()]
        memory.set_visible(selected["supports_memory"])
        parallel.set_visible(selected["supports_memory"])
        if not initial:
            defaults = selected["defaults"]
            rounds.set_value(defaults["rounds"])
            memory.set_value(defaults.get("memory_kib", 65536) / 1024)
            parallel.set_value(defaults.get("parallelism", 4))
    algorithm_changed(initial=True)
    kdf.connect("notify::selected", algorithm_changed)
    for row in (cipher, kdf, rounds, memory, parallel):
        encryption.add(row)
    target = _spin("Target Unlock Time (ms)", 1000, 100, 5000, step=100)
    calibrate = Gtk.Button(label="Calibrate", valign=Gtk.Align.CENTER)
    target.add_suffix(calibrate)
    encryption.add(target)
    def calibration_parameters():
        selected = kdfs[kdf.get_selected()]
        params = {"kdf": selected["id"], "milliseconds": int(target.get_value())}
        if selected["supports_memory"]:
            params.update(memory_kib=int(memory.get_value() * 1024), parallelism=int(parallel.get_value()))
        return params
    def benchmark(*_):
        params = calibration_parameters()
        previous_rounds = int(rounds.get_value())
        def calibrated(result):
            if params != calibration_parameters() or int(rounds.get_value()) != previous_rounds:
                app.toast("Encryption settings changed; calibrate again")
                return
            rounds.set_value(result["rounds"])
            app.toast("Iterations calibrated · save to apply")
        app.run_job(lambda: app.vault.benchmark_kdf(**params), calibrated)
    calibrate.connect("clicked", benchmark)
    box.append(encryption)
    version = data["format"]
    box.append(Gtk.Label(label=f"KDBX {version >> 16}.{version & 0xffff}", css_classes=["caption", "dim-label"]))
    def submit(*_):
        buf = description.get_buffer()
        selected_kdf = kdfs[kdf.get_selected()]
        values = {"name": name.get_text(), "description": buf.get_text(buf.get_start_iter(), buf.get_end_iter(), True),
                  "default_username": username.get_text(), "recycle_bin": recycle.get_active(),
                  "compression": compression.get_active(), "history_items": int(versions.get_value()),
                  "history_size": int(size.get_value() * 1048576) if limited.get_active() else -1,
                  "cipher": ciphers[cipher.get_selected()]["id"], "kdf": selected_kdf["id"],
                  "rounds": int(rounds.get_value())}
        if selected_kdf["supports_memory"]:
            values.update(memory_kib=int(memory.get_value() * 1024), parallelism=int(parallel.get_value()))
        changes = {key: value for key, value in values.items() if value != data.get(key)}
        app.run_job(lambda: app.vault.save_settings(**changes),
                    lambda snapshot: (dialog.close(), app.window.show_vault(snapshot), app.toast("Database settings saved")))
    _save(header, submit)
    dialog.connect("closed", lambda *_: (name.set_text(""), username.set_text(""), description.get_buffer().set_text("")))
    app.present_dialog(dialog)


def change_key(app, data=None):
    if not app.vault.unlocked or app.busy:
        return
    if data is None:
        app.run_job(app.vault.settings, lambda value: change_key(app, value))
        return
    dialog, header, box = _dialog("Change Unlock Key")
    password_group = Adw.PreferencesGroup(title="Password")
    replace = Adw.SwitchRow(title="Set a New Master Password")
    password = Adw.PasswordEntryRow(title="New Master Password", sensitive=False)
    repeat = Adw.PasswordEntryRow(title="Repeat Password", sensitive=False)
    remove_password = Adw.SwitchRow(title="Remove Current Password", sensitive=data["password_key"])
    def replacement_changed(*_):
        active = replace.get_active()
        password.set_sensitive(active)
        repeat.set_sensitive(active)
        if active:
            remove_password.set_active(False)
    replace.connect("notify::active", replacement_changed)
    remove_password.connect("notify::active", lambda *_: replace.set_active(False) if remove_password.get_active() else None)
    for row in (replace, password, repeat, remove_password):
        password_group.add(row)
    box.append(password_group)
    key_group = Adw.PreferencesGroup(title="Key File")
    selected_key = [""]
    file_row = Adw.ActionRow(title="New Key File", subtitle="Keep the current key file")
    remove_file = Adw.SwitchRow(title="Remove Current Key File", sensitive=data["file_key"])
    def selected(path):
        selected_key[0] = path
        file_row.set_subtitle(Path(path).name)
        remove_file.set_active(False)
    choose = Gtk.Button(valign=Gtk.Align.CENTER, icon_name="document-open-symbolic", tooltip_text="Choose Existing Key File")
    choose.connect("clicked", lambda *_: app.choose_file(selected))
    generate = Gtk.Button(valign=Gtk.Align.CENTER, icon_name="list-add-symbolic", tooltip_text="Generate New Key File")
    def generate_file():
        app.choose_file(lambda path: app.run_job(lambda: app.vault.generate_keyfile(path), lambda _: selected(path)),
                        save=True, name="Passwords.keyx")
    generate.connect("clicked", lambda *_: generate_file())
    file_row.add_suffix(choose)
    file_row.add_suffix(generate)
    key_group.add(file_row)
    key_group.add(remove_file)
    box.append(key_group)
    hardware = Adw.PreferencesGroup(title="Hardware Key")
    slot = Adw.EntryRow(title="New Slot (1 or 2, optional :serial)")
    remove_hardware = Adw.SwitchRow(title="Remove Current Hardware Key", sensitive=data["hardware_key"])
    hardware.add(slot)
    hardware.add(remove_hardware)
    box.append(hardware)
    box.append(Gtk.Label(label="The encrypted backup retains the previous unlock key.", wrap=True,
                         css_classes=["caption", "dim-label"]))
    def submit(*_):
        changes = {}
        if replace.get_active():
            value = password.get_text()
            if not value or value != repeat.get_text():
                app.error("Enter a nonempty new master password and repeat it exactly.")
                return
            changes["password"] = value
        if remove_password.get_active():
            changes["remove_password"] = True
        if selected_key[0] and remove_file.get_active():
            app.error("Choose either a replacement key file or removal of the current file key.")
            return
        if selected_key[0]:
            changes["keyfile"] = selected_key[0]
        if remove_file.get_active():
            changes["remove_keyfile"] = True
        if slot.get_text():
            changes["yubikey"] = slot.get_text()
        if remove_hardware.get_active():
            changes["remove_hardware"] = True
        if not changes:
            dialog.close()
            return
        def changed(snapshot):
            app.quick_blob = None
            dialog.close()
            app.window.show_vault(snapshot)
            app.toast("Database unlock key changed")
        app.run_job(lambda: app.vault.change_key(**changes), changed)
    _save(header, submit, "Change Key")
    dialog.connect("closed", lambda *_: (password.set_text(""), repeat.set_text("")))
    app.present_dialog(dialog)


def merge(app, source=None):
    if not app.vault.unlocked or app.busy:
        return
    if source is None:
        app.choose_file(lambda path: merge(app, path), kdbx=True)
        return
    dialog, header, box = _dialog("Merge Databases", width=460, height=500)
    box.append(Gtk.Label(label=f"Merge {Path(source).name} into {app.vault.snapshot.name or app.vault.path.stem}.", wrap=True))
    group = Adw.PreferencesGroup(title="Source Database Unlock")
    same = Adw.SwitchRow(title="Use Current Database's Unlock Key")
    password = Adw.PasswordEntryRow(title="Source Master Password")
    key_only = Adw.SwitchRow(title="Key File / Hardware Key Only")
    slot = Adw.EntryRow(title="Hardware Key Slot (1 or 2, optional :serial)")
    file_row = Adw.ActionRow(title="Key File", subtitle="None selected")
    selected_key = [""]
    def selected(path):
        selected_key[0] = path
        file_row.set_subtitle(Path(path).name)
    choose = Gtk.Button(valign=Gtk.Align.CENTER, icon_name="document-open-symbolic", tooltip_text="Choose Source Key File")
    choose.connect("clicked", lambda *_: app.choose_file(selected))
    file_row.add_suffix(choose)
    def sensitivity(*_):
        for row in (key_only, slot, file_row):
            row.set_sensitive(not same.get_active())
        password.set_sensitive(not same.get_active() and not key_only.get_active())
    same.connect("notify::active", sensitivity)
    key_only.connect("notify::active", sensitivity)
    for row in (same, password, key_only, file_row, slot):
        group.add(row)
    box.append(group)
    def submit(*_):
        values = {"password": password.get_text() if not same.get_active() and not key_only.get_active() else "",
                  "keyfile": selected_key[0], "yubikey": slot.get_text(), "no_password": key_only.get_active(),
                  "same_credentials": same.get_active()}
        app.run_job(lambda: app.vault.merge(source, **values),
                    lambda snapshot: (dialog.close(), app.window.show_vault(snapshot), app.toast("Databases merged")))
    _save(header, submit, "Merge")
    dialog.connect("closed", lambda *_: password.set_text(""))
    app.present_dialog(dialog)


def export(app):
    if not app.vault.unlocked or app.busy:
        return
    dialog = Adw.AlertDialog(heading="Export Unencrypted Data",
        body="The exported file will include passwords and other stored secrets. Choose the format to export.")
    formats = ["xml", "csv", "html"]
    choice = Gtk.DropDown.new_from_strings(["KeePass XML", "CSV", "HTML"])
    dialog.set_extra_child(choice)
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("choose", "Choose File…")
    def selected(_dialog, response):
        if response != "choose":
            return
        format = formats[choice.get_selected()]
        app.choose_file(lambda path: confirm_export(app, path, format), save=True, name="Passwords." + format)
    dialog.connect("response", selected)
    app.present_dialog(dialog)


def save_copy(app, destination=None):
    if not app.vault.unlocked or app.busy:
        return
    if destination is None:
        name = Path(app.vault.path).stem + " Copy.kdbx"
        app.choose_file(lambda path: save_copy(app, path), save=True, name=name, kdbx=True)
        return
    def save(overwrite=False):
        app.run_job(lambda: app.vault.save_copy(destination, overwrite),
                    lambda _: app.toast("Encrypted database copy saved"))
    if not Path(destination).exists():
        save()
        return
    dialog = Adw.AlertDialog(heading="Replace Existing File?",
        body=f"Save an encrypted copy to {destination}? The existing file will be replaced. The current database stays open.")
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("replace", "Replace")
    dialog.set_response_appearance("replace", Adw.ResponseAppearance.DESTRUCTIVE)
    dialog.connect("response", lambda _dialog, response: save(True) if response == "replace" else None)
    app.present_dialog(dialog)


def confirm_export(app, destination, format):
    if not app.vault.unlocked or app.busy:
        return
    overwrite = Path(destination).exists()
    dialog = Adw.AlertDialog(heading="Save Unencrypted Export?",
        body=f"Save passwords and other secrets to {destination}?" + (" The existing file will be replaced." if overwrite else ""))
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("export", "Export and Replace" if overwrite else "Export")
    dialog.set_response_appearance("export", Adw.ResponseAppearance.DESTRUCTIVE)
    dialog.connect("response", lambda _dialog, response: app.run_job(
        lambda: app.vault.export_database(destination, format, overwrite), lambda _: app.toast("Unencrypted export saved"))
        if response == "export" else None)
    app.present_dialog(dialog)


def browser_connections(app, data=None):
    if not app.vault.unlocked or app.busy:
        return
    if data is None:
        app.run_job(app.vault.browser_associations, lambda value: browser_connections(app, value))
        return
    dialog, _header, box = _dialog("Browser Connections", height=360)
    group = Adw.PreferencesGroup(title="Connected Browsers",
        description="Connections are saved inside this encrypted database. Revoking a connection requires that browser to pair again.")
    box.append(group)
    state = {"closed": False}
    dialog.connect("closed", lambda *_: state.update(closed=True))
    rows = []

    def render(connections):
        if state["closed"]:
            return
        for row in rows:
            group.remove(row)
        rows.clear()
        if not connections:
            row = Adw.ActionRow(title="No Connected Browsers", subtitle="No browser has been paired with this database")
            rows.append(row)
            group.add(row)
        for connection in connections:
            identifier = connection["id"]
            row = Adw.ActionRow(title=identifier, subtitle=connection.get("created", ""), use_markup=False)
            remove = Gtk.Button(icon_name="edit-delete-symbolic", tooltip_text="Revoke Browser Connection", valign=Gtk.Align.CENTER)
            remove.connect("clicked", lambda *_args, identifier=identifier: confirm(identifier))
            row.add_suffix(remove)
            rows.append(row)
            group.add(row)

    def confirm(identifier):
        alert = Adw.AlertDialog(heading="Revoke Browser Connection?",
            body=f'“{identifier}” will need to connect to this database again.')
        alert.add_response("cancel", "Cancel")
        alert.add_response("revoke", "Revoke Connection")
        alert.set_default_response("cancel")
        alert.set_close_response("cancel")
        alert.set_response_appearance("revoke", Adw.ResponseAppearance.DESTRUCTIVE)

        def response(_alert, choice):
            if choice != "revoke" or state["closed"]:
                return
            def revoke():
                app.vault.browser_revoke(identifier)
                return app.vault.browser_associations()
            app.run_job(revoke, render)
        alert.connect("response", response)
        app.present_dialog(alert)

    render(data)
    app.present_dialog(dialog)


def report(app, data=None):
    if not app.vault.unlocked or app.busy:
        return
    if data is None:
        app.run_job(app.vault.report, lambda value: report(app, value))
        return
    dialog, _header, box = _dialog("Database Reports", width=620)
    totals = Adw.PreferencesGroup(title="Statistics")
    for title, key in [("Groups", "groups"), ("Entries", "entries"), ("Expired Entries", "expired"),
                       ("Weak Passwords", "weak"), ("Reused Passwords", "reused"),
                       ("Unique Passwords", "unique"), ("Average Password Length", "average_length")]:
        row = Adw.ActionRow(title=title)
        row.add_suffix(Gtk.Label(label=str(data[key]), css_classes=["numeric"]))
        totals.add(row)
    box.append(totals)
    health = Adw.PreferencesGroup(title="Password Health")
    qualities = ["Bad", "Poor", "Weak", "Good", "Excellent"]
    def show_entry(uuid):
        app.window.search.set_text("")
        app.window.search_matches = None
        app.window.groups.select_row(app.window.groups.get_first_child())
        app.window.render_entries(uuid)
        app.window.inner.set_show_content(True)
        dialog.close()
    for item in sorted(data["health"], key=lambda item: item["score"]):
        label = qualities[item["quality"]] if 0 <= item["quality"] < len(qualities) else "Unknown"
        subtitle = f"{label} · {item['entropy']:.0f} bits · Score {item['score']}"
        if item["expired"]:
            subtitle += " · Expired"
        if item.get("reason"):
            subtitle += "\n" + item["reason"]
        row = Adw.ActionRow(title=GLib.markup_escape_text(item["title"] or "Untitled Entry"),
                            subtitle=GLib.markup_escape_text(subtitle), activatable=True)
        info = Gtk.Button(icon_name="dialog-information-symbolic", tooltip_text="Health Details", valign=Gtk.Align.CENTER)
        def details(_button, item=item):
            alert = Adw.AlertDialog(heading=item["title"] or "Untitled Entry",
                body="\n\n".join(value for value in [item.get("reason"), item.get("details")] if value) or "No problems detected.")
            alert.add_response("close", "Close")
            app.present_dialog(alert)
        info.connect("clicked", details)
        row.add_suffix(info)
        row.connect("activated", lambda _, uuid=item["uuid"]: show_entry(uuid))
        health.add(row)
    box.append(health)
    app.present_dialog(dialog)
