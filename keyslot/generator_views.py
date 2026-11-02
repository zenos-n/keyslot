"""Upstream password/passphrase generation with private, credential-free settings."""
from .i18n import mark as _mark, tr as _tr, trf as _trf
import json
from pathlib import Path

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

from .startup import _write
from .core_backend import EngineError
from .backend import VaultError
from .wordlists import WordLists, WordListError


DEFAULTS = dict(length=24, word_count=6, passphrase=False, lowercase=True, uppercase=True,
                numbers=True, symbols=True, braces=True, punctuation=True, quotes=True,
                dashes=True, math=True, logograms=True, extended_ascii=False, every_group=True,
                exclude_lookalike=False, additional="", excluded="", word_case="lowercase",
                separator=" ", wordlist="eff_large.wordlist")
CASES = [("lowercase", _mark("lower case")), ("uppercase", _mark("UPPER CASE")),
         ("titlecase", _mark("Title Case")), ("mixedcase", _mark("MIXED case"))]
QUALITIES = [_mark("Poor"), _mark("Poor"), _mark("Weak"), _mark("Good"), _mark("Excellent")]


def _validate(data):
    if not isinstance(data, dict) or set(data) != set(DEFAULTS):
        return False
    for key, default in DEFAULTS.items():
        if type(data[key]) is not type(default):
            return False
        if isinstance(default, str) and (len(data[key]) > 32767 or "\0" in data[key]):
            return False
    return (1 <= data["length"] <= 999 and 1 <= data["word_count"] <= 100
            and data["word_case"] in {code for code, _ in CASES})


def _load(path):
    try:
        with path.open() as stream:
            encoded = stream.read(1024 * 1024 + 1)
        data = json.loads(encoded) if len(encoded) <= 1024 * 1024 else None
        return data if _validate(data) else dict(DEFAULTS)
    except (OSError, ValueError):
        return dict(DEFAULTS)


def saved_settings(startup, *, strict=False):
    if startup.storage:
        return startup.storage.read_generator()
    path = startup.directory / "keyslot" / "generator.json"
    if not strict:
        return _load(path)
    try:
        with path.open() as stream:
            encoded = stream.read(1024 * 1024 + 1)
    except FileNotFoundError:
        if path.is_symlink():
            raise VaultError("The saved generator settings link is broken. Review Generator Options before generating.")
        return dict(DEFAULTS)
    if len(encoded) > 1024 * 1024:
        raise VaultError("The saved generator settings are too large. Review Generator Options before generating.")
    data = json.loads(encoded)
    if not _validate(data):
        raise VaultError("The saved generator settings are invalid. Review Generator Options before generating.")
    return data


def parameters(chosen):
    params = {key: value for key, value in chosen.items() if key != "word_count"}
    params["length"] = chosen["word_count"] if chosen["passphrase"] else chosen["length"]
    return params


def show(session, on_apply=None):
    from .application import button, margins, scroll

    if session.busy:
        return
    path = session.application.startup.directory / "keyslot" / "generator.json"
    storage = getattr(session.application.startup, "storage", None)
    library = WordLists(session.application.startup)
    try:
        saved = saved_settings(session.application.startup)
    except (OSError, ValueError, VaultError) as exc:
        session.error(str(exc))
        return
    state = {"revision": 0, "closed": False, "applied": False, "setting_output": False,
             "health_revision": 0, "health_timer": 0, "mode": saved["passphrase"], "saved": saved,
             "length": saved["length"], "word_count": saved["word_count"], "lists": [], "library": [], "system": [],
             "custom": saved["wordlist"] if Path(saved["wordlist"]).is_absolute() else ""}
    dialog = Adw.Dialog(title=_tr("Password Generator"), content_width=440)
    toolbar = Adw.ToolbarView()
    header = Adw.HeaderBar()
    toolbar.add_top_bar(header)
    box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24), 24)
    output = Adw.PasswordEntryRow(title=_tr("Generated Passphrase") if saved["passphrase"] else _tr("Generated Password"))
    result_group = Adw.PreferencesGroup()
    result_group.add(output)
    box.append(result_group)
    strength = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, visible=False)
    strength_label = Gtk.Label(xalign=0, wrap=True, css_classes=["caption"])
    meter = Gtk.LevelBar(min_value=0, max_value=128, tooltip_text=_tr("Estimated Password Strength"))
    for name, value in (("low", 40), ("high", 75), ("full", 100)):
        meter.add_offset_value(name, value)
    strength.append(strength_label)
    strength.append(meter)
    box.append(strength)
    warning = Gtk.Label(label=_tr("This word list contains fewer than 1296 distinct words."),
                        xalign=0, wrap=True, css_classes=["warning"], visible=False)
    box.append(warning)
    error_label = Gtk.Label(xalign=0, wrap=True, css_classes=["error"], visible=False)
    box.append(error_label)
    options = Adw.PreferencesGroup()
    words = Adw.SwitchRow(title=_tr("Use a Passphrase"), active=saved["passphrase"])
    length = Adw.SpinRow.new_with_range(1, 100 if saved["passphrase"] else 999, 1)
    length.set_title(_tr("Words") if saved["passphrase"] else _tr("Length"))
    length.set_value(saved["word_count"] if saved["passphrase"] else saved["length"])
    options.add(words)
    options.add(length)
    box.append(options)
    phrase = Adw.PreferencesGroup(title=_tr("Passphrase Options"), visible=saved["passphrase"])
    word_case = Adw.ComboRow(title=_tr("Word Case"), model=Gtk.StringList.new([_tr(label) for _, label in CASES]))
    word_case.set_selected(next(i for i, (code, _) in enumerate(CASES) if code == saved["word_case"]))
    separator = Adw.EntryRow(title=_tr("Word Separator"), text=saved["separator"])
    wordlist = Adw.ComboRow(title=_tr("Word List"), sensitive=False)
    custom = Adw.ActionRow(title=_tr("Custom Word List"), subtitle=Path(state["custom"]).name or _tr("None selected"),
                          subtitle_lines=1, use_markup=False, visible=bool(state["custom"]))
    phrase.set_description(_tr("Choose a UTF-8 or Diceware word list. Import a copy into your library or use a file directly."))
    for row in (word_case, separator, wordlist, custom):
        phrase.add(row)
    manage = Adw.ActionRow(title=_tr("Manage Word Lists…"), subtitle=_tr("Import or remove custom lists"), activatable=True)
    manage.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
    phrase.add(manage)
    box.append(phrase)
    characters = Adw.PreferencesGroup(title=_tr("Characters"), visible=not saved["passphrase"])
    rows = {}
    for key, title in [("lowercase", _mark('Lowercase (a–z)')), ("uppercase", _mark('Uppercase (A–Z)')),
                       ("numbers", _mark('Numbers (0–9)')), ("symbols", _mark("Symbols (!@#$…)"))]:
        row = Adw.SwitchRow(title=_tr(title.strip()), active=saved[key])
        characters.add(row)
        rows[key] = row
    box.append(characters)
    advanced_group = Adw.PreferencesGroup(visible=not saved["passphrase"])
    advanced = Adw.ExpanderRow(title=_tr("More Character Options"))
    for key, title in [("exclude_lookalike", _mark("Exclude Look-alike Characters")),
                       ("every_group", _mark("Require Each Character Group")), ("extended_ascii", _mark("Extended ASCII Characters"))]:
        row = Adw.SwitchRow(title=_tr(title), active=saved[key])
        advanced.add_row(row)
        rows[key] = row
    symbol_rows = []
    for key, title in [("braces", _mark("Brackets: ()[]{}")), ("punctuation", _mark("Punctuation: .,:;")),
                       ("quotes", _mark("Quotes")), ("dashes", _mark("Dashes and Slashes")),
                       ("math", _mark("Math Symbols")), ("logograms", _mark("Other Symbols"))]:
        row = Adw.SwitchRow(title=_tr(title), active=saved[key], sensitive=saved["symbols"])
        advanced.add_row(row)
        rows[key] = row
        symbol_rows.append(row)
    additional = Adw.EntryRow(title=_tr("Additional Characters"), text=saved["additional"])
    excluded = Adw.EntryRow(title=_tr("Excluded Characters"), text=saved["excluded"])
    advanced.add_row(additional)
    advanced.add_row(excluded)
    advanced_group.add(advanced)
    box.append(advanced_group)
    actions = Gtk.Box(spacing=12, homogeneous=True)
    generate = Gtk.Button(label=_tr("Generate"), css_classes=["suggested-action"], sensitive=False)
    copy = Gtk.Button(label=_tr("Use Password") if on_apply else _tr("Copy"), sensitive=False)
    actions.append(generate)
    if on_apply:
        generate.remove_css_class("suggested-action")
        copy.add_css_class("suggested-action")
        copy.set_valign(Gtk.Align.CENTER)
        header.pack_end(copy)
    else:
        actions.append(copy)
    box.append(actions)

    def clear_strength():
        state["health_revision"] += 1
        if state["health_timer"]:
            GLib.source_remove(state["health_timer"])
            state["health_timer"] = 0
        strength.set_visible(False)
        warning.set_visible(False)
        strength_label.set_label("")
        meter.set_value(0)

    def set_output(value):
        state["setting_output"] = True
        output.set_text(value)
        state["setting_output"] = False
        copy.set_sensitive(bool(value) and not state["closed"])

    def invalidate(*_):
        state["revision"] += 1
        error_label.set_label("")
        error_label.set_visible(False)
        clear_strength()
        set_output("")

    def display_health(data):
        quality = QUALITIES[data["quality"]]
        strength_label.set_label(_trf('{arg0} · {arg1:.1f} bits · {arg2} characters', arg0=_tr(quality), arg1=data['entropy'], arg2=data['length']))
        meter.set_value(min(128, max(0, data["entropy"])))
        strength.set_visible(True)
        warning.set_visible(data.get("wordlist_valid") is False)

    def output_changed(*_):
        if state["setting_output"] or state["closed"]:
            return
        state["revision"] += 1
        clear_strength()
        copy.set_sensitive(bool(output.get_text()))
        if not output.get_text():
            return
        revision = state["health_revision"]
        def estimate():
            if state["closed"] or revision != state["health_revision"]:
                state["health_timer"] = 0
                return GLib.SOURCE_REMOVE
            value = output.get_text()
            def done(data):
                if not state["closed"] and revision == state["health_revision"]:
                    display_health(data)
            if not session.jobs.run(lambda: session.vault.password_health(value), done, interactive=False):
                return GLib.SOURCE_CONTINUE
            state["health_timer"] = 0
            return GLib.SOURCE_REMOVE
        state["health_timer"] = GLib.timeout_add(250, estimate)
    output.connect("changed", output_changed)

    def mode_changed(*_):
        state["word_count" if state["mode"] else "length"] = int(length.get_value())
        active = words.get_active()
        state["mode"] = active
        length.get_adjustment().set_upper(100 if active else 999)
        length.set_value(state["word_count" if active else "length"])
        length.set_title(_tr("Words") if active else _tr("Length"))
        output.set_title(_tr("Generated Passphrase") if active else _tr("Generated Password"))
        phrase.set_visible(active)
        characters.set_visible(not active)
        advanced_group.set_visible(not active)
        invalidate()
    words.connect("notify::active", mode_changed)
    length.connect("notify::value", invalidate)
    word_case.connect("notify::selected", invalidate)
    separator.connect("changed", invalidate)
    for row in rows.values():
        row.connect("notify::active", invalidate)
    additional.connect("changed", invalidate)
    excluded.connect("changed", invalidate)
    rows["symbols"].connect("notify::active", lambda *_: [row.set_sensitive(rows["symbols"].get_active()) for row in symbol_rows])

    def custom_selected(value):
        if state["closed"]:
            return
        state["custom"] = value
        custom.set_subtitle(Path(value).name if value else _tr("None selected"))
        if value:
            wordlist.set_selected(state["lists"].index(value) if value in state["lists"] else len(state["lists"]))
        else:
            wordlist.set_selected(next((i for i, name in enumerate(state["lists"]) if name == "eff_large.wordlist"), 0))
        invalidate()
    custom.add_suffix(button("document-open-symbolic", _tr('Choose Word List'), lambda: session.choose_file(custom_selected)))
    custom.add_suffix(button("edit-clear-symbolic", _tr('Use Default Word List'), lambda: custom_selected("")))
    def list_changed(*_):
        custom.set_visible(wordlist.get_selected() == len(state["lists"]))
        invalidate()
    wordlist.connect("notify::selected", list_changed)

    def chosen_list():
        index = wordlist.get_selected()
        return state["lists"][index] if index < len(state["lists"]) else state["custom"]

    def update_lists(entries, selected=None):
        selected = chosen_list() if selected is None else selected
        state["library"] = entries
        state["lists"] = state["system"] + [item["path"] for item in entries]
        if Path(selected).is_absolute() and Path(selected).parent == library.directory and selected not in state["lists"]:
            selected = "eff_large.wordlist"
            state["custom"] = ""
            custom.set_subtitle(_tr("None selected"))
        labels = [f"{name} (Installed)" for name in state["system"]] + [item["name"] for item in entries]
        wordlist.set_model(Gtk.StringList.new(labels + [_tr("Custom…")]))
        wordlist.set_selected(state["lists"].index(selected) if selected in state["lists"] else len(state["lists"]))
        custom.set_visible(wordlist.get_selected() == len(state["lists"]))
        invalidate()

    def manage_lists(*_):
        if state["closed"] or session.busy:
            return
        from .application import scroll
        view = Adw.Dialog(title=_tr("Word Lists"), content_width=440, content_height=460)
        tools = Adw.ToolbarView()
        top = Adw.HeaderBar()
        add = Gtk.Button(label=_tr("Import…"), css_classes=["suggested-action"])
        top.pack_end(add)
        tools.add_top_bar(top)
        content = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18), 18)
        description = Gtk.Label(label=_tr("Imported lists are copied into this configuration's library. Removing a copy leaves the original file untouched."),
                                xalign=0, wrap=True, css_classes=["dim-label"])
        content.append(description)
        notice = Gtk.Label(xalign=0, wrap=True, visible=False)
        content.append(notice)
        entries_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content.append(entries_box)
        tools.set_content(scroll(content, natural=True))
        view.set_child(tools)
        opened = {"alive": True, "working": False}

        def render(entries):
            while child := entries_box.get_first_child():
                entries_box.remove(child)
            group = Adw.PreferencesGroup(title=_tr("Custom Word Lists"))
            entries_box.append(group)
            if not entries:
                group.add(Adw.ActionRow(title=_tr("No custom word lists"), subtitle=_tr("Installed word lists remain available in the generator.")))
            for item in entries:
                row = Adw.ActionRow(title=item["name"], use_markup=False, subtitle=item["path"], subtitle_lines=1)
                row.add_suffix(button("user-trash-symbolic", _tr('Remove Word List'), lambda item=item: remove(item)))
                group.add(row)

        def failed(message):
            opened["working"] = False
            if opened["alive"]:
                add.set_sensitive(True)
                entries_box.set_sensitive(True)
                notice.set_label(message)
                notice.add_css_class("error")
                notice.set_visible(True)

        def run(operation, done):
            if not opened["alive"] or opened["working"] or state["closed"]:
                return
            opened["working"] = True
            add.set_sensitive(False)
            entries_box.set_sensitive(False)
            notice.set_visible(False)
            def finished(result):
                opened["working"] = False
                if opened["alive"] and not state["closed"]:
                    add.set_sensitive(True)
                    entries_box.set_sensitive(True)
                    if "error" in result:
                        failed(result["error"])
                    else:
                        done(result["value"])
            def perform():
                try:
                    return {"value": operation()}
                except EngineError as exc:
                    if exc.code not in {"invalid_request", "file_error"}:
                        raise
                    return {"error": str(exc)}
                except (WordListError, OSError, ValueError) as exc:
                    return {"error": str(exc)}
            if not session.run_job(perform, finished, failed):
                failed("Wait for the current operation, then try again.")

        def imported(result):
            update_lists(result["entries"], result["path"])
            render(result["entries"])
            notice.remove_css_class("error")
            notice.set_label(_tr("Word list imported.") if result["wordlist_valid"] else
                             _tr("Imported. This list has fewer than 1296 distinct words; use a longer passphrase or a larger list."))
            notice.set_visible(True)

        def import_file(path):
            epoch = session.epoch
            def alive():
                return opened["alive"] and not state["closed"] and not session.jobs.closed and session.epoch == epoch
            def operation():
                result = library.add(path, session.vault.inspect_wordlist, alive)
                return {**result, "entries": library.entries()}
            if alive():
                run(operation, imported)
        add.connect("clicked", lambda *_: session.choose_file(import_file))

        def remove(item):
            if opened["working"]:
                return
            alert = Adw.AlertDialog(heading=_tr("Remove Word List?"), body=_trf('Remove “{arg0}” from this library? The original imported file is kept.', arg0=item['name']))
            alert.add_response("cancel", _tr("Cancel"))
            alert.add_response("remove", _tr("Remove"))
            alert.set_close_response("cancel")
            alert.set_default_response("cancel")
            alert.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
            def response(_alert, answer):
                if answer != "remove" or not opened["alive"]:
                    return
                def operation():
                    library.remove(item)
                    return library.entries()
                def removed(entries):
                    selected = chosen_list()
                    if selected == item["path"]:
                        selected = "eff_large.wordlist"
                    if state["custom"] == item["path"]:
                        state["custom"] = ""
                        custom.set_subtitle(_tr("None selected"))
                    update_lists(entries, selected)
                    render(entries)
                run(operation, removed)
            alert.connect("response", response)
            session.present_dialog(alert)
        render(state["library"])
        view.connect("closed", lambda *_: opened.update(alive=False))
        session.present_dialog(view)
        def refreshed(entries):
            if entries != state["library"]:
                update_lists(entries)
            render(entries)
        run(library.entries, refreshed)

    manage.connect("activated", manage_lists)

    def settings():
        state["word_count" if words.get_active() else "length"] = int(length.get_value())
        selected = wordlist.get_selected()
        return {"length": state["length"], "word_count": state["word_count"], "passphrase": words.get_active(),
                **{key: row.get_active() for key, row in rows.items()}, "additional": additional.get_text(),
                "excluded": excluded.get_text(), "word_case": CASES[word_case.get_selected()][0],
                "separator": separator.get_text(),
                "wordlist": state["lists"][selected] if selected < len(state["lists"]) else state["custom"]}

    def request(*_, initial=False):
        if session.busy or state["closed"]:
            return
        invalidate()
        revision = state["revision"]
        chosen = settings()
        params = parameters(chosen)
        def generated(data):
            if state["closed"] or revision != state["revision"]:
                return
            if "error" in data:
                error_label.set_label(data["error"])
                error_label.set_visible(True)
                return
            set_output(data["value"])
            display_health(data)
            if chosen != state["saved"] or not storage:
                try:
                    if storage:
                        storage.write_generator(chosen)
                    else:
                        _write(path, json.dumps(chosen) + "\n")
                    state["saved"] = chosen
                except (OSError, ValueError, VaultError) as exc:
                    session.toast(_tr("Generated password; settings could not be saved"))
                    error_label.set_label(str(exc))
                    error_label.set_visible(True)
        def perform():
            try:
                return session.vault.generate(**params, details=True)
            except EngineError as exc:
                if exc.code in {"invalid_request", "file_error"}:
                    return {"error": str(exc)}
                raise
        if on_apply and initial:
            session.jobs.run(perform, generated, interactive=False)
        else:
            session.run_job(perform, generated)
    generate.connect("clicked", request)

    def use(*_):
        if state["closed"] or state["applied"] or not output.get_text():
            return
        if on_apply:
            state["applied"] = True
            on_apply(output.get_text())
        else:
            session.copy(output.get_text())
    copy.connect("clicked", use)
    toolbar.set_content(scroll(box, natural=True))
    dialog.set_child(toolbar)
    def closed(*_):
        state["closed"] = True
        invalidate()
        if on_apply and not state["applied"]:
            on_apply(None)
    def clear_sensitive():
        state["closed"] = True
        invalidate()
    dialog._clear_sensitive_fields = clear_sensitive
    def close_attempt(*_):
        from .application import clear_dialog_fields
        clear_dialog_fields(dialog)
        dialog.force_close()
    dialog.set_can_close(False)
    dialog.connect("close-attempt", close_attempt)
    dialog.connect("closed", closed)
    session.present_dialog(dialog)
    def catalogue(data):
        if state["closed"]:
            return
        state["system"] = data["wordlists"]
        update_lists(data["user_wordlists"], saved["wordlist"])
        wordlist.set_sensitive(True)
        manage.set_sensitive("wordlist-library" in session.vault.capabilities)
        generate.set_sensitive(True)
        request(initial=True)
    def load_catalogue():
        return {**session.vault.generator_info(), "user_wordlists": library.entries()}
    if on_apply:
        session.jobs.run(load_catalogue, catalogue, interactive=False)
    else:
        session.run_job(load_catalogue, catalogue)
    return dialog
