"""Shortcut recording, staged editing and help from the active bindings."""
from .application import Adw, Gdk, Gtk, button
from .backend import VaultError
from .database_views import _dialog, _save
from .shortcuts import BY_ACTION, MODIFIERS, RESERVED, SPECS, conflicts, effective, normalize


def help_dialog(session):
    dialog = Adw.ShortcutsDialog()
    section = Adw.ShortcutsSection(title="Application")
    for spec in SPECS:
        if key := session.application.shortcuts.bindings[spec.action]:
            section.add(Adw.ShortcutsItem(title=spec.title, accelerator=key))
    dialog.add(section)
    selection = Adw.ShortcutsSection(title="Entry List")
    for key, title in RESERVED.items():
        selection.add(Adw.ShortcutsItem(title=title, accelerator=key))
    dialog.add(selection)
    from .autotype_fields import TYPES, SELECTOR_KEYS
    autotype = Adw.ShortcutsSection(title="Auto-Type Selector")
    for name, key in SELECTOR_KEYS.items():
        autotype.add(Adw.ShortcutsItem(title="Type " + TYPES[name][0], accelerator=key))
        autotype.add(Adw.ShortcutsItem(title="Copy " + TYPES[name][0],
                                     accelerator=key.replace("<Control>", "<Control><Shift>")))
    dialog.add(autotype)
    session.present_dialog(dialog)


def record(session, spec, chosen):
    manager = session.application.shortcuts
    dialog, _header, box = _dialog("Set Keyboard Shortcut", width=420, height=280)
    box.append(Gtk.Label(label=spec.title, wrap=True, css_classes=["title-2"]))
    box.append(Gtk.Label(label="Press a key combination. Use Escape to cancel.", wrap=True))
    status = Gtk.Label(wrap=True, css_classes=["error"])
    box.append(status)
    epoch = session.epoch
    inhibitor = object()
    manager.inhibitors.add(inhibitor)
    manager.install()
    def closed(*_):
        manager.inhibitors.discard(inhibitor)
        manager.install()
    dialog.connect("closed", closed)
    def key_pressed(_controller, keyval, _code, state):
        if keyval == Gdk.KEY_Escape:
            dialog.close()
            return True
        if keyval in (Gdk.KEY_Shift_L, Gdk.KEY_Shift_R, Gdk.KEY_Control_L, Gdk.KEY_Control_R,
                      Gdk.KEY_Alt_L, Gdk.KEY_Alt_R, Gdk.KEY_Super_L, Gdk.KEY_Super_R, Gdk.KEY_Meta_L, Gdk.KEY_Meta_R):
            return True
        mods = state & MODIFIERS
        # Keep Shift for letters, but remove it when the key symbol consumed it.
        event = _controller.get_current_event()
        if event and Gdk.keyval_to_lower(keyval) == keyval:
            mods &= ~(event.get_consumed_modifiers() & Gdk.ModifierType.SHIFT_MASK)
        try:
            if Gdk.keyval_to_unicode(keyval) and not mods & (Gdk.ModifierType.CONTROL_MASK | Gdk.ModifierType.ALT_MASK | Gdk.ModifierType.SUPER_MASK):
                raise VaultError("Combine a character key with Control, Alt or Super.")
            key = normalize(Gtk.accelerator_name(keyval, mods))
        except VaultError as exc:
            status.set_label(str(exc))
            return True
        if session.epoch == epoch:
            dialog.force_close()
            chosen(key)
        return True
    controller = Gtk.EventControllerKey()
    controller.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
    controller.connect("key-pressed", key_pressed)
    dialog.add_controller(controller)
    if not session.present_dialog(dialog):
        closed()


def show(session, snapshot=None):
    if session.busy:
        return
    manager = session.application.shortcuts
    if snapshot is None:
        session.run_job(manager.store.read, lambda value: show(session, value))
        return
    dialog, header, box = _dialog("Keyboard Shortcuts", width=560, height=640)
    box.append(Gtk.Label(label="Choose an action to change its shortcut. Changes apply when you save. Desktop auto-type shortcuts are configured separately.", wrap=True, xalign=0))
    draft = dict(snapshot["values"])
    changed = set()
    rows = {}
    status = Gtk.Label(wrap=True, xalign=0, css_classes=["error"], visible=False)
    box.append(status)
    search = Gtk.SearchEntry(placeholder_text="Search actions")
    box.append(search)
    group = Adw.PreferencesGroup()
    box.append(group)
    def current():
        return dialog in session.dialogs and not session.jobs.closed
    def refresh():
        bindings = effective(draft)
        for action, (row, label, reset, disable) in rows.items():
            spec, value = BY_ACTION[action], draft[action]
            label.set_accelerator(bindings[action])
            problem = snapshot["problems"].get(action) if action not in changed else None
            collision = conflicts(bindings, action, bindings[action])
            row.set_subtitle(problem or ("Conflicts with another shortcut" if collision else
                "Default" if value is None else "Disabled" if value == "" else "Custom"))
            reset.set_sensitive(value is not None or bool(problem))
            disable.set_sensitive(value != "" or bool(problem))
        save.set_sensitive(bool(changed) and not any(conflicts(bindings, action, key) for action, key in bindings.items()))
    def stage(action, value):
        draft[action] = value
        # A preserved unsupported value must be replaceable by an explicit Disable.
        if value == snapshot["values"][action] and action not in snapshot["problems"]:
            changed.discard(action)
        else:
            changed.add(action)
        refresh()
    def choose(action, key):
        if not current():
            return
        collisions = conflicts(effective(draft), action, key)
        if any(name not in BY_ACTION for name in collisions):
            status.set_label("This combination is reserved for entry selection or navigation.")
            status.set_visible(True)
            return
        status.set_visible(False)
        if not collisions:
            stage(action, key)
            return
        alert = Adw.AlertDialog(heading="Replace Existing Shortcut?", body="This combination is assigned to: " +
            ", ".join(BY_ACTION[name].title for name in collisions) + ". Their shortcuts will be disabled when you save.")
        alert.add_response("cancel", "Cancel")
        alert.add_response("replace", "Replace")
        alert.set_close_response("cancel")
        alert.set_default_response("cancel")
        def replace(_dialog, response):
            if response == "replace" and current():
                for other in collisions:
                    stage(other, "")
                stage(action, key)
        alert.connect("response", replace)
        session.present_dialog(alert)
    for spec in SPECS:
        row = Adw.ActionRow(title=spec.title, activatable=True)
        label = Adw.ShortcutLabel(valign=Gtk.Align.CENTER, disabled_text="Disabled")
        row.add_suffix(label)
        reset = button("edit-undo-symbolic", "Restore Default for " + spec.title, lambda action=spec.action: stage(action, None))
        disable = button("edit-clear-symbolic", "Disable Shortcut for " + spec.title, lambda action=spec.action: stage(action, ""))
        row.add_suffix(reset)
        row.add_suffix(disable)
        row.connect("activated", lambda _row, spec=spec: record(session, spec, lambda key: choose(spec.action, key)))
        group.add(row)
        rows[spec.action] = row, label, reset, disable
    search.connect("search-changed", lambda *_: [row.set_visible(search.get_text().casefold() in BY_ACTION[action].title.casefold())
                                                for action, (row, *_rest) in rows.items()])
    def reset_all(*_):
        for spec in SPECS:
            draft[spec.action] = None
            if snapshot["values"][spec.action] is not None or spec.action in snapshot["problems"]:
                changed.add(spec.action)
            else:
                changed.discard(spec.action)
        status.set_visible(False)
        refresh()
    reset = Gtk.Button(label="Restore All Defaults")
    reset.connect("clicked", reset_all)
    box.append(reset)
    def submit(*_):
        if not current() or session.busy or not changed:
            return
        changes = {action: draft[action] for action in changed}
        def completed(value):
            manager.apply(value)
            if current():
                dialog.close()
            session.toast("Keyboard shortcuts saved")
        session.run_job(lambda: manager.store.save(changes, snapshot), completed)
    save = _save(header, submit)
    refresh()
    session.present_dialog(dialog)
