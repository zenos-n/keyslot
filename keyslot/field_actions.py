"""Stock field double-click behavior on GNOME property rows."""
from gi.repository import Gtk


def add_double_click(session, row, entry, name):
    snapshot, epoch = session.vault.snapshot, session.epoch
    gesture = Gtk.GestureClick(button=1, propagation_phase=Gtk.PropagationPhase.CAPTURE)

    def released(gesture, presses, x, y):
        if (presses != 2 or session.busy or not session.active or not session.vault.unlocked
                or session.epoch != epoch or session.vault.snapshot is not snapshot or row.get_root() is None
                or session.window.selected_entry is not entry or session.dialogs or session.file_requests):
            return
        picked = row.pick(x, y, Gtk.PickFlags.DEFAULT)
        while picked is not None and picked is not row:
            if isinstance(picked, (Gtk.Button, Gtk.MenuButton, Gtk.Entry, Gtk.Switch)):
                return
            picked = picked.get_parent()
        gesture.set_state(Gtk.EventSequenceState.CLAIMED)
        settings = session.application.startup
        if name == "URL":
            action = settings.url_double_click_action
            if action == 0:
                session.open_entry_url(entry)
                return
            copy = action == 1
        else:
            copy = settings.copy_on_double_click
        if copy:
            session.run_job(lambda: session.vault.attribute(entry, name), session.copy_entry)
        else:
            session.edit_entry(entry)

    gesture.connect("released", released)
    row.add_controller(gesture)
