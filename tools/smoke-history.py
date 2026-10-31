"""Mapped history comparisons, explicit reveals, version attachments and stale/lock cleanup."""
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
temporary = tempfile.TemporaryDirectory(prefix="keyslot-history-ui-")
directory = Path(temporary.name)
os.environ["XDG_CONFIG_HOME"] = str(directory / "config")
from keyslot.app import Keyslot
from gi.repository import Adw, GLib, Gtk

app = Keyslot()
failures = []


def widgets(root):
    yield root
    child = root.get_first_child()
    while child:
        yield from widgets(child)
        child = child.get_next_sibling()


def row(root, title, kind=Adw.ExpanderRow):
    return next(widget for widget in widgets(root) if isinstance(widget, kind) and widget.get_title() == title)


def click(root, label=None, tooltip=None):
    button = next(widget for widget in widgets(root) if isinstance(widget, Gtk.Button)
                  and (widget.get_label() == label if label else widget.get_tooltip_text() == tooltip))
    button.emit("clicked")


def texts(root):
    return [widget.get_text() for widget in widgets(root) if isinstance(widget, Gtk.Label)]


def wait(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, "History UI fixture timed out"
        yield


def scenario():
    yield from wait(lambda: app.active_session is not None)
    session = app.active_session
    app.set_background(False)
    session.requested_path = directory / "fixture.kdbx"
    session.vault.create(session.path, "public fixture master")
    session.vault.save_entry(session.vault.snapshot.root, "Old <Title>", "old-user", "", "Old notes\nSecond line", "public old secret")
    attachment = directory / "Attachment.bin"
    attachment.write_bytes(b"public old attachment\x00\xff")
    session.vault.import_attachment(session.vault.snapshot.entries[0], attachment)
    old_index = session.vault.snapshot.entries[0].history_count
    entry = session.vault.snapshot.entries[0]
    session.vault.save_entry(entry.group, "New Title", "new-user", "https://example.org", "New notes", "public new secret", entry=entry, tags="new")
    entry = session.vault.snapshot.entries[0]
    session.window.show_vault(session.vault.snapshot)
    before = session.path.read_bytes()
    session.show_history(entry)
    yield from wait(lambda: not session.busy and session.dialogs and session.dialogs[-1].get_title() == "Entry History")
    history = session.dialogs[-1]
    assert "Old <Title>" in texts(history)  # No markup interpretation of a title.
    click(history, tooltip="Inspect and Compare Version")
    yield from wait(lambda: not session.busy and session.dialogs[-1].get_title() == "Compare Entry Versions")
    comparison = session.dialogs[-1]
    password = row(comparison, "Password")
    password.set_expanded(True)
    assert not any("public old secret" in text or "public new secret" in text for text in texts(comparison))
    click(password, "Reveal")
    yield from wait(lambda: not session.busy and "public old secret" in texts(password))
    click(password, "Hide")
    assert "public old secret" not in texts(password)
    click(password, "Reveal")
    yield from wait(lambda: not session.busy and "public old secret" in texts(password))
    password.set_expanded(False)
    assert "public old secret" not in texts(password)
    password.set_expanded(True)
    assert session.path.read_bytes() == before

    # Rebuilding a comparison while a secret fetch is pending must discard its late reply.
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original = session.vault.history_value
    def paused(*args):
        entered.set()
        assert release.wait(8)
        try:
            return original(*args)
        finally:
            finished.set()
    with patch.object(session.vault, "history_value", paused):
        click(password, "Reveal")
        yield from wait(entered.is_set)
        row(comparison, "Only Show Changes", Adw.SwitchRow).set_active(False)
        release.set()
        yield from wait(lambda: finished.is_set() and not session.busy)
    assert "public old secret" not in texts(comparison)
    password = row(comparison, "Password")
    password.set_expanded(True)
    click(password, "Reveal")
    yield from wait(lambda: not session.busy and "public old secret" in texts(comparison))
    saved_labels = [widget for widget in widgets(comparison) if isinstance(widget, Gtk.Label)]

    # An attachment comes from the selected saved version, without rewriting the vault.
    field = row(comparison, "Attachment.bin")
    field.set_expanded(True)
    target = directory / "export.bin"
    with patch.object(session, "choose_file", side_effect=lambda callback, **_kwargs: callback(str(target))):
        click(field, tooltip="Save This Version’s Attachment")
    yield from wait(lambda: target.exists() and not session.busy)
    assert target.read_bytes() == b"public old attachment\x00\xff"
    assert session.path.read_bytes() == before

    # Any two versions can be selected; equal endpoints have no differences.
    right = row(comparison, "Compare With", Adw.ComboRow)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original_compare = session.vault.compare_history
    def delayed_compare(*args):
        entered.set()
        assert release.wait(8)
        try:
            return original_compare(*args)
        finally:
            finished.set()
    with patch.object(session.vault, "compare_history", delayed_compare):
        right.set_selected(1)
        yield from wait(entered.is_set)
        right.set_selected(0)
        release.set()
        yield from wait(finished.is_set)
    yield from wait(lambda: not session.busy and any("fields differ" in text and not text.startswith("0 fields") for text in texts(comparison)))
    right.set_selected(1)
    yield from wait(lambda: not session.busy and any(text.startswith("0 fields differ") for text in texts(comparison)))
    assert not any(label.get_text() == "public old secret" for label in saved_labels)
    row(comparison, "Selected Version", Adw.ComboRow).set_selected(0)
    yield from wait(lambda: not session.busy)
    restore = next(widget for widget in widgets(comparison) if isinstance(widget, Gtk.Button)
                   and widget.get_label() == "Restore Selected Version…")
    assert not restore.get_sensitive()
    row(comparison, "Selected Version", Adw.ComboRow).set_selected(1)
    yield from wait(lambda: not session.busy)
    click(comparison, "Restore Selected Version…")
    alert = session.dialogs[-1]
    click(alert, "Cancel")
    yield from wait(lambda: alert not in session.dialogs)
    assert comparison in session.dialogs and session.path.read_bytes() == before
    click(comparison, "Restore Selected Version…")
    click(session.dialogs[-1], "Restore")
    yield from wait(lambda: not session.busy and comparison not in session.dialogs and history not in session.dialogs)
    assert session.vault.snapshot.entries[0].title == "Old <Title>"
    assert session.vault.attribute(session.vault.snapshot.entries[0]) == "public old secret"

    # Explicit delete-all supports cancel and keeps the current entry when accepted.
    session.show_history(session.vault.snapshot.entries[0])
    yield from wait(lambda: not session.busy and session.dialogs and session.dialogs[-1].get_title() == "Entry History")
    history = session.dialogs[-1]
    before = session.path.read_bytes()
    click(history, "Delete All History…")
    alert = session.dialogs[-1]
    click(alert, "Cancel")
    yield from wait(lambda: alert not in session.dialogs)
    assert history in session.dialogs and session.path.read_bytes() == before
    click(history, "Delete All History…")
    click(session.dialogs[-1], "Delete All")
    yield from wait(lambda: not session.busy and history not in session.dialogs)
    entry = session.vault.snapshot.entries[0]
    assert entry.history_count == 0 and session.vault.attribute(entry) == "public old secret"

    # Lock during a comparison read cannot reopen a helper or repaint old fields.
    session.vault.save_entry(entry.group, entry.title, "later-user", entry.url, entry.notes, "public later secret", entry=entry)
    session.window.show_vault(session.vault.snapshot)
    entry = session.vault.snapshot.entries[0]
    session.show_history(entry)
    yield from wait(lambda: not session.busy and session.dialogs and session.dialogs[-1].get_title() == "Entry History")
    history = session.dialogs[-1]
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original_compare = session.vault.compare_history
    def paused_compare(*args):
        entered.set()
        assert release.wait(8)
        try:
            return original_compare(*args)
        finally:
            finished.set()
    with patch.object(session.vault, "compare_history", paused_compare):
        click(history, tooltip="Inspect and Compare Version")
        yield from wait(entered.is_set)
        comparison = session.dialogs[-1]
        session.lock()
        release.set()
        yield from wait(finished.is_set)
        yield
    assert not session.dialogs and not session.vault.unlocked
    assert "public later secret" not in texts(comparison)
    app.quit()


steps = scenario()
def tick():
    try:
        for session in app.sessions:
            for dialog in session.dialogs:
                if isinstance(dialog, Adw.AlertDialog) and dialog.get_heading() == "Could Not Complete Operation":
                    raise AssertionError(dialog.get_body())
        next(steps)
        return True
    except StopIteration:
        return False
    except Exception as exc:
        failures.append(exc)
        app.quit()
        return False

app.connect("activate", lambda *_: GLib.timeout_add(25, tick))
status = app.run(["keyslot-history-fixture"])
temporary.cleanup()
if failures:
    raise failures[0]
assert status == 0
print("GTK history comparison/reveal/hide, field rebuild cleanup, any-version selectors, attachment export, reviewed restore/delete-all and late-lock cancellation: PASS")
