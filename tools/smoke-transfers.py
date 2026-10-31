"""Mapped GTK copy/move/review/cancellation across two disposable native vaults."""
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
temporary = tempfile.TemporaryDirectory(prefix="keyslot-transfer-ui-")
directory = Path(temporary.name)
os.environ["XDG_CONFIG_HOME"] = str(directory / "config")
from keyslot.app import Keyslot
from gi.repository import Adw, GLib, Gtk

app = Keyslot()
failures = []
expected_notice = False


def widgets(root):
    yield root
    child = root.get_first_child()
    while child:
        yield from widgets(child)
        child = child.get_next_sibling()


def row(dialog, title):
    return next(item for item in widgets(dialog) if isinstance(item, Adw.ComboRow) and item.get_title() == title)


def click(dialog, label):
    next(item for item in widgets(dialog) if isinstance(item, Gtk.Button) and item.get_label() == label).emit("clicked")


def wait(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, "Transfer GTK fixture timed out"
        yield


def scenario():
    global expected_notice
    yield from wait(lambda: app.active_session is not None)
    source = app.active_session
    app.set_background(False)
    source.requested_path = directory / "Source.kdbx"
    source.vault.create(source.path, "public fixture master")
    source.vault.save_entry(source.vault.snapshot.root, "Reviewed Entry", "public user", "https://example.org", "public notes", "public password")
    source.window.show_vault(source.vault.snapshot)
    destination = app.new_window(present=False)
    destination.requested_path = directory / "Destination.kdbx"
    destination.vault.create(destination.path, "different public master")
    destination.vault.add_group(destination.vault.snapshot.root, "Chosen Group")
    destination.window.show_vault(destination.vault.snapshot)
    target_group = next(group.uuid for group in destination.vault.snapshot.groups if group.name == "Chosen Group")
    original_id = source.vault.snapshot.entries[0].uuid

    def choose(copy=False):
        source.move_entry(source.vault.snapshot.entries[0])
        dialog = source.dialogs[-1]
        assert dialog.get_title() == "Copy or Move Entry"
        row(dialog, "Destination Vault").set_selected(1)
        group = row(dialog, "Destination Group")
        group.set_selected(next(index for index in range(group.get_model().get_n_items())
                                if "Chosen Group" in group.get_model().get_string(index)))
        if copy:
            row(dialog, "Action").set_selected(0)
        click(dialog, "Continue")

    before_source, before_destination = source.path.read_bytes(), destination.path.read_bytes()
    choose()
    yield from wait(lambda: not source.busy and any(isinstance(item, Adw.AlertDialog) and item.get_heading() == "Move Entry?" for item in source.dialogs))
    alert = source.dialogs[-1]
    assert "Reviewed Entry" in alert.get_body() and "Chosen Group" in alert.get_body()
    assert str(destination.path) in alert.get_body() and str(source.path) in alert.get_body()
    click(alert, "Cancel")
    yield from wait(lambda: not source.dialogs)
    source.jobs.executor.submit(lambda: None).result(timeout=3)
    assert source.path.read_bytes() == before_source and destination.path.read_bytes() == before_destination

    choose(copy=True)
    yield from wait(lambda: source.dialogs and isinstance(source.dialogs[-1], Adw.AlertDialog) and source.dialogs[-1].get_heading() == "Copy Entry?")
    click(source.dialogs[-1], "Copy")
    yield from wait(lambda: not source.busy and not destination.busy and len(destination.vault.snapshot.entries) == 1)
    copied = destination.vault.snapshot.entries[0]
    assert copied.group == target_group and copied.uuid != original_id
    assert source.vault.snapshot.entries[0].uuid == original_id
    assert destination.vault.attribute(copied) == "public password"

    choose()
    yield from wait(lambda: source.dialogs and isinstance(source.dialogs[-1], Adw.AlertDialog) and source.dialogs[-1].get_heading() == "Move Entry?")
    click(source.dialogs[-1], "Move")
    yield from wait(lambda: not source.busy and not destination.busy and len(destination.vault.snapshot.entries) == 2)
    assert not source.vault.snapshot.entries
    assert all(entry.uuid != original_id for entry in destination.vault.snapshot.entries)
    assert destination.window.selected_group == target_group

    # Locking the reviewed source cancels its transfer; neither vault is modified.
    source.vault.save_entry(source.vault.snapshot.root, "Cancelled Entry", "", "", "", "public second password")
    source.window.show_vault(source.vault.snapshot)
    # A saved copy whose source changed before cleanup must produce a visible partial-outcome warning.
    original_request = source.vault.transfer_request
    def changed(operation, **params):
        if operation == "finish":
            source.vault.set_attribute(source.vault.snapshot.entries[0], "Fixture update", "public value")
        return original_request(operation, **params)
    source.vault.transfer_request = changed
    choose()
    yield from wait(lambda: source.dialogs and isinstance(source.dialogs[-1], Adw.AlertDialog) and source.dialogs[-1].get_heading() == "Move Entry?")
    expected_notice = True
    click(source.dialogs[-1], "Move")
    yield from wait(lambda: not source.busy and source.dialogs and isinstance(source.dialogs[-1], Adw.AlertDialog)
                    and source.dialogs[-1].get_heading() == "Transfer Could Not Be Confirmed")
    notice = source.dialogs[-1]
    assert "destination copy was saved" in notice.get_body() and "cleanup could not be confirmed" in notice.get_body()
    assert len(source.vault.snapshot.entries) == 1 and len(destination.vault.snapshot.entries) == 3
    source.vault.transfer_request = original_request
    click(notice, "Close")
    yield from wait(lambda: not source.dialogs)
    expected_notice = False

    choose()
    yield from wait(lambda: source.dialogs and isinstance(source.dialogs[-1], Adw.AlertDialog) and source.dialogs[-1].get_heading() == "Move Entry?")
    before = destination.path.read_bytes()
    source.lock()
    yield from wait(lambda: not source.dialogs and not source.vault.unlocked)
    source.jobs.executor.submit(lambda: None).result(timeout=3)
    assert destination.path.read_bytes() == before
    source.vault.unlock(source.path, "public fixture master")
    assert source.vault.snapshot.entries[0].title == "Cancelled Entry"
    assert destination.vault.attribute(destination.vault.snapshot.entries[0]) == "public password"
    app.quit()


steps = scenario()
def tick():
    try:
        for session in app.sessions:
            if session.pending_errors:
                raise AssertionError(session.pending_errors)
            for dialog in session.dialogs:
                if not expected_notice and isinstance(dialog, Adw.AlertDialog) and dialog.get_heading() in (
                    "Could Not Complete Operation", "Transfer Could Not Be Confirmed", "Entry Copied; Original Kept"):
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
status = app.run(["keyslot-transfer-fixture"])
temporary.cleanup()
if failures:
    raise failures[0]
assert status == 0
print("GTK cross-vault copy/move selection, review/cancel, preserved credentials, refreshed views, partial-save warning and lock cancellation: PASS")
