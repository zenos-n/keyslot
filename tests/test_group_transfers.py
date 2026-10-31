"""Recursive native group transfer and atomic bulk-entry operations."""
import base64
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch
import uuid

from keyslot.backend import VaultError
from keyslot.core_backend import Vault
from keyslot.transfers import EntryTransfer
from test_appearance import png
import test_transfers as fixtures

ENGINE = fixtures.ENGINE


@unittest.skipUnless(ENGINE, "native engine required")
class GroupTransfers(unittest.TestCase):
    setUp = fixtures.Transfers.setUp
    tearDown = fixtures.Transfers.tearDown
    original = fixtures.Transfers.original
    xml = fixtures.Transfers.xml
    deliver = fixtures.Transfers.deliver

    def collection(self):
        self.source.add_group(self.source.snapshot.root, "Collection")
        root = next(group.uuid for group in self.source.snapshot.groups if group.name == "Collection")
        self.source.add_group(root, "Nested")
        child = next(group.uuid for group in self.source.snapshot.groups if group.name == "Nested")
        self.source.add_group(root, "Empty")
        self.source.move_entry(self.original(), root)
        self.source.save_entry(child, "Nested Entry", "public nested user", "", "", "public nested password")
        return root, child

    def prepare(self, root, move=False, destination=None, group=None):
        destination = destination or self.destination
        transfer = EntryTransfer(self.source, destination, [], group or destination.snapshot.root, move, root)
        transfer.prepare()
        self.addCleanup(transfer.cancel)
        return transfer

    def test_recursive_copy_preserves_settings_history_attachments_and_remaps_all_colliding_icons(self):
        root, child = self.collection()
        image = self.directory / "Icon.png"
        image.write_bytes(png())
        icon = self.source.import_icon(image)
        self.source.save_group(root, "Collection", "Public group notes\nUnicode: ł", custom_icon=icon, tags="one;two",
                               searching=2, expires=True, expiry="2030-01-01T00:00:00Z")
        self.source.save_group(child, "Nested", "Public child notes", custom_icon=icon)
        self.source.save_autotype_settings(group=root, enabled=2, sequence="{TITLE}{ENTER}")
        self.source.save_keeshare_settings(root, mode=1, path=str(self.directory / "Public-share.kdbx"),
                                          keep_groups=True, password="public share password")
        self.source.save_entry(root, "Transfer", "public user", "", "", entry=self.original(), custom_icon=icon)
        self.source.set_attribute(self.original(), "Protected", "public protected value", True)
        self.source.set_attribute(self.original(), "Reference", "{REF:U@I:" + self.identifier.replace("-", "") + "}", False)
        attachment = self.directory / "Evidence.bin"
        attachment.write_bytes(bytes(range(256)) * 100)
        self.source.import_attachment(self.original(), attachment)
        before = self.source.path.read_bytes()
        # Existing destination entries/groups deliberately retain the source UUIDs, with different icon bytes.
        mirror = self.xml(self.source, "Mirror")
        mirror.find(".//Meta/CustomIcons/Icon/Data").text = base64.b64encode(png(3, 7)).decode()
        input_xml = self.directory / "Mirror.xml"
        mirror.write(input_xml, encoding="utf-8", xml_declaration=True)
        self.destination.lock()
        self.destination.import_database(self.directory / "Mirror.kdbx", input_xml, "xml", "different public master")
        existing_icon = self.destination.icon(custom_icon=icon)
        source_groups = {item.uuid for item in self.source.snapshot.groups}
        source_entries = {item.uuid for item in self.source.snapshot.entries}
        transfer = self.prepare(root)
        self.assertEqual(transfer.source_ticket["count"], 2)
        self.assertEqual(len(transfer.source_ticket["groups"]), 3)
        self.assertTrue(transfer.source_ticket["references"])
        outcome = self.deliver(transfer)
        self.assertFalse(outcome.message)
        self.assertTrue(outcome.destination_group)
        group = next(item for item in self.destination.snapshot.groups if item.uuid == outcome.destination_group)
        self.assertNotIn(group.uuid, source_groups)
        self.assertEqual((group.notes, group.tags, group.searching, group.expires, group.expiry),
                         ("Public group notes\nUnicode: ł", "one;two", 2, True, "2030-01-01T00:00:00Z"))
        children = [item for item in self.destination.snapshot.groups if item.parent == group.uuid]
        self.assertEqual({item.name for item in children}, {"Nested", "Empty"})
        self.assertTrue(all(item.uuid not in source_groups for item in children))
        self.assertEqual(self.destination.autotype_settings(group=group.uuid), self.source.autotype_settings(group=root))
        self.assertEqual(self.destination.keeshare_settings(group.uuid), self.source.keeshare_settings(root))
        copied = [item for item in self.destination.snapshot.entries if item.uuid in outcome.entries]
        self.assertEqual(len(copied), 2)
        self.assertTrue(all(item.uuid not in source_entries for item in copied))
        entry = next(item for item in copied if item.title == "Transfer")
        nested = next(item for item in copied if item.title == "Nested Entry")
        self.assertEqual(nested.group, next(item.uuid for item in children if item.name == "Nested"))
        self.assertEqual(self.destination.attribute(nested), "public nested password")
        self.assertEqual(self.destination.attribute_info(entry, "Protected"), {"value": "public protected value", "protected": True})
        self.assertEqual(len(self.destination.history(entry)), len(self.source.history(self.original())))
        self.assertNotEqual(group.custom_icon, icon)
        self.assertEqual(entry.custom_icon, group.custom_icon)
        self.assertEqual(self.destination.icon(custom_icon=icon), existing_icon)
        self.assertEqual(self.destination.icon(custom_icon=group.custom_icon), self.source.icon(custom_icon=icon))
        output = self.directory / "Copied.bin"
        self.destination.export_attachment(entry, attachment.name, output)
        self.assertEqual(output.read_bytes(), attachment.read_bytes())
        exported = self.xml(self.destination, "Transferred")
        encoded_entry = base64.b64encode(uuid.UUID(entry.uuid).bytes).decode()
        node = next(item for item in exported.findall(".//Entry") if item.findtext("UUID") == encoded_entry)
        expected_icon = base64.b64encode(uuid.UUID(group.custom_icon).bytes).decode()
        self.assertTrue(node.findall("History/Entry/CustomIconUUID"))
        self.assertTrue(all(item.text == expected_icon for item in node.findall("History/Entry/CustomIconUUID")))
        self.assertEqual(self.source.path.read_bytes(), before)
        self.destination.lock()
        self.destination.unlock(self.directory / "Mirror.kdbx", "different public master")
        self.assertEqual(len(self.destination.snapshot.entries), 4)

    def test_group_move_is_saved_with_all_children_before_original_is_removed(self):
        root, child = self.collection()
        transfer = self.prepare(root, move=True)
        original = self.source.transfer_request
        def verify(operation, **params):
            if operation == "finish":
                observer = Vault(ENGINE)
                try:
                    observer.unlock(self.destination.path, "different public master")
                    self.assertEqual(len(observer.snapshot.entries), 2)
                    self.assertEqual({item.name for item in observer.snapshot.groups if item.parent}, {"Collection", "Nested", "Empty"})
                    self.assertTrue(any(item.uuid == root for item in self.source.snapshot.groups))
                finally:
                    observer.lock()
            return original(operation, **params)
        with patch.object(self.source, "transfer_request", verify):
            outcome = self.deliver(transfer)
        self.assertTrue(outcome.moved)
        self.assertFalse(any(item.uuid in (root, child) for item in self.source.snapshot.groups))
        self.assertFalse(self.source.snapshot.entries)

    def test_empty_groups_copy_and_move_with_zero_entry_receipts(self):
        self.source.add_group(self.source.snapshot.root, "Empty")
        root = next(item.uuid for item in self.source.snapshot.groups if item.name == "Empty")
        self.assertFalse(self.deliver(self.prepare(root)).message)
        self.assertTrue(self.deliver(self.prepare(root, move=True)).moved)
        self.assertEqual(sum(item.name == "Empty" for item in self.destination.snapshot.groups), 2)
        self.assertFalse(self.destination.snapshot.entries)
        self.assertFalse(any(item.uuid == root for item in self.source.snapshot.groups))

    def test_local_group_copy_refreshes_all_ids_and_move_retains_all_ids(self):
        root, child = self.collection()
        old_entries = {item.uuid for item in self.source.snapshot.entries}
        outcome = self.prepare(root, destination=self.source).send()
        self.assertFalse(outcome.message)
        self.assertNotEqual(outcome.destination_group, root)
        self.assertTrue(set(outcome.entries).isdisjoint(old_entries))
        self.source.add_group(self.source.snapshot.root, "Destination")
        target = next(item.uuid for item in self.source.snapshot.groups if item.name == "Destination")
        outcome = self.prepare(root, move=True, destination=self.source, group=target).send()
        self.assertTrue(outcome.moved)
        self.assertEqual(outcome.destination_group, root)
        self.assertEqual(set(outcome.entries), old_entries)
        self.assertEqual(next(item.parent for item in self.source.snapshot.groups if item.uuid == root), target)
        self.assertEqual(next(item.parent for item in self.source.snapshot.groups if item.uuid == child), root)

    def test_root_recycled_and_recursive_destinations_are_rejected_without_writes(self):
        root, child = self.collection()
        before = self.source.path.read_bytes()
        with self.assertRaises(VaultError):
            self.prepare(self.source.snapshot.root)
        for move in (False, True):
            for target in (root, child):
                with self.subTest(move=move, target=target), self.assertRaises(VaultError):
                    self.prepare(root, move=move, destination=self.source, group=target).send()
        self.assertEqual(self.source.path.read_bytes(), before)
        self.source.recycle_group(root)
        before = self.source.path.read_bytes()
        with self.assertRaises(VaultError):
            self.prepare(root)
        self.assertEqual(self.source.path.read_bytes(), before)

    def test_mismatched_group_manifest_cannot_save_or_remove_anything(self):
        root, child = self.collection()
        transfer = EntryTransfer(self.source, self.destination, [], self.destination.snapshot.root, True, root)
        transfer.source_ticket = self.source.prepare_group_transfer(root, True)
        invalid = transfer.source_ticket | {"groups": [root]}
        transfer.destination_ticket = self.destination.listen_transfer(invalid, self.destination.snapshot.root)
        self.addCleanup(transfer.cancel)
        before = self.destination.path.read_bytes()
        with ThreadPoolExecutor(max_workers=1) as executor:
            receiver = executor.submit(transfer.receive)
            outcome = transfer.send()
            with self.assertRaises(VaultError):
                receiver.result(timeout=15)
        self.assertFalse(outcome.copied)
        self.assertEqual(self.destination.path.read_bytes(), before)
        self.assertTrue(any(item.uuid == root for item in self.source.snapshot.groups))

    def test_changed_child_retains_entire_source_group_after_saved_copy(self):
        root, child = self.collection()
        transfer = self.prepare(root, move=True)
        original = self.source.transfer_request
        def changed(operation, **params):
            if operation == "finish":
                entry = next(item for item in self.source.snapshot.entries if item.group == child)
                self.source.set_attribute(entry, "Edited meanwhile", "public value")
            return original(operation, **params)
        with patch.object(self.source, "transfer_request", changed):
            outcome = self.deliver(transfer)
        self.assertTrue(outcome.copied)
        self.assertFalse(outcome.moved)
        self.assertTrue(outcome.message)
        self.assertEqual(len(self.destination.snapshot.entries), 2)
        self.assertEqual(len(self.source.snapshot.entries), 2)
        self.assertTrue(any(item.uuid == root for item in self.source.snapshot.groups))


@unittest.skipUnless(ENGINE, "native engine required")
class BulkEntries(unittest.TestCase):
    setUp = fixtures.Transfers.setUp
    tearDown = fixtures.Transfers.tearDown
    original = fixtures.Transfers.original
    deliver = fixtures.Transfers.deliver

    def selected(self):
        for index in range(2):
            self.source.save_entry(self.source.snapshot.root, "Duplicate", str(index), "", "", "public password " + str(index))
        return list(self.source.snapshot.entries)

    def test_bulk_copy_duplicate_titles_preserves_every_selected_entry(self):
        entries = self.selected()
        transfer = EntryTransfer(self.source, self.destination, entries, self.destination.snapshot.root, False)
        transfer.prepare()
        self.addCleanup(transfer.cancel)
        outcome = self.deliver(transfer)
        self.assertFalse(outcome.message)
        self.assertEqual(len(outcome.entries), 3)
        self.assertTrue(set(outcome.entries).isdisjoint(item.uuid for item in entries))
        self.assertEqual({(item.title, item.username, self.destination.attribute(item)) for item in self.destination.snapshot.entries},
                         {(item.title, item.username, self.source.attribute(item)) for item in entries})

    def test_bulk_local_move_and_recycle_are_atomic_and_keep_ids(self):
        entries = self.selected()
        self.source.add_group(self.source.snapshot.root, "Target")
        target = next(item.uuid for item in self.source.snapshot.groups if item.name == "Target")
        transfer = EntryTransfer(self.source, self.source, entries, target, True)
        transfer.prepare()
        self.addCleanup(transfer.cancel)
        outcome = transfer.send()
        self.assertTrue(outcome.moved)
        self.assertEqual(set(outcome.entries), {item.uuid for item in entries})
        self.assertTrue(all(item.group == target for item in self.source.snapshot.entries))
        self.source.recycle_entries(self.source.snapshot.entries)
        self.assertTrue(all(item.recycled for item in self.source.snapshot.entries))
        self.source.lock()
        self.source.unlock(self.directory / "Source.kdbx", "public fixture master")
        self.assertEqual({item.uuid for item in self.source.snapshot.entries}, {item.uuid for item in entries})

    def test_bulk_recycle_rejects_missing_duplicate_foreign_and_disabled_before_writing(self):
        entries = self.selected()
        for identifiers in ([entries[0].uuid, str(uuid.uuid4())], [entries[0].uuid, entries[0].uuid], []):
            before = self.source.path.read_bytes()
            with self.subTest(ids=identifiers), self.assertRaises(VaultError):
                self.source._rpc("entries.recycle", entries=identifiers)
            self.assertEqual(self.source.path.read_bytes(), before)
            self.assertFalse(any(item.recycled for item in self.source.snapshot.entries))
        self.destination.save_entry(self.destination.snapshot.root, "Foreign", "", "", "", "public foreign password")
        with self.assertRaises(VaultError):
            self.source.recycle_entries([entries[0], self.destination.snapshot.entries[0]])
        self.source.save_settings(recycle_bin=False)
        before = self.source.path.read_bytes()
        with self.assertRaises(VaultError):
            self.source.recycle_entries(self.source.snapshot.entries)
        self.assertEqual(self.source.path.read_bytes(), before)

    def test_bulk_source_approval_rejects_duplicate_ids_and_includes_exact_manifest(self):
        entries = self.selected()
        with self.assertRaises(VaultError):
            self.source.prepare_transfer([entries[0], entries[0]])
        ticket = self.source.prepare_transfer(iter(entries))
        self.assertEqual(set(ticket["ids"]), {item.uuid for item in entries})
        self.assertEqual(ticket["count"], 3)
        self.assertEqual(ticket["groups"], [])
        self.source.transfer_request("cancel", token=ticket["token"])

    def test_review_preview_is_bounded_but_every_selected_entry_is_transferred(self):
        for index in range(12):
            self.source.save_entry(self.source.snapshot.root, "Bulk " + str(index), str(index), "", "", "public password " + str(index))
        self.source.set_attribute(self.source.snapshot.entries[-1], "Reference", "{REF:U@I:" + self.identifier.replace("-", "") + "}", False)
        transfer = EntryTransfer(self.source, self.destination, self.source.snapshot.entries, self.destination.snapshot.root, False)
        transfer.prepare()
        self.addCleanup(transfer.cancel)
        self.assertEqual(transfer.source_ticket["count"], 13)
        self.assertEqual(len(transfer.source_ticket["entries"]), 10)
        self.assertEqual(len(transfer.source_ticket["ids"]), 13)
        self.assertTrue(transfer.source_ticket["references"])
        self.assertFalse(any(item["references"] for item in transfer.source_ticket["entries"]))
        outcome = self.deliver(transfer)
        self.assertFalse(outcome.message)
        self.assertEqual(len(self.destination.snapshot.entries), 13)
        self.assertEqual({item.title for item in self.destination.snapshot.entries}, {item.title for item in self.source.snapshot.entries})

    def test_bulk_recycle_save_failure_rolls_back_every_entry(self):
        entries = self.selected()
        before = self.source.path.read_bytes()
        try:
            self.directory.chmod(0o500)
            with self.assertRaises(VaultError):
                self.source.recycle_entries(entries)
        finally:
            self.directory.chmod(0o700)
        self.assertEqual(self.source.path.read_bytes(), before)
        self.source._snapshot_call("snapshot")
        self.assertFalse(any(item.recycled for item in self.source.snapshot.entries))
        self.assertEqual({item.uuid for item in self.source.snapshot.entries}, {item.uuid for item in entries})
