"""Real native helper transfers: preservation, saved-copy ordering and partial failure."""
from concurrent.futures import ThreadPoolExecutor
import base64
import os
from pathlib import Path
import shutil
import socket
import tempfile
import unittest
import uuid
from unittest.mock import patch
import xml.etree.ElementTree as ET

from keyslot.backend import VaultError
from keyslot.core_backend import Vault
from keyslot.transfers import EntryTransfer
from test_appearance import png

ENGINE = os.environ.get("KEYSLOT_ENGINE") or shutil.which("keyslot-engine")


@unittest.skipUnless(ENGINE, "native engine required")
class Transfers(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="keyslot-transfers-")
        self.directory = Path(self.temporary.name)
        self.source, self.destination = Vault(ENGINE), Vault(ENGINE)
        self.source.create(self.directory / "Source.kdbx", "public fixture master")
        self.destination.create(self.directory / "Destination.kdbx", "different public master")
        self.source.save_entry(self.source.snapshot.root, "Transfer", "public user", "https://example.org", "public notes", "public password")
        self.identifier = self.source.snapshot.entries[0].uuid

    def tearDown(self):
        self.source.lock()
        self.destination.lock()
        self.temporary.cleanup()

    def original(self):
        return next(entry for entry in self.source.snapshot.entries if entry.uuid == self.identifier)

    def prepare(self, move=False, destination=None, group=None):
        destination = destination or self.destination
        transfer = EntryTransfer(self.source, destination, [self.original()], group or destination.snapshot.root, move)
        transfer.prepare()
        self.addCleanup(transfer.cancel)
        return transfer

    def deliver(self, transfer):
        with ThreadPoolExecutor(max_workers=1) as executor:
            received = executor.submit(transfer.receive)
            outcome = transfer.send()
            received.result(timeout=15)
            return outcome

    def xml(self, vault, label):
        path = self.directory / (label + ".xml")
        vault.export_database(path)
        return ET.parse(path)

    def test_copy_preserves_protected_fields_history_attachment_and_advanced_metadata(self):
        image = self.directory / "Icon.png"
        image.write_bytes(png())
        icon = self.source.import_icon(image)
        self.source.set_attribute(self.original(), "Sensitive", "public protected value", True)
        self.source.set_totp(self.original(), "otpauth://totp/Fixture?secret=JBSWY3DPEHPK3PXP&issuer=Fixture")
        attachment = self.directory / "Evidence.bin"
        attachment.write_bytes(bytes(range(256)) * 1000)
        self.source.import_attachment(self.original(), attachment)
        self.source.save_entry(self.original().group, "Transfer", "public user", "https://example.org", "public notes", entry=self.original(),
                               custom_icon=icon, foreground="#112233", background="#556677", tags="one;two",
                               expires=True, expiry="2030-01-01T00:00:00Z", override_url="https://example.org/{USERNAME}", exclude_reports=True)
        self.source.save_autotype_settings(entry=self.original(), enabled=True, sequence="{USERNAME}{TAB}{PASSWORD}", associations=[])
        source_before = self.source.path.read_bytes()
        transfer = self.prepare()
        # Only opaque control tokens/public review metadata cross the Python pipe boundary.
        self.assertNotIn("public password", repr(transfer.source_ticket) + repr(transfer.destination_ticket))
        self.assertEqual(Path(transfer.destination_ticket["socket"]).stat().st_mode & 0o077, 0)
        outcome = self.deliver(transfer)
        self.assertTrue(outcome.copied)
        self.assertFalse(outcome.moved)
        self.assertFalse(outcome.message)
        copied = self.destination.snapshot.entries[0]
        self.assertNotEqual(copied.uuid, self.identifier)
        self.assertEqual(self.destination.attribute(copied), "public password")
        self.assertEqual(self.destination.attribute(copied, "Sensitive"), "public protected value")
        self.assertEqual(self.destination.totp_settings(copied), self.source.totp_settings(self.original()))
        self.assertEqual(self.destination.autotype_settings(entry=copied), self.source.autotype_settings(entry=self.original()))
        self.assertEqual((copied.foreground, copied.background, copied.tags, copied.expiry, copied.override_url, copied.exclude_reports),
                         (self.original().foreground, self.original().background, self.original().tags, self.original().expiry, self.original().override_url, True))
        self.assertEqual(self.destination.icon(custom_icon=copied.custom_icon), self.source.icon(custom_icon=icon))
        self.assertEqual(len(self.destination.history(copied)), len(self.source.history(self.original())))
        output = self.directory / "Copied.bin"
        self.destination.export_attachment(copied, attachment.name, output)
        self.assertEqual(output.read_bytes(), attachment.read_bytes())
        xml = self.xml(self.destination, "Copied")
        protected = next(node for node in xml.findall(".//Root/Group/Entry/String") if node.findtext("Key") == "Sensitive")
        self.assertEqual(protected.find("Value").get("ProtectInMemory"), "True")
        self.assertEqual(self.source.path.read_bytes(), source_before)
        self.assertFalse(Path(transfer.destination_ticket["socket"]).exists())
        self.destination.lock()
        self.destination.unlock(self.directory / "Destination.kdbx", "different public master")
        self.assertEqual(self.destination.attribute(self.destination.snapshot.entries[0]), "public password")

    def test_move_saves_destination_before_permanently_removing_original(self):
        transfer = self.prepare(move=True)
        finish = self.source.transfer_request
        def checked(operation, **params):
            if operation == "finish":
                observer = Vault(ENGINE)
                try:
                    observer.unlock(self.destination.path, "different public master")
                    self.assertEqual(observer.attribute(observer.snapshot.entries[0]), "public password")
                    self.assertEqual(self.original().uuid, self.identifier)
                finally:
                    observer.lock()
            return finish(operation, **params)
        with patch.object(self.source, "transfer_request", checked):
            outcome = self.deliver(transfer)
        self.assertTrue(outcome.moved)
        self.assertFalse(any(entry.uuid == self.identifier for entry in self.source.snapshot.entries))
        self.assertFalse(outcome.message)
        with self.assertRaises(VaultError):
            finish("finish", token=transfer.source_ticket["token"])

    def test_local_copy_gets_new_uuid_and_move_keeps_uuid(self):
        copy = self.prepare(destination=self.source)
        outcome = copy.send()
        self.assertFalse(outcome.moved)
        self.assertEqual(len(self.source.snapshot.entries), 2)
        self.assertNotEqual(outcome.entries[0], self.identifier)
        self.source.add_group(self.source.snapshot.root, "Target")
        group = next(group.uuid for group in self.source.snapshot.groups if group.name == "Target")
        move = self.prepare(move=True, destination=self.source, group=group)
        self.assertTrue(move.send().moved)
        self.assertEqual(self.original().group, group)

    def test_source_and_destination_changes_revoke_pending_approval(self):
        transfer = self.prepare()
        self.source.set_attribute(self.original(), "Changed", "public value")
        with self.assertRaises(VaultError):
            self.source.transfer_request("send", token=transfer.source_ticket["token"], destination=transfer.destination_ticket)
        transfer.cancel()
        transfer = self.prepare()
        self.destination.add_group(self.destination.snapshot.root, "Changed")
        with self.assertRaises(VaultError):
            transfer.receive()
        self.assertFalse(self.destination.snapshot.entries)
        self.assertEqual(self.original().uuid, self.identifier)

    def test_same_file_and_hardlink_are_rejected(self):
        self.destination.lock()
        alias = self.directory / "Alias.kdbx"
        os.link(self.source.path, alias)
        self.destination.unlock(alias, "public fixture master")
        with self.assertRaises(VaultError):
            self.prepare(move=True)
        self.assertEqual(self.original().uuid, self.identifier)

    def test_no_source_removal_without_acknowledgement_or_after_destination_change(self):
        transfer = self.prepare(move=True)
        with self.assertRaises(VaultError):
            self.source.transfer_request("finish", token=transfer.source_ticket["token"])
        transfer.cancel()
        transfer = self.prepare(move=True)
        with ThreadPoolExecutor(max_workers=1) as executor:
            received = executor.submit(transfer.receive)
            self.source.transfer_request("send", token=transfer.source_ticket["token"], destination=transfer.destination_ticket)
            received.result(timeout=15)
        self.destination.add_group(self.destination.snapshot.root, "Another update")
        with self.assertRaises(VaultError):
            self.source.transfer_request("finish", token=transfer.source_ticket["token"])
        self.assertEqual(self.original().uuid, self.identifier)
        self.assertEqual(len(self.destination.snapshot.entries), 1)

    def test_cancellation_and_parent_impostor_cannot_import_entries(self):
        transfer = self.prepare(move=True)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.connect(transfer.destination_ticket["socket"])
            channel.sendall(b"KSXFER01" + transfer.destination_ticket["token"].encode("ascii"))
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(transfer.receive)
            transfer.cancel_endpoint()
            with self.assertRaises(VaultError):
                future.result(timeout=10)
        self.assertFalse(self.destination.snapshot.entries)
        self.assertEqual(self.original().uuid, self.identifier)
        transfer.cancel()
        with self.assertRaises(VaultError):
            self.source.transfer_request("send", token=transfer.source_ticket["token"], destination=transfer.destination_ticket)

    def test_lock_discards_approval_without_restarting_helper(self):
        transfer = self.prepare(move=True)
        process = self.source._process
        self.source.lock()
        with self.assertRaises(VaultError):
            transfer.send()
        self.assertIsNone(self.source._process)
        self.assertIsNotNone(process.poll())
        self.assertFalse(self.destination.snapshot.entries)

    def test_saved_destination_with_failed_source_cleanup_is_explicit_and_original_survives(self):
        transfer = self.prepare(move=True)
        original = self.source.transfer_request
        def changed(operation, **params):
            if operation == "finish":
                self.source.set_attribute(self.original(), "Edited meanwhile", "public value")
            return original(operation, **params)
        with patch.object(self.source, "transfer_request", changed):
            outcome = self.deliver(transfer)
        self.assertTrue(outcome.copied)
        self.assertFalse(outcome.moved)
        self.assertTrue(outcome.message)
        self.assertEqual(self.original().uuid, self.identifier)
        self.assertEqual(self.destination.attribute(self.destination.snapshot.entries[0]), "public password")

    def test_icon_uuid_collision_and_existing_entry_uuid_do_not_overwrite_destination(self):
        image = self.directory / "Icon.png"
        image.write_bytes(png())
        icon = self.source.import_icon(image)
        self.source.save_entry(self.original().group, "Transfer", "public user", "https://example.org", "", entry=self.original(), custom_icon=icon)
        self.source.save_entry(self.original().group, "Transfer", "public user", "https://example.org", "history with icon", entry=self.original())
        xml = self.xml(self.source, "Collision")
        # Deliberately retain both UUIDs while assigning a different valid icon image in the other vault.
        xml.find(".//Meta/CustomIcons/Icon/Data").text = base64.b64encode(png(3, 7)).decode()
        collision = self.directory / "Collision.xml"
        xml.write(collision, encoding="utf-8", xml_declaration=True)
        self.destination.lock()
        self.destination.import_database(self.directory / "Collision.kdbx", collision, "xml", "different public master")
        existing_icon = self.destination.icon(custom_icon=icon)
        outcome = self.deliver(self.prepare())
        self.assertFalse(outcome.message)
        self.assertEqual(len(self.destination.snapshot.entries), 2)
        original = next(entry for entry in self.destination.snapshot.entries if entry.uuid == self.identifier)
        copied = next(entry for entry in self.destination.snapshot.entries if entry.uuid != self.identifier)
        self.assertEqual(original.custom_icon, icon)
        self.assertNotEqual(copied.custom_icon, icon)
        self.assertEqual(self.destination.icon(custom_icon=icon), existing_icon)
        self.assertEqual(self.destination.icon(custom_icon=copied.custom_icon), self.source.icon(custom_icon=icon))
        xml = self.xml(self.destination, "Remapped")
        copied_uuid = base64.b64encode(uuid.UUID(copied.uuid).bytes).decode()
        node = next(entry for entry in xml.findall(".//Root/Group/Entry") if entry.findtext("UUID") == copied_uuid)
        mapped = base64.b64encode(uuid.UUID(copied.custom_icon).bytes).decode()
        self.assertTrue(node.findall("History/Entry/CustomIconUUID"))
        self.assertTrue(all(item.text == mapped for item in node.findall("History/Entry/CustomIconUUID")))

    def test_failed_destination_save_retains_original_and_no_destination_copy(self):
        transfer = self.prepare(move=True)
        original = self.source.transfer_request
        def readonly(operation, **params):
            if operation == "send":
                self.directory.chmod(0o500)
            return original(operation, **params)
        try:
            with ThreadPoolExecutor(max_workers=1) as executor, patch.object(self.source, "transfer_request", readonly):
                receiver = executor.submit(transfer.receive)
                outcome = transfer.send()
                with self.assertRaises(VaultError):
                    receiver.result(timeout=15)
        finally:
            self.directory.chmod(0o700)
        self.assertFalse(outcome.copied)
        self.assertTrue(outcome.message)
        self.assertFalse(self.destination.snapshot.entries)
        self.assertEqual(self.original().uuid, self.identifier)

    def test_lost_source_ack_reply_never_removes_original(self):
        transfer = self.prepare(move=True)
        original = self.source.transfer_request
        def lost(operation, **params):
            value = original(operation, **params)
            if operation == "send":
                raise VaultError("Public fixture: acknowledgement reply lost")
            return value
        with patch.object(self.source, "transfer_request", lost):
            outcome = self.deliver(transfer)
        self.assertTrue(outcome.copied)
        self.assertFalse(outcome.moved)
        self.assertTrue(outcome.message)
        self.assertEqual(self.original().uuid, self.identifier)

    def test_lost_finish_reply_reports_uncertainty_instead_of_claiming_original_kept(self):
        transfer = self.prepare(move=True)
        original = self.source.transfer_request
        def lost(operation, **params):
            value = original(operation, **params)
            if operation == "finish":
                raise VaultError("Public fixture: cleanup committed but reply lost")
            return value
        with patch.object(self.source, "transfer_request", lost):
            outcome = self.deliver(transfer)
        self.assertTrue(outcome.copied)
        self.assertTrue(outcome.uncertain)
        self.assertFalse(outcome.moved)
        self.assertTrue(outcome.message)
        self.assertFalse(self.source.snapshot.entries)
        self.assertEqual(self.destination.attribute(self.destination.snapshot.entries[0]), "public password")

    def test_streamed_attachment_exceeds_private_json_reply_limit(self):
        attachment = self.directory / "Large.bin"
        # Compression cannot hide a transfer that accidentally routes the attachment through JSON.
        with attachment.open("wb") as stream:
            for _ in range(65):
                stream.write(os.urandom(1024 * 1024))
        self.source.import_attachment(self.original(), attachment)
        outcome = self.deliver(self.prepare())
        self.assertFalse(outcome.message)
        output = self.directory / "Large-copy.bin"
        self.destination.export_attachment(self.destination.snapshot.entries[0], attachment.name, output)
        import hashlib
        with attachment.open("rb") as a, output.open("rb") as b:
            self.assertEqual(hashlib.file_digest(a, "sha256").digest(), hashlib.file_digest(b, "sha256").digest())
