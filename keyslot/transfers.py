"""Coordinate peer-authenticated native transfers; Python carries metadata and control tokens only."""
from concurrent.futures import Future, TimeoutError
from dataclasses import dataclass, field
import socket
import struct
import os
import time
from .backend import VaultError


@dataclass
class Outcome:
    copied: bool
    moved: bool
    entries: list[str] = field(default_factory=list)
    message: str = ""
    uncertain: bool = False
    destination_group: str = ""


class EntryTransfer:
    def __init__(self, source, destination, entries, group, move, source_group="", position=-1):
        self.source, self.destination = source, destination
        self.entries, self.group, self.move = list(entries), group, move
        self.source_group = source_group
        self.position = position
        self.contexts = [(vault, vault.identity, vault.generation) for vault in (source, destination)]
        self.source_ticket = self.destination_ticket = None
        self.received = Future()
        self.cancelled = False
        self.deadline = time.monotonic() + 110

    def valid(self):
        if self.cancelled:
            raise VaultError("The entry transfer was cancelled.")
        for vault, identity, generation in self.contexts:
            if not vault.unlocked or vault.identity is not identity or vault.generation != generation:
                raise VaultError("A transfer vault was locked or closed.")

    def prepare(self):
        self.valid()
        self.source_ticket = (self.source.prepare_group_transfer(self.source_group, self.move) if self.source_group
                              else self.source.prepare_transfer(self.entries, self.move))
        try:
            self.valid()
            if self.source is not self.destination:
                self.destination_ticket = self.destination.listen_transfer(self.source_ticket, self.group, self.position)
            self.valid()
            return self.source_ticket
        except Exception:
            self.cancel()
            raise

    def cancel_endpoint(self):
        ticket = self.destination_ticket
        if not ticket:
            return
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                channel.settimeout(.5)
                channel.connect(ticket["socket"])
                peer = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                if peer[0] != ticket["pid"] or peer[1] != os.getuid():
                    return
                channel.sendall(b"KSXCAN01" + ticket["token"].encode("ascii"))
        except (OSError, ValueError):
            pass

    def cancel(self):
        self.cancelled = True
        self.cancel_endpoint()
        for vault, identity, generation in self.contexts:
            if vault.identity is not identity or vault.generation != generation or not vault.unlocked:
                continue
            ticket = self.source_ticket if vault is self.source else self.destination_ticket
            if ticket:
                try:
                    vault.transfer_request("cancel", token=ticket["token"])
                except (VaultError, OSError):
                    pass

    def receive(self):
        try:
            self.valid()
            value = self.destination.transfer_request("receive", token=self.destination_ticket["token"])
            self.received.set_result(value)
            return value
        except Exception as exc:
            self.received.set_exception(exc)
            raise

    def send(self):
        try:
            return self._send()
        finally:
            # Release a receiver waiting after a preflight failure and discard the native sealed capsule.
            self.cancel()

    def _send(self):
        self.valid()
        if time.monotonic() > self.deadline:
            self.cancel()
            raise VaultError("The entry transfer approval expired. Choose the destination again.")
        if self.source is self.destination:
            value = self.source.transfer_request("local", token=self.source_ticket["token"], group=self.group, position=self.position)
            return Outcome(True, value["moved"], value["entries"], destination_group=value.get("root_group", ""))
        error = None
        try:
            sent = self.source.transfer_request("send", token=self.source_ticket["token"], destination=self.destination_ticket)
        except (VaultError, OSError) as exc:
            error = exc
            sent = None
            self.cancel_endpoint()
        try:
            deadline = time.monotonic() + 365
            while True:
                try:
                    received = self.received.result(timeout=.2)
                    break
                except TimeoutError:
                    self.valid()
                    if time.monotonic() > deadline:
                        raise VaultError("The destination reply timed out.")
        except Exception as exc:
            # No source deletion has been requested. A lost destination reply can still hide a saved copy.
            return Outcome(bool(sent), False, message=str(error or exc), uncertain=True)
        if not received.get("saved"):
            return Outcome(False, False, message="The destination did not confirm a saved copy.")
        if error or not received.get("acknowledged"):
            return Outcome(True, False, received["entries"], str(error or "The source did not receive the save acknowledgement."),
                           destination_group=received.get("root_group", ""))
        try:
            self.valid()
            if self.move:
                value = self.source.transfer_request("finish", token=self.source_ticket["token"])
                return Outcome(True, value["moved"], received["entries"], destination_group=received.get("root_group", ""))
            self.source.transfer_request("cancel", token=self.source_ticket["token"])
            return Outcome(True, False, received["entries"], destination_group=received.get("root_group", ""))
        except (VaultError, OSError) as exc:
            # Source cleanup may have committed before its reply was lost; never claim it was retained.
            return Outcome(True, False, received["entries"], str(exc), uncertain=self.move,
                           destination_group=received.get("root_group", ""))
