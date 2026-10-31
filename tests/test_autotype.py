"""Key release guarantees when focus, cancellation or portal replies interrupt typing."""
import unittest
from unittest.mock import Mock
from gi.repository import GLib
from keyslot.autotype import PortalKeyboard
from keyslot.backend import VaultError


class PortalKeyRelease(unittest.TestCase):
    def keyboard(self):
        keyboard = object.__new__(PortalKeyboard)
        keyboard.pressed = []
        keyboard._notify = Mock()
        return keyboard

    def test_modifiers_and_key_are_released_in_reverse_order(self):
        keyboard = self.keyboard()
        keyboard.key(ord("a"), 0x06000000, lambda: None)
        self.assertEqual([call.args for call in keyboard._notify.call_args_list],
            [(0xFFE1, True), (0xFFE3, True), (ord("a"), True), (ord("a"), False), (0xFFE3, False), (0xFFE1, False)])
        self.assertFalse(keyboard.pressed)

    def test_focus_change_after_modifier_press_releases_it_without_typing(self):
        keyboard = self.keyboard()
        guard = Mock(side_effect=[None, None, VaultError("focus changed")])
        with self.assertRaises(VaultError):
            keyboard.key(ord("a"), 0x02000000, guard)
        self.assertEqual([call.args for call in keyboard._notify.call_args_list], [(0xFFE1, True), (0xFFE1, False)])
        self.assertFalse(keyboard.pressed)

    def test_uncertain_press_reply_still_attempts_release(self):
        keyboard = self.keyboard()
        keyboard._notify.side_effect = [GLib.Error("fixture timeout after possible press"), None]
        with self.assertRaises(GLib.Error):
            keyboard.key(ord("a"), 0, lambda: None)
        self.assertEqual([call.args for call in keyboard._notify.call_args_list], [(ord("a"), True), (ord("a"), False)])
        self.assertFalse(keyboard.pressed)

    def test_cancelled_sequence_never_presses_any_key(self):
        keyboard = self.keyboard()
        with self.assertRaises(VaultError):
            keyboard.key(ord("a"), 0, Mock(side_effect=VaultError("locked")))
        keyboard._notify.assert_not_called()
