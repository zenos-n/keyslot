# Remembered Auto-Type selection

Preferences → Auto-Type → **Remember Last Typed Entry (Seconds)** accepts0–60,
with15 seconds as the default. Zero disables remembering. Explicit INI profiles
use KeePassXC's `GlobalAutoTypeRetypeTime` key; private profiles save the flag
with their existing Auto-Type preferences. Older six-field private settings gain
the new default without losing their matching, locking or delay choices.

After a successful Auto-Type action, a subsequent selector can preselect the
same entry and sequence if they are among its fresh choices. If its old sequence
is absent, the entry’s first available sequence is selected, following upstream. A click selects a
row; double-click, Type or Enter approves it. The Type dropdown also offers
[Field Actions](autotype-fields.md) and explicit Copy Field actions. PICKCHARS and destination checks still follow where
needed. See [Confirmation Preferences](autotype-confirmation.md) for automatic
single-match and selected-entry behavior. A nonempty search with no remembered match selects its
first result. Enter refreshes an outstanding delayed search before activating
anything. Standard list selection supports keyboard navigation.

The application retains one short-lived record: entry UUID, sequence digest,
weak session/snapshot references, epoch/identity/generation and monotonic time.
It does not cache resolved passwords, TOTP values, character picks, key events,
destination tokens or a typing approval. Fresh native search results supply each
actual default or association sequence for digest comparison; direct matches use
their fresh sequence as well. The cache does not keep a plaintext sequence or an
entry object alive. No secure-zero guarantee is made for transient Python/GTK strings.

Expiry, owner lock/close/reload, a changed snapshot/generation, failed typing,
Auto-Type preference changes and shutdown discard or invalidate the record.
Relock-after-Auto-Type locks only the vault opened for that invocation and does
not retain its choice. Already-unlocked vaults may retain selection memory even
when this preference is on; see [Unlock for Auto-Type](autotype-unlock.md).
Canceling a selector or confirmation marks it closed before clearing/animation;
late search callbacks cannot refill it. Prepared responses are checked against
the captured owner/session/snapshot before opening confirmation. Native tokens
and focus leases retain their existing expiry and validation.

This adds the selection-memory workflow, not a complete Auto-Type parity claim.
[Chooser Search](autotype-search.md) now preserves native query syntax and association
variants. [Locked-vault resumption](autotype-unlock.md) and immediate temporary-vault
relocking and a locked-vault chooser are implemented. [Sort controls](autotype-search.md)
and [portal permission lifetimes](autotype-permissions.md) are implemented;
protected/reference display ordering and broader platform behavior remain gaps.
The optional [portal Copy](autotype-clipboard.md) path now implements the stock
clipboard setting; its ownership/FD/lifecycle acceptance remains manual.
Confirmation preferences follow the linked policy.

References: KeePassXC Team/Felix Geyer GPL2-or-3 source; this independent adapter
is GPL3-only.

- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/autotype/AutoType.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/autotype/AutoTypeSelectDialog.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/ApplicationSettingsWidgetGeneral.ui

Runtime/Python compilation only. No tests/harnesses or automated GUI, typing,
portal, keyboard, config or vault behavior runs were added or performed. Manual
acceptance remains for0/default/max settings, old/private/INI profiles, direct
versus default/custom sequences, search/Enter timing and keyboard accessibility,
multiple vaults, success/failure/cancel/lock/reload/close/expiry and X11/Wayland
destination/focus behavior. This does not establish production readiness.

Desktop shortcut aliases/disable/reset are now editable in the [GNOME companion](autotype-shortcuts.md); recorder, focus and platform acceptance remains manual.
