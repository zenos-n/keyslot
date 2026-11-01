# Remembered Auto-Type selection

Preferences → Auto-Type → **Remember Last Typed Entry (Seconds)** accepts0–60,
with15 seconds as the default. Zero disables remembering. Explicit INI profiles
use KeePassXC's `GlobalAutoTypeRetypeTime` key; private profiles save the flag
with their existing Auto-Type preferences. Older six-field private settings gain
the new default without losing their matching, locking or delay choices.

After a successful Auto-Type action, a subsequent selector can preselect the
same entry and sequence if they are among its fresh choices. A click selects a
row; double-click, Type or Enter approves it. The Type dropdown also offers
[Field Actions](autotype-fields.md) and explicit Copy Field actions. PICKCHARS and destination checks still follow where
needed. See [Confirmation Preferences](autotype-confirmation.md) for automatic
single-match and selected-entry behavior. A nonempty search with no remembered match selects its
first result. Enter refreshes an outstanding delayed search before activating
anything. Standard list selection supports keyboard navigation.

The application retains one short-lived record: entry UUID, sequence digest,
weak session/snapshot references, epoch/identity/generation and monotonic time.
It does not cache resolved passwords, TOTP values, character picks, key events,
destination tokens or a typing approval. Fresh native metadata supplies the
remembered entry's current default sequence for comparison with search/default
choices; only its digest crosses back into that comparison. Direct matches use
their fresh sequence. The cache does not keep a plaintext sequence or an entry
object alive. No secure-zero guarantee is made for transient Python/GTK strings.

Expiry, owner lock/close/reload, a changed snapshot/generation, failed typing,
Auto-Type preference changes and shutdown discard or invalidate the record.
Relock-after-Auto-Type still locks immediately and does not retain a choice.
Canceling a selector or confirmation marks it closed before clearing/animation;
late search callbacks cannot refill it. Prepared responses are checked against
the captured owner/session/snapshot before opening confirmation. Native tokens
and focus leases retain their existing expiry and validation.

This adds the selection-memory workflow, not a complete Auto-Type parity claim.
Association variants in general search, temporary unlock/relock timing, portal
persistence/clipboard typing and broader platform behavior remain separate gaps.
Confirmation preferences now follow the linked policy; immediate relocking is
unchanged.

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
