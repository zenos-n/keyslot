# Saving, expiry and field-action preferences

These controls map the Linux KeePassXC2.8 defaults into GNOME preferences.
The language controls and English/Polish/Romanian text are documented in
[Localization](localization.md).

## Non-data changes

Preferences → Saving adds **Save Non-Data Changes Automatically**, mapping
`AutoSaveNonDataChanges` (default true). Enabling Save Changes Automatically
also enables the close/lock and non-data options, as stock preferences do.
The latter controls become editable when ordinary autosave is disabled.

Group expansion/collapse uses the native Group::setExpanded non-data signal and
persists the stock KDBX IsExpanded state. The sidebar respects collapsed parents;
the disclosure button can expand them again. A pure non-data transaction is
classified using Database::hasNonDataChanges/isModified independently of earlier
checkpoints. A previous unsaved data change prevents that classification from
silently becoming non-data-only. Any later data change also clears it.

With non-data autosave enabled, pure view/order changes are held in an encrypted
checkpoint and saved on close/lock without a prompt, even if ordinary close-save
is disabled. With the option disabled they use normal autosave/manual-save and
close-confirmation behavior. They do not alter entry history or expose secrets.
Existing data changes still follow the data-save policy; this option cannot
silently approve their save. The UI does not show a dirty marker for non-data
changes configured to save automatically.

The optional private recovery-record boolean is checked under the existing
owner/journal locks before conditional close-time commit. Older records without
it are treated as data-bearing. Native capability checks prevent a mismatched
helper from silently ignoring this behavior. Live helpers refresh the atomic
committed saving-policy tuple before subsequent operations; newly opened windows
and close-time recovery use the same current preference. Backups and encrypted
rollback/recovery remain independent.

Keyslot retains stricter error handling than stock's best-effort non-data save:
failed writes retain encrypted recovery and report the error rather than silently
losing the state. Security locks still clear the unlocked helper immediately.

## Expiry after unlock

Preferences → Entry Behavior adds **Show Expiring Entries After Unlock** and
**Expiry Warning Look-Ahead (Days)**, mapping
`GUI/ShowExpiredEntriesOnDatabaseUnlock` (default true) and
`GUI/ShowExpiredEntriesOnDatabaseUnlockOffsetDays` (default 3, range 0–90).
Zero shows expired entries only.

The first ordinary unlock of a path in a vault window starts the existing native
`is:expired-N` search. It is a transient all-vault query: no saved search scope is
changed, recycled entries stay excluded and native search rules determine expiry.
The banner describes the look-ahead, and normal entry actions remain available.
Later relocks/unlocks preserve the existing view. Auto-Type resumption is not
interrupted by expiry search; the first later ordinary unlock can show it.
Background login unlock updates only the hidden view and never presents a window.
Search workers remain generation/query guarded and do not extend inactivity.

## Double-click field actions

Preferences → Entry Behavior maps `Security/EnableCopyOnDoubleClick` (default
false) and `URLDoubleClickAction` (0 Open, 1 Copy, 2 Edit; default Open).
Double-click the body of Username or Password to copy the native resolved field
when enabled, or edit the entry when disabled. Double-click Website to perform
the selected action. The existing buttons continue to provide explicit keyboard-
accessible Copy/Open actions. TOTP's existing reveal/copy controls are unchanged.

Gestures exclude suffix buttons/inputs, require the same live selected entry,
snapshot/epoch and unlocked active session, and use existing native field reads,
owned clipboard expiry/minimize policy and URL approval/launch checks. No password
is read merely to display a masked row or register the gesture. Commands still
require their existing approval; selecting Open does not bypass it.

Validation is ordinary native/runtime/Python/gettext compilation and static
source/artifact review only. No tests, harnesses or vault/GTK/login/clipboard/
keyboard behavior probes were added or run. Manual acceptance remains for
non-data/data mixtures, policy changes, lock/close/recovery/conflicts/failures,
expiry timing/first-unlock/background operation, field gestures/buttons/keyboard,
profiles, en/pl/ro wording/layout and accessibility. This does not establish
production readiness or full replacement parity.

Sources: KeePassXC Team GPL2-or-3, independent integration GPL3-only.

- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Group.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/DatabaseWidget.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/ApplicationSettingsWidget.cpp
