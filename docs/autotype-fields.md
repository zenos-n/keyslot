# Auto-Type individual fields

The entry's Auto-Type row now has a field menu. The same choices are available
from the Auto-Type selector's Type dropdown:

| Action | Native sequence |
|---|---|
| Username | `{USERNAME}` |
| Username, Then Enter | `{USERNAME}{ENTER}` |
| Password | `{PASSWORD}` |
| Password, Then Enter | `{PASSWORD}{ENTER}` |
| One-Time Password | `{TOTP}` |
| Website | `{URL}` |
| Website, Then Enter | `{URL}{ENTER}` |

These are fixed templates. The existing native parser resolves fields,
references and current TOTP after approval/portal permission; field values are
not fetched into GTK for typing. Native `autotype.fields` returns only five
booleans: eligibility and raw username/password/URL presence plus valid TOTP
setup. This handles protected fields without treating their masked preview as
empty. Presence follows upstream raw-field semantics; references are resolved
later. Native prepare validates the field name, exact template and current
presence again, before a field-only Enter variant can be executed. Existing
eligibility, snapshot/revision, one-use approval and focus checks remain.

The selector also offers Copy Username, Password, One-Time Password and Website.
Values are fetched only for that explicit Copy operation, using existing native
reference/TOTP handling. Clipboard ownership belongs to the selected vault even
when another vault hosts the selector. Existing timeout, Linux secret hint,
primary-selection support and owner-lock clearing remain; the presenting window's
copy/hide policy is applied. Copy keeps the selector open while the temporary
unlock flow remains active, so it cannot place a secret after relocking. See
[Unlock for Auto-Type](autotype-unlock.md). Copy does not type or reuse a typing approval.

One click selects a selector row; double-click, Type or Enter types its normal
sequence. The dropdown acts on the selected row. Ctrl+1/2/3/4 type username,
password, TOTP or URL; Ctrl+Shift+1/2/3/4 copy them. These shortcuts are scoped
to the selector and listed in Keyboard Shortcuts. A pending [search](autotype-search.md) clears old rows/actions immediately.
Enter waits for its current results; field actions wait for fresh selection and
availability instead of acting on an old row.

Ctrl+Shift+V now types the selected entry's sequence, matching KeePassXC's
`actionEntryAutoTypeSequence`. Global matching remains available from Auto-Type
in the menu and the companion shortcut. The seven field actions have configurable
window shortcuts with the corresponding stock Qt action keys and no new defaults.
Entry actions are disabled while editing text, in selection mode, with a modal
dialog, on locked/recycled/ambiguous entries or while availability is pending.
Explicit private `win.autotype` bindings still belong to the global chooser;
if one conflicts with the newly corrected selected-entry default, the existing
conflict UI preserves the stored value and asks the user to resolve it.
No live shortcut settings are rewritten by packaging this change.

Availability requests use weak owner/snapshot references and epoch/generation/
identity/UUID/serial guards. Selection/lock/close clears flags, late responses
cannot enable another entry's actions, and retries of a full background queue stop
when the context is stale. Metadata errors keep the actions disabled with a
retry notice. A new engine capability guards all field-only requests; older
engines cannot silently ignore the field/template check. Native and companion
typing authorization policies remain as documented in
[Confirmation Preferences](autotype-confirmation.md).

Runtime/native/Python compilation only. No tests/harnesses or automated GUI,
typing, clipboard, portal, shortcut, config or vault behavior runs were added or
performed. User manual acceptance remains for every action/reference/protected
or empty field, TOTP validity/freshness, disabled/inherited eligibility, keyboard
and pointer selection, shortcut/profile conflicts, metadata/cancel/lock/reload
races, cross-vault clipboard ownership and real X11/Wayland behavior. No production
readiness or complete Auto-Type parity is established.

References: KeePassXC Team/Felix Geyer GPL2-or-3 sources; this independent
integration is GPL3-only.

- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/DatabaseWidget.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/MainWindow.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/MainWindow.ui
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/autotype/AutoTypeSelectDialog.cpp
