# Entry and group properties

**Entry Properties…** in the entry details and **Group Properties** in the Groups
header expose the selected object's identity, parent/previous-parent UUIDs,
created/modified/access/location timestamps, expiry, usage count and recycle
state. UUIDs have normal and stock hexadecimal representations and use the
existing timed clipboard. Entry history count and direct/recursive group and
entry counts are included. This is an inspector: identifiers and timestamps are
not rewritten. The pinned stock `EditWidgetProperties` page also treats these
fields as read-only.

Plugin data is the object's `CustomData`, distinct from editable entry attributes.
The list searches names, shows character counts/last-modified timestamps, pages
100 items at a time and keeps all values in the native core until an explicit
inspect/copy request. Values are never included in snapshots or list/review
responses. The value dialog clears on close/lock. Copy uses the ordinary timed
clipboard. A separate explicit plaintext-export confirmation writes the complete
UTF-8 value to a new, owner-only file; existing paths cannot be overwritten.
Values over one million UTF-16 code units require export rather than rendering
or copying through GTK. Names over 32,768 code units are reported as omitted;
manage those unusual items through stock KeePassXC. Empty names and values are
supported. Invalid identifiers and ambiguous current entry/group UUIDs are
rejected; history copies do not make a current entry ambiguous.

The stock Properties page permits removal, rather than arbitrary creation or
editing, of plugin data. Keyslot follows that scope. Select up to 256 items,
including across list pages, and review their exact names plus object before
confirming removal. The native token expires after two minutes and binds the
helper database identity, working revision, unique target and each selected
value/timestamp fingerprint. Changes or expiration refuse the operation. Local
file conflicts use the normal source fingerprint check. No other plugin items
are removed. Automatic bookkeeping can be recreated by the core; deleting
integration settings may disable plugins or change inherited permissions, which
the dialog explains before confirmation.

Entry removal uses `beginUpdate`/`endUpdate` and the existing custom-data history
backport in `SecurityBackports.patch`, subject to the database's history limits.
Groups have no entry history. Both use ordinary encrypted transactions,
manual-save checkpoints or automatic saving, backup and rollback handling.
No helper keys or secret values are sent over the public GNOME D-Bus interface.

The UI reuses native property semantics from the KeePassXC Team/Felix Geyer
GPL-2.0-or-later sources; this independent Keyslot adapter/UI is GPL-3.0-only:

- [EditWidgetProperties.cpp, pinned 2.7.12](https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/gui/EditWidgetProperties.cpp)
- [TimeInfo.h](https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/core/TimeInfo.h)
- [CustomData.h](https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/core/CustomData.h)

Validation is native/package/Python compilation only. No tests or harnesses were
added/run, and no automated vault/GUI/clipboard/file-export behavior was run.
Manual acceptance remains for large/empty/Unicode plugin items, pagination and
selection, copy/reveal/export, history/rollback/recovery, integration revocation,
lock/cancellation, source conflicts and GNOME/accessibility behavior.
