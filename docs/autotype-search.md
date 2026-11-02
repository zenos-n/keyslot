# Auto-Type chooser search

The chooser has the same two search scopes as KeePassXC:

- **Window matches** is the initial scope when the destination has matches.
  The native Qt wildcard filter checks group name, resolved title and resolved
  username, case-insensitively. It does not search sequence text. Matching
  destination associations retain their individual sequences.
- **Search All Unlocked Databases** uses the native EntrySearcher, including
  field prefixes, negation, regular expressions and protected-field search as
  supported by the pinned2.8 core. An empty query becomes `*`. Each eligible entry
  contributes its nonempty effective default sequence and every distinct,
  nonempty custom association sequence, irrespective of destination pattern.
  Empty/inherited association sequences do not create duplicate rows. Group
  search exclusions are respected; Auto-Type-disabled entries/groups,
  recycled entries and optionally expired entries are omitted.

When there are no window matches, all-database search starts automatically and
its scope switch is fixed on, following upstream. Ctrl+F toggles the scope when
it is available. All databases means those unlocked and unchanged when the
request began; a vault unlocked or reloaded later requires a new invocation.
Ambiguous entry identifiers are excluded rather than selecting an arbitrary
entry. Native and GTK ship together under the `autotype-search` capability;
an older engine cannot silently fall back to substring search.

Searches run off the GTK thread. Edits immediately clear old rows/actions,
debounce all-database searches and coalesce behind one in-flight request. At
most one queue-retry timer is retained. Query, scope and request serial are
checked before display. Weak snapshot/session contexts and epoch, identity,
generation and unlocked state are checked around native search and before
Type/Copy. Closing stops timers, clears rows/contexts and rejects late callbacks.
Errors remain inline and leave the selector open for a corrected query.

Enter during a pending search waits for the current query's fresh results and
then activates the selected result; another edit/scope change cancels that
intent. Type and field actions cannot act on old rows. Remembered selection
compares each actual sequence digest, including custom associations, and falls
back to the same entry’s first available sequence if the old sequence is absent,
as upstream does. Neither search results nor remembering bypass native preparation, one-use
approval, PICKCHARS, portal or focus checks. The live chooser receives only its
explicit native display projection plus entry UUIDs/unexpanded sequences; general
snapshots and automatic matching keep their narrower existing schemas.
Queries are not written to preferences.

The selector's **Sort Entries** header button offers Group, Title, Username or
Sequence, in ascending or descending order. The profile uses stock
`AutoTypeDialogSortColumn` (0–3) and `AutoTypeDialogSortOrder` (0–1), with Group /
Ascending as the native defaults. Existing private options gain only those
defaults; malformed sort settings are rejected. Other Auto-Type preferences
preserve these keys when saved.

Sorting uses native `QSortFilterProxyModel` with the same locale-aware,
case-insensitive settings as stock AutoTypeMatchView. It orders the raw native-
resolved display keys across all results and returns only a source-index
permutation. GTK appends that order without casefolding, GLib comparison or a
second tie-breaker. The [chooser projection](autotype-display.md) includes
protected usernames and reference values as the stock model does; general entry
snapshots retain their existing protected-field omissions. Equal keys preserve
the Qt proxy's ordering of the captured input, without claiming identical stock
multi-vault traversal order.

Changing order starts a fresh asynchronous collection, retains the selected
owner/entry/sequence when still eligible, cancels pending Enter intent and does
not initiate typing. Type/Copy cannot use the old rows. Sort controls are disabled
during Copy. Save failures restore the prior setting; query, scope, sort options,
serial and vault contexts guard display and actions. Late callbacks after close
or lock cannot repopulate rows. The private `autotype-sort` capability and strict
index-permutation validation prevent silent fallback to a different comparator.

This is an independent GPL3-only integration of behavior documented by
KeePassXC Team/Felix Geyer GPL2-or-3 sources:

- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/autotype/AutoTypeSelectDialog.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/autotype/AutoTypeMatchView.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/autotype/AutoTypeMatchModel.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/core/EntrySearcher.cpp

Native/runtime/Python compilation only. No tests/harnesses added or run; no
automated search, GTK, keyboard, typing, clipboard, portal or vault behavior
checks. Manual acceptance remains for native query syntax/protected fields,
search-excluded groups, wildcard/reference matching, default/custom/duplicate
associations, expired/disabled/recycled/ambiguous entries, multiple vaults,
selection memory, Enter/edit/scope/lock/reload/close/error/queue races and real
X11/Wayland focus/keyboard behavior. [Locked-vault resumption](autotype-unlock.md) now uses existing providers and
immediate temporary-vault relocking and a chooser for other locked vaults. Saved
sort controls and [portal permission lifetimes](autotype-permissions.md) are implemented;
[resolved chooser display/native sorting](autotype-display.md) manual acceptance, [portal Copy](autotype-clipboard.md) manual acceptance and wider
platform/accessibility acceptance remain separate work. The core now uses [2.8/Qt6](../engine/Native28.md); GTK behavior and production
readiness remain unproven.

Desktop shortcut aliases/disable/reset are now editable in the [GNOME companion](autotype-shortcuts.md); recorder, focus and platform acceptance remains manual.

The chooser now fetches [native-resolved display fields](autotype-display.md) for protected usernames and title/username references; automatic match results and general snapshots are unchanged. Compilation only, user manual display/lifecycle/locale acceptance remains.
