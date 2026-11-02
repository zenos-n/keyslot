# Auto-Type chooser display fields

KeePassXC2.8 AutoTypeMatchModel displays the immediate parent group, placeholder-
resolved Title, placeholder-resolved UserName and the raw selected sequence. Its
proxy sorts those display values with Qt case-insensitive locale collation.
Previously Keyslot used its general entry snapshot, which deliberately omits a
protected username and retains raw reference text. Matching could therefore find
an entry whose displayed/sorted name did not match the native search result.

The native `autotype.search` response now carries chooser-only `group`, `title`
and `username` strings alongside entry UUID and sequence. Title/UserName resolution
uses upstream `Entry::resolveMultiplePlaceholders`, the same calls as the native
model; the parent group is its immediate name. The existing `autotype.matches`
identity/sequence response remains unchanged, including automatic single-match
execution. No resolved display fields are added to the general Snapshot, recent-
selection cache, saved preferences, browser protocol or typing plan.

The backend requires `autotype-display`, `autotype-search` and `autotype-sort`
and validates the exact response structure/types. The chooser initially waits for this native
projection rather than briefly displaying raw snapshot values. Search scope,
owner identity/epoch/generation/snapshot and flow/query serial guards remain in
place. Rows use markup-disabled labels; NUL characters are removed at the GTK
text boundary after native ordering of the unmodified display values. Empty display titles
retain the GNOME “Untitled Entry” fallback but sort as the native empty string.
Sequence text, entry identity and approval/preparation checks are unchanged.

As in the stock chooser, a protected username can be displayed here while the
main metadata snapshot still hides it. A user-authored reference in a title or
username can also resolve protected content: this is the native chooser’s display
behavior, not an expansion of main-window previews or a new password reveal API.
Projection runs only for the live chooser on already-unlocked eligible entries.
GTK’s configured main preview masking remains separate, as before.

Resolved labels are blanked and rows disabled/removed before close/cancel/lock
animation; row identity references and pending selection are then dropped. Completed
search result lists are cleared even when stale, and stale callbacks cannot
repopulate the dialog. Native/Python temporary strings and allocator copies are
not guaranteed to be securely zeroized. Existing lock/native helper teardown,
request-bound ownership, native prepare tokens and destination/permission gates
remain the security boundaries.

Ordering now runs through Qt's `QSortFilterProxyModel`, configured exactly as
stock AutoTypeMatchView: dynamic sorting, locale-aware comparison and
case-insensitive sorting, with the selected ascending/descending direction.
A temporary `QStringListModel` holds only the chosen column's raw display keys;
there is no Python casefolding, GLib collation, numeric mode or extra tie-breaker.
The proxy's source row mapping returns a permutation, so equal-key behavior uses
the same proxy implementation and captured source order. For equal keys across
vaults, that source order follows the captured session/result order; this does
not establish identical upstream multi-database traversal order.

All chooser results are ordered together, rather than concatenating per-vault
sorted lists. The selected display keys can include already-projected values
from other unlocked vaults and are sent transiently to the initiating vault's
existing native helper. The sort request contains no vault/entry identifiers,
new field reads or raw credentials; its reply contains only source row indices.
It stays behind the existing unlocked-database gate and generation-bound
operation, reads no database data and changes no pending typing token. The
backend rejects malformed, repeated, missing or out-of-range indices. No sort
strings are stored on GTK rows or in preferences/recent-choice caches.

Column/direction join the query/scope/serial freshness key. Changing a sort
clears and disables stale actions while collecting fresh results, cancels pending
Enter intent and restores the selected owner/entry/sequence after rendering when
it remains eligible. Rapid changes coalesce; changing query or scope drops that
selection. Copy disables sort controls, failed preference writes restore the
previous settings, and lock/close discards pending selection and late callbacks.
Native search/reference resolution and key sequences are unchanged. This removes
the separate GLib sorting implementation; same-locale ordering and lifecycle
behavior still require manual acceptance, not a production/full-parity claim.

Evidence is native/runtime/Python compilation and static source/artifact review
only. No tests/harnesses or automated vault/reference/search/GTK/typing/portal/
clipboard behavior runs were added or performed. User manual acceptance remains
for protected/plain/reference chains and missing/cyclic targets, literal braces,
Unicode/locale/case, duplicate group names, empty/large values, multiple vaults,
remembered selection, initial/search/Enter/sort timing, close/lock/reload and stale
worker races, screen readers and X11/Wayland. Older engines should be upgraded
with the app; no unsafe fallback to snapshot-projected values is used.

Behavioral references: KeePassXC Team/Felix Geyer source GPL2-or-3;
independent Keyslot integration GPL3-only.

- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/autotype/AutoTypeMatchModel.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/autotype/AutoTypeMatchView.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Entry.cpp
