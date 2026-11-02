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

The backend requires `autotype-display` as well as `autotype-search` and validates
the exact response structure/types. The chooser initially waits for this native
projection rather than briefly displaying raw snapshot values. Search scope,
owner identity/epoch/generation/snapshot and flow/query serial guards remain in
place. Rows use markup-disabled labels and resolved title/username/group sort
values; NUL characters are removed at the GTK text boundary. Empty display titles
retain the GNOME “Untitled Entry” fallback but sort as the native empty string.
Sequence text, entry identity and approval/preparation checks are unchanged.

As in the stock chooser, a protected username can be displayed here while the
main metadata snapshot still hides it. A user-authored reference in a title or
username can also resolve protected content: this is the native chooser’s display
behavior, not an expansion of main-window previews or a new password reveal API.
Projection runs only for the live chooser on already-unlocked eligible entries.
GTK’s configured main preview masking remains separate, as before.

Resolved labels and sort strings are blanked and rows disabled/removed before
close/cancel/lock animation; row identity references are then dropped. Completed
search result lists are cleared even when stale, and stale callbacks cannot
repopulate the dialog. Native/Python temporary strings and allocator copies are
not guaranteed to be securely zeroized. Existing lock/native helper teardown,
request-bound ownership, native prepare tokens and destination/permission gates
remain the security boundaries.

This closes the raw/protected/reference display-source mismatch. Sorting still
uses GTK/GLib casefolded locale comparison, so exact Qt/GLib locale/case ordering
can differ. Native search/reference resolution and key sequences are unchanged;
this does not claim full platform/feature parity or production readiness.

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
