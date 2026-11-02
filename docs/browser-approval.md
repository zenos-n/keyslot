# Browser approvals and connection trust

With the GNOME companion version4/package0.4.0 enabled, a browser request for
password access opens a compact Shell dialog rather than bringing up the main
Keyslot window. The dialog shows the paired connection, website/form destination,
and selectable entry names/usernames. It has Allow Selected, Deny, Remember This
Decision, and Fully Trust This Browser. It contains no passwords, TOTP seeds,
browser association keys, or vault unlock credentials.

This uses GNOME's modal dialog surface, independently of notification Do Not
Disturb. It does not change DND settings. Without a running compatible companion,
the existing GTK approval dialog opens instead. Unlocking, pairing, saving or
deleting a login, password generation and passkey ceremonies retain their
existing application dialogs.

Fully Trust This Browser applies to that paired browser connection in that
database. It permits subsequent matching login requests, including HTTP
authentication, without per-entry access prompts. Website matching, hidden and
recycled entries, expiry checks, explicit website denials and group connection
restrictions still apply. This is not an unrestricted export endpoint. Browser
TOTP requests retain the existing authenticated UUID/visibility rules. The
separate entry-listing preference is unchanged. Saving/deleting credentials and
passkey user-presence/verification still require their existing approval.

Trust is encrypted database metadata bound to the current browser identification
key. It is distinct from per-entry remembered website permissions. In Database
Settings → Browser Connections, a fully trusted connection shows Stop Trusting;
this removes trust without disconnecting the browser. Existing remembered site
decisions remain. Revoking or replacing the connection clears its trust. Normal
automatic/manual database-saving preferences apply to trust changes.

The native release operation accepts trust only with explicit approval and a
nonempty selection from its single-use, database/revision-bound lookup token.
The request is reauthenticated before persisting trust. Removing trust from the
connection list checks a key-derived connection revision so a stale row cannot
change a replacement connection. Native lookup enforces trust; no browser-supplied
boolean grants it.

The companion exports Browser1 on GNOME Shell's existing session-bus owner and
accepts calls only from Keyslot's current unique owner. The app resolves and
addresses the unique Shell owner. Request payloads contain only display metadata
and opaque entry identifiers; native release validates every returned identifier.
Only one browser consent prompt is active. Escape, owner loss, lock-screen entry,
extension disable, browser cancellation/disconnect, vault invalidation and a
25-second deadline cancel approval. Closed/expired prompts do not reopen the main
window. Dialog metadata is removed without a closing animation.

Implementation follows the [GNOME Shell dialog API](https://gjs.guide/extensions/topics/dialogs.html)
and the installed GNOME50.4 ModalDialog, Dialog and CheckBox implementations.
Validation for this change is limited to native/runtime package compilation,
packaged Python bytecode compilation, JavaScript syntax parsing and static
source/artifact review. No tests, harnesses or application/Shell/browser/vault
behavior runs were added or performed. User manual approval/DND/owner/lifecycle,
accessibility and trust/revocation acceptance remains pending.
