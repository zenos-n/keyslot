# Wayland portal Copy

**Use Desktop Portal for Clipboard** maps stock
`AutoTypeDesktopPortalUseClipboard`, default false. KeePassXC uses this option in
its explicit Clipboard::setText/Copy path. Auto-Type itself continues to execute
the parsed key/delay/clear sequence; this feature adds no synthetic paste action.

When enabled on Wayland, normal explicit Copy and the Auto-Type selector's Copy
Field actions first acquire the existing guarded RemoteDesktop connection.
Clipboard version support is checked and RequestClipboard is sent before Start.
Only a successful `clipboard_enabled` grant enables selection publication.
Unavailable interfaces, denied access and unsupported large values can use the
standard GTK path if the original Copy request is still current and no portal
selection claim has been attempted. After a portal claim starts, failures or
ownership loss report failure without a later fallback that could overwrite a
newer selection. The opt-in applies to explicit Copy; built-in GTK editing and
primary-selection providers keep their existing tracking/expiry behavior.

Copy requests bind their source session epoch, native identity/generation and
snapshot, configuration profile and request serial. A newer Copy, lock/close,
source hide or regular-clipboard change before claiming cancels a pending
request. Selector Copy also checks its existing flow. Publication and minimize/
lower/background behavior happen only after successful Copy completion. A
published value is then associated with its weak originating session and epoch;
it can be pasted after the window is hidden, just like the GTK clipboard.

The portal owns a MIME selection for UTF-8/plain text and the advisory
`x-kde-passwordManagerHint=secret` format. A SelectionTransfer from the captured
unique portal owner is answered using SelectionWrite's returned Unix FD and a
SelectionWriteDone success/failure response. Descriptor indices are checked,
the duplicated FD is closed, and writes are nonblocking in bounded chunks with a
five-second transfer deadline. There are at most eight concurrent transfer workers
per transport and no unbounded queue. Rejected/canceled transfers receive failure
responses. The client never calls SelectionRead or reads another application's
clipboard. Payloads above 16 MiB take the standard path before a claim; they are
not truncated. Both text representations use UTF-8; the hint is metadata only.

Before each chunk, the client checks current record/owner, permission/profile and
connection epochs, session closure/revocation, cancellation and expiry. A
replacement Copy invalidates the old record; owner-change signals drop its
payload. Unpublished records have a five-second limit so a stale/suppressed GUI
completion cannot leave an indefinite clipboard claim. Published deadlines use
the existing clipboard timeout/Never preference, recalculated from the original
publication time on changes. Timer callbacks carry both record identity and a
unique scheduling marker. Copied bytearrays are overwritten on release; GTK,
Python strings, OS pipes and applications that already read the data cannot be
securely erased by that operation.

The connection stays alive while it owns copied data, including Never. Once
another application takes ownership, normal keep-open/idle closure resumes.
Expiry, explicit clear, lock or shutdown releases the owning session instead of
issuing an empty SetSelection that could reclaim a newer foreign clipboard.
That security cleanup can end an in-progress Auto-Type operation sharing the
connection. It uses transport identity so an old cleanup cannot close a newer
transport. A different vault's GTK provider is still preserved; the shared portal
connection closes at the existing any-vault security-clear boundary. This path
publishes the regular clipboard; it does not replace the GTK primary selection.
Clipboard manager behavior and central desktop retention remain outside client
ownership, as with ordinary explicit Copy.

Runtime/Python compilation only. No tests/harnesses or automated portal,
clipboard, FD, payload, GUI, vault, permission or input behavior runs. Manual
acceptance remains for supported/old/unavailable services, grants/denial, first
and repeated/empty/Unicode/large copies, multiple formats/readers, stale/new
owners, FD backpressure/timeouts, concurrent copies, source locks/hides/edits,
selector flows and temporary relocking, fallback, Never/deadline changes,
minimize/background grace, policy/profile/Forget/shutdown races and accessibility.
No full-parity or production-readiness claim is established.

Independent GPL3-only integration. KeePassXC Team/Felix Geyer source behavior is
GPL2-or-3; API documentation is by the XDG Desktop Portal and GLib authors.

- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/Clipboard.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/osutils/nixutils/NixUtils.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/osutils/nixutils/RemoteDesktopPortal.cpp
- https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Clipboard.html
- https://docs.gtk.org/gio/method.DBusConnection.call_with_unix_fd_list_sync.html
- https://docs.gtk.org/gio/method.UnixFDList.get.html
