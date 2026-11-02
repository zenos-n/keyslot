# Wayland Auto-Type keyboard connections

**Keep Keyboard Connection Open** maps stock
`AutoTypeDesktopPortalPersistConnection`, default false. When enabled, a
successfully used connection stays available until it is closed, invalidated or
Keyslot quits. With it disabled, the stock `GlobalAutoTypeRetypeTime` (0–60 seconds,
default 15) controls idle closure; zero closes immediately. This is distinct from
[remembering portal permission](autotype-permissions.md): permission lifetimes
apply when opening a new connection, while reusing a connection does not make a
new permission request. The desktop can still end either connection or grant.

An application-owned transport manager serializes keyboard use across vaults.
Each acquisition receives a fresh invocation lease, captures the current
permission epoch/profile before any portal request, and checks the invocation's
vault, flow, focus lease, native one-use token and deadline. An idle transport
retains no vault, entry, sequence, plan, destination or previous invocation
callback. Its validity callback is replaced with a false callback until a fresh
lease is installed. A reused connection cannot select or approve an entry by
itself; failed input is never automatically replayed.

Successful completion may retain the transport. Errors, cancellation or revoked
sessions close it. An idle timer checks transport identity and a unique idle-period marker;
acquisition also checks monotonic expiry, so a delayed timer cannot extend reuse.
The idle marker changes on every reuse, preventing a canceled old timer from
closing that same transport after a later invocation has returned it to idle.
Failure to start a timer or close thread falls back to closing the transport.
Persistent mode omits the timer. A granted [portal Copy](autotype-clipboard.md)
selection also holds its connection until ownership is lost or its data is
cleared; copy expiry/clear releases that session. Turning persistence off closes the old transport;
changing only this flag leaves remembered permission intact. Other Auto-Type
policy changes close the connection as well, including timeout changes.

Vault security clearing, Lock All, Forget, permission/profile changes and shutdown
invalidate the transport epoch immediately. Idle close runs off the GTK thread.
An active worker retains its reservation until it releases any pressed keys and
closes the old session; another invocation must retry while that cleanup is
pending. A vault lock closes the shared connection even if another vault used it.
This deliberately retains the existing security-lock boundary; remembering a
desktop permission does not keep a typing connection alive through a vault lock.

Portal requests, input, session signals and closes are bound to the captured
unique D-Bus owner. Owner-change and Session::Closed signals mark it unusable;
reuse also checks the current owner directly. A stale cached owner causes a fresh
session negotiation before any new sequence is prepared or sent. Queued signals
and timers refer only to their old transport and cannot retarget a new session.
Close is serialized/idempotent, and modifier-release cleanup retains its existing
behavior. [Portal Copy](autotype-clipboard.md) now requests clipboard access only
when its separate preference is enabled. Screen capture, pointer and EIS access
are not requested.

Runtime/Python compilation only. No tests/harnesses or automated transport,
portal, GUI, timer, keyboard, clipboard, profile or vault behavior runs. Manual
acceptance remains for persistent/default/zero/max idle timing, rapid repeated
invocations, multi-vault lock/cancel/temporary relock, cleanup reservations,
service-owner and session changes, denial/revocation, policy/Forget/shutdown
races, old portals, focus, keyboard and accessibility. No full-parity or
production claim is made; portal Copy and wider Auto-Type/desktop workflows
still need manual acceptance.

Independent GPL3-only integration; KeePassXC Team/Felix Geyer behavior is
attributed to its GPL2-or-3 sources. Portal API documentation is by the XDG
Desktop Portal authors.

- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/osutils/nixutils/RemoteDesktopPortal.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp
- https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Session.html
- https://docs.gtk.org/gio/method.DBusConnection.signal_subscribe.html
