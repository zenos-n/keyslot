# Linux system-authentication unlock

**Preferences → Security → System Authentication** enrolls the current vault for
this Keyslot application session after re-verifying its master password/key-file/
hardware components. **Enable System Authentication** confirms that enrollment.
This does not change the master key. After locking, opening that location offers
**Authenticate and Unlock**, master-password fallback, and the existing short
password when configured. Authentication is never started automatically just by
opening a window. Configured hardware keys can still require a touch after
system authentication. Closing a vault session (rather than hiding its background window), changing the vault key,
changed-key reauthentication, Save As to another path, disabling the option or
quitting revokes its cached credential. Ordinary locking keeps the enrolled
session credential, while still destroying the native vault helper and its open
database/key objects.

The separate `keyslot-auth-broker` owns an encrypted credential capsule. It uses
upstream KeePassXC/Botan AES-256-GCM with a fresh 32-byte key and 12-byte IV.
Only the key/IV are held in a private Linux process keyring; its ring and keys
have possessor-only permissions. The broker retains ciphertext plus opaque
handles/path metadata, not a permanently decrypted master credential. Keying
buffers are explicitly scrubbed after use. Core dumps and dumpability are
disabled. Qt parsing/IPC necessarily creates short-lived native plaintext buffers
during enrollment/authenticated delivery; this is not a promise that arbitrary
process memory/swap is a secure enclave.

Enrollment and authenticated credential delivery go directly between native
processes over a private owner-only local socket. GTK's control pipe contains
only registration PIDs, opaque handles and status. Kernel peer credentials,
parent-owned one-use helper PID/start-time registrations, and the expected broker
PID are checked. Unacknowledged enrollments expire in ten seconds or are revoked
when their native peer disconnects. A generation check prevents cancelled
backend enrollment from publishing a handle. No credential is stored on disk
by this provider or sent on the public Shell D-Bus API. The existing GNOME
login-keyring startup feature remains a separate explicit enrollment.

The broker connects to the fixed `/run/dbus/system_bus_socket`, independently of
`DBUS_SYSTEM_BUS_ADDRESS`, verifies a root-owned Polkit service, and identifies
its authorization subject by its unique system-bus name. Every release requires
`CheckAuthorization` for `com.neg-zero.keyslot.unlockDatabase`, with interaction
allowed and a unique cancellation ID. The packaged policy denies remote and
inactive sessions and requires the active user's authentication (`auth_self`,
no retained grant). Local administrator Polkit rules can override that policy;
Keyslot does not edit those rules. Fingerprint/FIDO/password offerings belong to
the installed GNOME agent and PAM configuration, not a custom biometric driver.

Authorization is asynchronous in the broker, so it continues servicing revocation
and control requests. Peer loss, vault locking, dialog cancellation, timeout or
forgetting a handle cancels the authority request and invalidates late callbacks.
The native credential is only decrypted after approval, with record-generation,
peer-liveness and authority-identity rechecks. Closing the broker revokes kernel
keys; a Linux pidfd follows whole-application death (not just the enrolling worker
thread), and control-pipe EOF also stops it. This requires Linux pidfd support. Authorization failures use master-password
fallback, never an unguarded cached credential. Changes to the actual vault key
that make native reopening fail also discard the handle.

The action file must be installed system-wide in the system Polkit action search
path. The app package installs it under `share/polkit-1/actions`; NixOS's Polkit
module links that directory from system packages. Select the updated Keyslot
ZenPkgs package and rebuild the system before using this option. In ZenOS, the
system package selection is `system.packages.com.neg-zero.keyslot = true;`.
Replace the global stock KeePassXC selection with Keyslot, since both provide
the `keepassxc`, CLI and native-proxy compatibility commands.
A `users.<name>.packages` selection alone does not publish its action to the
system authority. In ordinary NixOS, include Keyslot in
`environment.systemPackages` and enable `security.polkit`. `nix run` by itself
cannot register a trusted system action. Availability checks inspect the
action's installed default policy without starting an authentication prompt;
missing policy, authority, agent or kernel keyring support fails closed. No
system policy or PAM configuration is changed by enrollment.

The design follows the KeePassXC Team's GPL-2.0-or-later Linux Polkit provider
(fixed bus, authorization before credential decryption, AES-GCM plus process
keyring). This independent broker/client/GTK integration is GPL-3.0-only.

- [Upstream Polkit.cpp, 2.8.0](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/quickunlock/Polkit.cpp)
- [Polkit Authority API](https://www.freedesktop.org/software/polkit/docs/latest/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html)
- [Linux process keyrings](https://www.kernel.org/doc/html/latest/security/keys/core.html)

Validation is native/package/Python compilation only. No tests/harnesses were
added/run; no actual authentication/keyring/GUI/vault/session-policy acceptance
was performed. Real GNOME agent/PAM/biometrics/hardware, enrollment/revocation,
lock/cancel/timeout/parent-death, key changes/recovery, multiple windows and
installed policy discovery require user manual acceptance before production.
