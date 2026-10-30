# Keyslot

GTK4/libadwaita client for KeePassXC databases, with a separate GNOME Shell 50
Quick Settings companion. Application and ZenPkgs identity:
`com.neg-zero.keyslot`. AppStream uses the normalized `com.neg_zero.keyslot`.

**Compatibility work in progress. This is not yet a drop-in replacement.**
The [coverage matrix](docs/parity.md) distinguishes source implementation from
verified behavior. Auto-type, remaining SSH platform acceptance, Secret Service,
KeeShare, breach/browser reports, and several advanced database workflows remain unimplemented.

## Native engine

Version 0.2 replaces the CLI boundary in the app with a private helper linked
against the actual **KeePassXC 2.7.12 core**. It does not reconstruct databases
from XML. The packaged source and dependencies come from the same pinned
Nixpkgs KeePassXC derivation; a version assertion prevents an unreviewed engine
upgrade. The old CLI adapter remains only for regression tests.

The helper addresses entries and groups by UUID, so duplicate names and slashes
are no longer ambiguous. Its source supports clearing fields, multiline and
Unicode values, custom attributes/protection, TOTP configuration, entry expiry
and tags, group editing/moves/recycling, attachment import/export/removal,
history restore/removal, and upstream search syntax. Database workflows include
metadata, compression, cipher/KDF settings and unlock-cost calibration; key-component
rotation, generated key files and key-file-only creation; upstream merge; XML/CSV/HTML
export; encrypted database copies; and local health/statistics reports. Failed refresh
keeps the current data open so it can be saved as an encrypted copy if the source
file is unavailable. These operations are wired into GTK
dialogs. Their real engine integration tests must pass before packaging succeeds.

Import source includes KeePass 1 (`.kdb`), KeePass XML, Bitwarden JSON (including
password-protected exports), 1Password 1PUX/OPVault, and Proton Pass JSON through
the pinned upstream readers. The GTK workflow collects source credentials
separately from the new database's unlock key. It saves a new encrypted KDBX4
file without replacing an existing destination or changing the import source.
CSV source uses KeePassXC's parser with encoding, separators, quotes, comments,
backslash escapes, skipped rows and eleven mapped fields. Import review pages
through titles/groups/usernames with passwords hidden. CSV source values can be
previewed explicitly with row/column navigation; preview text shortening does
not truncate imported values. A reviewed source's fingerprint must still match
at import. Native integration tests cover the pinned upstream import fixtures.

The native helper and complete Nix application package build successfully on
the GNOME 50 host. All 188 tests pass without skips. Ten package gates cover the backend, GTK,
login keyring, terminal signals, browser management, encrypted browser workflow, passkey management, SSH management, GCR and real agent forwarding. This verifies implemented workflows, not full KeePassXC parity.
Separate host acceptance with unmodified KeePassXC-Browser 1.10.4.1 and sandboxed
Chromium155.0.8059.40 also passes pairing, DOM form filling, TOTP, generation,
saving, groups and DOM WebAuthn create/get with independent signature verification.

## Build and run

Requires Linux, Nixpkgs with KeePassXC 2.7.12, and a graphical session with GTK4,
libadwaita, PyGObject, and a session bus. The Nix package supplies runtime
libraries and the helper, and runs real engine integration tests.

```sh
nix build
./result/bin/keyslot
# Or build and launch in one command:
nix run
# Build just the private native helper:
nix build .#engine
# Run the real-core, GTK and login-keyring package checks:
nix flake check
```

The flake locks the reviewed Nixpkgs revision containing KeePassXC 2.7.12 and
exports `keyslot` (also the default package/app), `engine`, and a development
shell for `x86_64-linux` and `aarch64-linux`. The companion extension remains
a separate repository and package. Update the Nixpkgs pin together with an
engine review; the recipe rejects an unexpected KeePassXC version.

The development shell supplies the helper, GTK/libadwaita/libsecret typelibs,
the CLI used by regression tests, and the pinned upstream import fixtures:

```sh
nix develop
python3 -m keyslot
python3 -m unittest discover -s tests -v
```

For real browser acceptance, supply an existing Chromium-based executable and the
official KeePassXC-Browser Chromium release ZIP. The check creates its own profile,
native-host manifest, HTTPS site and disposable database; it never opens user data.
It requires Chromium's `Extensions.loadUnpacked` debugging API (tested with the
versions above), keeps the browser sandbox enabled, and permits only its generated
TLS certificate. This host check is separate from the Nix build gates:

```sh
nix develop --command xvfb-run -a python3 tools/smoke-browser-extension.py \
  --browser /path/to/chromium-based-browser \
  --extension-zip /path/to/keepassxc-browser_1.10.4.1_chromium.zip
```

The existing `nix-build` and `nix-shell` entry points remain available.

A Meson-only install does not build the helper. Build it first, and supply
`KEYSLOT_ENGINE` when running the app:

```sh
meson setup build --prefix="$HOME/.local"
meson install -C build
```

The companion source is a separate repository, `../keyslot-gnome-extension`.
Select its ZenPkgs package separately and enable `keyslot@neg-zero` in GNOME
Extensions. The tile goes in **Quick Settings**, the upper-right system menu.

Ctrl+O opens a database; Ctrl+N adds an entry; Ctrl+F searches; Ctrl+L locks the current database;
Ctrl+G opens the generator; Ctrl+R refreshes; Ctrl+Shift+S saves an encrypted copy;
Ctrl+W closes the current window; Ctrl+Shift+L locks all databases;
Ctrl+Q quits and locks every database. With the default background preference,
closing a window hides it and keeps its vault available; disable background mode
to lock and close instead. Lock hooks cover configurable inactivity, GNOME screen
lock and logind suspend; real desktop acceptance of those hooks remains open.

Each database has its own window, helper, key, view and worker queue. Opening the
same resolved path selects its existing window; opening another file keeps the
other databases available. Modal dialogs stay with their originating window.
Background results update that window, and inactive windows do not publish clipboard
results. Closing a window with background mode disabled stops its helper.
The public Quick Settings lock state
is aggregated: Locked means every database is locked, and Lock locks all databases.
There are no database tabs. Accessibility still requires manual GNOME acceptance.
Cross-database entry copy/move remains unfinished.

The main header shows the database name. Navigation panes extend to the top of
the window, boxed lists fit their rows, and row actions stay vertically centered.
The generator offers lowercase, uppercase, numbers, symbol groups, additional
and excluded characters, look-alike exclusion and a require-each-group option.
The desktop, window and welcome screen temporarily use the themed `keepassxc` icon.

## Startup preferences

Preferences → Startup offers **Remember Last Opened Vault** and **Unlock at Login**.
Remembering reopens the last successfully unlocked vault's password screen.
Login unlock is opt-in: unlock the vault, enable it in Preferences, and confirm
its password/key-file/hardware-key options. The helper verifies the credential
without replacing the open database, then libsecret saves it in GNOME's login
keyring. A per-user XDG autostart entry runs `keyslot --login` after sign-in.
The keyring must already be unlocked by the login session; hardware keys may
still require interaction. Failure leaves manual unlock available.

Login unlock runs once per application lifetime through the login activation;
normal launches and manual locks never silently unlock the database again.
Successful manual unlocks update the remembered vault and, when login unlock
is enabled, its keyring credential. Disabling either option removes autostart;
disabling login unlock also removes Keyslot's saved login credentials. **Forget
Login Credentials** retries removal if the keyring was unavailable or locked.
Settings contain flags, an inactivity timeout and a vault path, in a mode-0600 file. Credentials
are stored only in the persistent GNOME login collection via libsecret, never
in the autostart entry or settings JSON. Remembering a vault and login unlock are opt-in.

**Run in Background** is enabled by default and keeps vaults and their windows available after closing a
window. Quit still locks and exits. `keyslot --background` starts without a
visible window; login unlock also stays hidden when background mode is enabled.
Manual activation or the companion's Open action restores a window. The native
app appears in GNOME 50's existing Background Apps menu through the companion
extension, with generic lock status and a Quit button. The installed portal's
built-in monitor tracks Flatpak instances only; this native bridge is necessary
for ZenPkgs packaging. It is removed when the extension is disabled.

Preferences → Security offers inactivity locking with **Never**, common timeout
values and a custom 1–1440 minute timeout. Screen lock and suspend still lock
vaults when inactivity locking is disabled.

**Quick Unlock** sets a short password for the current vault until Keyslot quits.
Setup verifies the full master credential. The upstream core encrypts that
credential in an in-memory KDBX container with Argon2id and the short password;
the bundle is never saved to disk or settings. On unlock the helper decrypts it
and opens the original vault with its unchanged master credential. Five failed
attempts discard the bundle and require the master password. Changing the vault
key or quitting clears it as well. Hardware keys can still require interaction.

## Browser integration

Preferences → Browser Integration enables filling and saving logins with the
KeePassXC-Browser extension. Keep Keyslot running, and close official KeePassXC
before enabling integration: both use the same browser connection. The preference
shows when the listener is ready. **Configure…** registers selected Firefox,
Chrome, Chromium, Brave, Vivaldi, Edge or Tor installations with the packaged
upstream native proxy, including a socket-message framing fix. Replacing an existing registration requires confirmation;
disabling that browser restores its original file. Registrations changed by
another application are preserved, with an error rather than silent replacement.
The package exposes `keepassxc-proxy` and the unchanged upstream `keepassxc-cli`
on PATH. Its proxy launcher clears inherited browser GUI library paths so wrapped
Nix browsers cannot load incompatible libraries into the native host. Owned browser
registrations refresh to this launcher when Keyslot starts.

Connect from KeePassXC-Browser and approve the database connection in Keyslot.
Site requests show the origin and matching entry names/usernames; select which
entries to share. Remembered allow/deny decisions stay inside the encrypted
vault using upstream metadata. Database Settings → Browser Integration reviews
and revokes connections. Lock, disconnect or rekey cancels outstanding prompts.
Browser polling does not extend the inactivity timeout or disable the window.

Saving a new login or updating an existing one requires a GTK confirmation.
The helper retains the incoming password and returns only review metadata;
approval is single-use and bound to the unchanged database. New entries can use
the default browser group or a selected group. Updates preserve other fields
and create history; password references update the original password entry,
identified in the dialog. Cancelled and unchanged requests do not write.

Pairing, authentication, filling, save cancellation, creation and updates pass a
real GTK workflow through the packaged proxy and independently encrypted requests.
Browser TOTP requests use the core’s current codes and respect hidden, recycled
and connection-restricted entries. Group listing returns the upstream group tree
without the recycle bin. Creating a group requires GTK confirmation and supports
nested paths; an existing group is returned without a write. These actions also
pass the encrypted GTK/proxy workflow. Authenticated browser lock requests lock
the current vault, and fixed public lock/unlock notifications keep the extension
informed without exposing database metadata. Unlock requires fresh browser
authentication. Browser password requests reuse the full character/passphrase
generator. Only “Use Password” releases a result to that request; cancel and late
callbacks do not, and generation does not copy to the clipboard. Opening its
automatic preview does not extend inactivity.

Browser deletion requires GTK confirmation and preserves history in the recycle
bin. When the bin is disabled, the dialog explicitly warns about permanent
deletion. Native tokens bind the reviewed mode/entry to the unchanged vault.
Cancel/missing entries return the upstream encrypted false-success response.
Passkey registration and sign-in reuse upstream validation, key generation and
signing, with GTK account/origin review. Registration supports new entries,
attachment and separately confirmed replacement. Authentication always requires
a selected account and approval. Protected key material stays in the helper;
EC/RSA signatures pass independent OpenSSL verification. Browser-requested
timeouts are bounded to 1–300 seconds, with a countdown and cancellation.
The separate real-extension host check covers DOM WebAuthn creation/sign-in in
addition to password workflows. Localhost preferences, favicon downloads, custom browser paths, sandboxed browser packaging
and broader browser/platform acceptance remain unfinished.

Database → Passkeys lists passkeys with their actual passkey account and relying
party, search, expired-entry filtering, and selection for export. Entry details
also provides passkey information and import. Import reads the upstream `.passkey`
format into a new entry/default or chosen group, or attaches it to an existing
entry. Existing passkeys need a separate replacement confirmation. Review returns
metadata only and binds import to the source fingerprint. Files must be regular
files no larger than1MiB; invalid/incomplete data never modifies the vault.

Single and selected-passkey exports use the upstream six-field JSON format.
They contain **unencrypted private keys** and require confirmation; existing files
need explicit replacement. Duplicate titles receive distinct filenames. Each file
is staged and published privately with mode0600, with partial-export counts if a
later file fails. Private keys go directly between files and the helper, rather
than through GTK. Removing a passkey preserves other entry fields and creates
history; it does not revoke the website credential, and history/backups may retain
the key. Native tests verify EC, RSA and Ed25519 transfer/signatures independently.
The separate GTK gate covers review, selection, cancellation, overwrite approval,
history-preserving removal, changed-source rejection and stale actions after lock.

## SSH Agent

Enable **Preferences → SSH Agent** to use your existing session agent. The socket
defaults to `SSH_AUTH_SOCK`; optional socket and security-key-provider overrides
have explicit Apply controls. The status reports startup and cleanup failures,
with retry controls. Enabling this does not start a replacement `ssh-agent`.

Each entry has **SSH Key Settings** for an attachment or external key file, using
the entry password to decrypt the key. Save automatic loading, removal on lock,
per-use confirmation and lifetime policies in upstream-compatible KeeAgent
metadata. Preview/copy the saved public key or explicitly approve adding it.
**Preferences → SSH Agent → Agent Keys** lists keys with ownership labels, search,
selection, a filter for this vault and Refresh, which retains the search/filter. Explicitly review removal of selected keys
or clearing the agent, including keys loaded by other applications or vaults.
Automatic loading follows saved policies on every unlock, including login-keyring
unlock. Background loading does not reset the inactivity timer or block GTK;
foreground actions take priority. Closing a window in background mode keeps
keys available; locking the vault or quitting applies its removal policies.

The native SSH backend now reuses KeePassXC's KeeAgentSettings XML, OpenSSHKey
parser/encoder and SSHAgent client. It supports attached/external encrypted keys,
public-key/fingerprint preview without an agent, reviewed single-use add tokens,
confirmation/lifetime constraints, managed removal and cleanup after helper
shutdown. A separate native relay owns key cleanup when the vault helper is
killed; private-key transfer goes directly between native processes. The GTK
parent's relay control channel carries process IDs and cleanup status only.
The relay authenticates registered helper PIDs with peer credentials, refuses
cross-vault ownership conflicts. Ownership uses the socket device/inode so
symlinks and hardlinks share records; cleanup retains bounded canonical routes.
Automatic loading and cleanup preserve
pre-existing external identities.

Twenty-eight disposable-agent tests verify real Ed25519/RSA/ECDSA signing and
independent verification/tamper rejection, UTF16 KeeAgent settings, file/attachment
sources, per-use confirmation, lifetime expiry, cancellation/replay/stale/expired
tokens, interrupted adds, lock/EOF/SIGTERM cleanup, ownership, malformed inputs,
private socket permissions, framing/deadlines, startup reaping, abrupt relay failure
and explicit cleanup failure/retry.
No real user agent or key is used. Twelve controller tests cover asynchronous
startup/cancellation/retry, helper epochs, multi-vault scheduling and cleanup
warnings. A required real GTK gate checks settings, preview, add/cancel/sign/remove,
automatic reload, background retention, stale lock actions and application quit.
Removal reviews are single-use and expire after 30 seconds. They bind the vault,
selected public keys, ownership and socket identity. Changed key lists require
a fresh clear review. Removal uses individual key requests, preserving keys added
after removal starts, and reports partial or unconfirmed outcomes. Original key
files and vault entries stay unchanged. Replacing an agent socket also prevents
old cleanup records from removing keys from the replacement agent. If a vault
helper dies during removal, further external-key removals stop.

SSH file paths retain upstream `~/` and `$NAME` expansion, with cycle, substitution
and size limits to prevent an environment variable from hanging key loading.
Two additional required gates use unmodified GCR 4.4.0.1 and an actual OpenSSH
10.5p1 forwarding channel. They verify encrypted Ed25519/RSA/ECDSA signing with
independent verification/tamper rejection, borrowed-key preservation, alias
ownership, lock cleanup, reviewed removal and expiry. GCR runs in the Nix sandbox
with no user SSH directory. Forwarding uses a loopback server and test-only
`nss_wrapper` account data/home; host/client keys and configuration are disposable.
The NSS test library is not used by the application. Normal forwarding also
passes host acceptance. Hardware/security keys, GCR preload/keyring prompts and
broader agent disconnect/failure/platform acceptance remain unfinished. An abruptly killed
relay or an unavailable/refusing agent can leave keys loaded; cleanup failures
are reported and must be reviewed in the agent. Unconfirmed cleanup at quit sends
a desktop notification and an error to the launching terminal.

## Secret and file handling

Control messages use inherited stdin/stdout pipes between the frontend and helper. Passwords,
entry values, and unlock requests never appear in command arguments, environment
variables, shell commands, or the public Quick Settings D-Bus interface. The
helper retains the upstream composite key while unlocked. The frontend no longer
retains a master-password bytearray or receives a complete plaintext XML export.
Python/GTK and JSON parsers can retain temporary copies until collection; this is
not an audited secure-memory implementation.

Locking kills the helper, closes dialogs, clears visible metadata, and clears
the owned clipboard. Copied data expires after 20 seconds if the application
still owns the clipboard; clipboard managers may retain copies independently.
The extension receives only Locked/Busy/Background booleans and can request
Show, Lock or Quit. It never receives filenames or credentials.

The helper saves through upstream serialization into an encrypted staging file,
checks the original file for external changes, saves an encrypted mode-0600
`.keyslot.bak`, and commits with QSaveFile. Failed edits reload the original
before accepting another request. Creation uses a no-clobber link. Conflict
checks are optimistic; do not edit one file concurrently in multiple clients.
Killing a helper mid-save may leave encrypted staging directories behind.
Attachment bytes use selected input files and private output staging, so they no
longer pass through base64 JSON frames or have the former 40 MiB frontend limit.
The upstream engine's attachment-size bound still applies. Explicitly requested
plaintext exports also use parent-owned staging; cancellation removes unfinished
output even if the helper is killed. A whole-application or system crash can still
leave private staging directories. Database backups retain the previous unlock
key after key rotation.

## Verification

```sh
python3 -m unittest discover -s tests -v
# The development shell supplies the helper, both proxies, libsodium and fixtures:
nix develop --command env KEYSLOT_REQUIRE_ENGINE=1 python3 -m unittest discover -s tests -v
# Requires an accessible graphical session and the built helper:
dbus-run-session --config-file=tools/test-session.conf -- python3 tools/smoke-ui.py
```

Host results: all 188 tests pass (seven legacy backend, one upstream CLI installation, fifteen pipe-protocol,
twelve browser transport, twenty-four browser-vault, twenty-eight browser-request,
eight native-host registration, seven worker, ten startup, eight window-controller
eighteen real-core, four native passkey, six passkey transfer, twenty-eight SSH-agent and twelve SSH-controller tests). Ten gates cover backend, GTK, login keyring,
terminal signals, browser management, the encrypted browser workflow, GTK passkey/SSH management, GCR and actual agent forwarding. Checks
require the helper, packaged and unmodified proxies, libsodium and upstream fixtures.
The GTK smoke test covers CSV field mapping, character-restricted generation,
multiple database windows, duplicate-path selection, responsive navigation,
aggregate D-Bus state, window teardown and immediate preview clearing on lock.
Its private bus disables service activation to avoid launching host portals.
The login smoke test starts a disposable GNOME Keyring on a separate private bus;
it checks real credential storage, login unlock, GTK enrollment, removal,
autostart disable, preservation of a manual lock, short-password enrollment and
unlock, and the five-attempt fallback. The UI gate checks window hiding without
closing the vault and restoration. The companion's disposable GNOME Shell 50.4
test covers Background Apps visibility, deduplication, Open/hide/Quit and cleanup.
Manual GNOME 50 visual review is underway. Live Shell extension behavior,
physical hardware keys, accessibility and full compatibility remain unverified.

The native browser transport is a work in progress and explicitly enabled in Preferences.
`keyslot-browser` uses the pinned upstream BrowserMessageBuilder for browser
encryption and the official proxy's local-socket protocol. Only inherited
stdin/stdout pipes carry decrypted requests and authorization replies to its
parent. Tests use independent libsodium and both the packaged and unmodified
upstream proxies for crypto/interoperability checks, plus malformed inputs, replay rejection,
connection isolation, rekey cancellation, endpoint ownership and EOF cleanup.
It refuses an occupied endpoint and never replaces stock KeePassXC's socket.
Database Settings → Browser Integration now lists existing KeePassXC connections
and supports confirmed revocation. Native pairing/authentication uses the upstream
KPXC_BROWSER_ metadata and database hashes, preserves unrelated metadata, refuses
unconfirmed connection replacement and rejects stale authorization after external
changes. Upstream CLI export and reopen/import fixtures verify compatibility.
GTK tests cover confirmed/cancelled revocation and lock cleanup.
The native adapter reuses upstream URL matching, ranking, HTTP-auth restrictions,
entry/group policies and credential formatting without constructing Qt windows or
starting a socket. Lookup returns metadata only. Credential release requires a
single-use confirmation bound to the database object, file fingerprint, selected
entries, options and a monotonic 30-second deadline. Remembered allow/deny decisions
use upstream entry metadata. Pending confirmations are bounded. The GTK parent
owns a private helper settings directory and removes it even after killing the
helper; stock KeePassXC settings are never read or written. Tests cover consent,
revocation, edits/refresh, request isolation, expiration and capacity.
GTK pairing/site selection, credential routing, save/group confirmation and
reversible browser registration are implemented and pass the real encrypted
workflow. A scoped patch fixes the upstream proxy treating each socket read as a
complete JSON message: fragmented and combined replies/notifications are now
framed separately, with JSON validation, size/depth bounds and no partial output.
An unmodified upstream proxy is built separately for compatibility checks. Use
Keyslot’s Browser Setup registration to obtain the framing fix; the stock proxy
can combine a lock reply and notification into invalid JSON. Real browser-extension
acceptance remains open.

Closing the app window in background mode keeps `nix run` attached to its
terminal. Ctrl+C quits, locks/cleans up the vault helper and exits with status
130 without a Python traceback. The signal gate verifies that lifecycle in a
private graphical session using a disposable vault.

ZenPkgs has separate app and extension declarations. Source inputs currently
reference local sibling repositories. Publish and pin them before distributing
the catalog to another machine.

License: GPL-3.0-only. See `LICENSE`; the linked KeePassXC source retains its
upstream licenses and notices.
