# Keyslot

GTK4/libadwaita client for KeePassXC databases, with a separate GNOME Shell 50
Quick Settings companion. Application and ZenPkgs identity:
`com.neg-zero.keyslot`. AppStream uses the normalized `com.neg_zero.keyslot`.

**Compatibility work in progress. This is not yet a drop-in replacement.**
The [coverage matrix](docs/parity.md) distinguishes source implementation from
verified behavior. The [release requirements](docs/release-readiness.md) track
production blockers and the upstream 2.8 security review. Broader Secret Service acceptance, breach/browser reports, several advanced database
workflows and broader platform acceptance remain open.

Auto-Type can now resume after unlocking a locked vault with the existing authentication providers, with a chooser for other open locked vaults that preserves the destination and original timeout. Its relock preference applies to vaults opened for that request. See [Unlock for Auto-Type](docs/autotype-unlock.md) for cancellation, Copy behavior and remaining manual acceptance.

Auto-Type chooser search now supports window-match filtering and native all-vault queries, including distinct custom association sequences. See [Chooser Search](docs/autotype-search.md) for scope, keyboard behavior and manual-acceptance limits.

## Native engine

Version 0.2 replaces the CLI boundary in the app with a private helper linked
against the actual **KeePassXC 2.7.12 core**. It does not reconstruct databases
from XML. The packaged source and dependencies come from the same pinned
Nixpkgs KeePassXC derivation; a version assertion prevents an unreviewed engine
upgrade. The old CLI adapter remains only for regression tests. New databases use
KDBX4 and upstream Argon2id defaults (64 MiB, 10 rounds). Existing databases keep
their configured KDF; required format upgrades follow upstream serialization rules.

The helper addresses entries and groups by UUID, so duplicate names and slashes
are no longer ambiguous. Its source supports clearing fields, multiline and
Unicode values, custom attributes/protection, TOTP configuration, entry expiry
and tags, group editing/moves/recycling, attachment import/export/removal,
history preview/comparison/restore/removal, and upstream search syntax. Database workflows include
metadata, compression, cipher/KDF settings and unlock-cost calibration; key-component
rotation, generated key files and key-file-only creation; upstream merge; XML/CSV/HTML
export; encrypted database copies and Save As; and local health/statistics reports. Failed refresh
keeps the current data open so it can be saved as an encrypted copy if the source
file is unavailable. These operations are wired into GTK
dialogs. Normal package builds compile the runtime only; development checks are opt-in.

Saving preferences support automatic saving or explicit Save (Ctrl+S), plus
save-on-close/lock. Manual edits remain in encrypted recovery checkpoints until
saved. Closing or quitting prompts when automatic saving on exit is disabled;
security locks clear the unlocked helper immediately and retain recoverable data
if the encrypted commit cannot complete. Reopening offers independent recovery
working copies. Save As (Ctrl+Shift+S) changes the active file and preserves the
previous file, with reviewed replacement and remembered-key/login migration.
External conflicts offer merge, discard/reload, copy or reviewed overwrite.
The main menu’s **Recover Unsaved Changes…** lists recovery copies even when the
original vault is missing or remembering vaults is disabled.

Recycle-bin actions include restoring entries or groups to their original
locations, a destination override, bulk restore, Restore All Contents and Empty
Recycle Bin in the bin's group editor. Delete reviews the exact selection and
all nested contents before recycling or permanently deleting; this also works
when recycling is disabled. Delete and Shift+Delete in the entry list request
normal deletion and explicit permanent deletion respectively. Permanent deletion
uses upstream deletion records so a later merge can recognize removed items.
These new workflows await manual desktop acceptance.

Database Reports includes statistics, password health, reused-password groups
and browser URL/Allow/Deny inventories. Entries can be included/excluded from
reports, and saved browser permissions can be cleared individually or for the
shown entries, with revision-bound confirmation. Protected URL fields stay hidden.
The exposed-password report checks an extracted HIBP SHA-1 corpus offline or,
after confirmation for that run, queries the
[padded HIBP range API](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange).
Password resolution, full hashes and result matching stay inside the native
helper. Checks report progress, cancellation, partial findings and retryable
network failures. Report refresh clears previous breach results. These new
workflows await user manual acceptance; no automated runs were added or performed.

The filter button beside Search controls whole-vault, selected-group and
selected-group-with-subgroups search, case sensitivity, password/protected
custom-field matching, recycled entries, disabled search groups and Enter-to-search.
Whole-vault results stay visible regardless of the selected sidebar group.
Browsing can include subgroup entries while keeping trash in its own group.
Scope, recursive browsing and Enter-to-search defaults are remembered separately
from query text and temporary switches. Explicit INI profiles share KeePassXC's
`SearchLimitGroup` and `GUI/SearchWaitForEnter` settings; Keyslot-specific browsing
defaults use its own namespace. These additions await user manual acceptance.

The icon picker can remove unused icons while retaining all current, historical,
recycled and open-editor references. Website-icon downloads review the sanitized
site/parent-domain addresses first, with optional path lookup and DuckDuckGo
service use. They send no saved credentials or browser cookies, bound downloads
and redirects, refuse HTTPS downgrades and preview the result before adding it.
Downloaded SVGs use the existing byte-only SVG conversion path; ICOs select the
largest supported frame. The stock favicon timeout and service defaults are read
from explicit profiles. These new workflows await manual desktop/network acceptance.

Browser requests for a favicon on a new login now appear as an optional switch
in the save-consent dialog. The credential save and browser response finish
first; queued icon work then uses the same separate network helper. It targets
the exact new entry through a native save-time website/icon reservation, defers assignment around open
editors, and cancels on lock, helper replacement or integration disable. Other
saves may continue, while website/icon changes or deletion protect the affected
entry from replacement. Icon failure keeps the saved login. Existing-entry
updates preserve their icons, matching the upstream browser behavior. This
addition awaits user browser/desktop acceptance; no automated runs were performed.

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

The development build passes 323 tests and nineteen package gates on the GNOME 50
host, including native X11 typing, GTK portal/focus/cancellation fixtures,
encrypted libsecret interoperability, icon/appearance editing and reviewed
cross-vault transfer, bulk operations, recursive groups, entry URL launching, history inspection and live TOTP/QR workflows.
Existing gates cover the backend, GTK, login keyring,
terminal signals, encrypted browser workflow, passkey/SSH management, GCR and
real agent forwarding. This verifies implemented workflows; full KeePassXC
parity remains open.
Separate host acceptance with unmodified KeePassXC-Browser 1.10.4.1 and sandboxed
Chromium155.0.8059.40 also passes pairing, DOM form filling, TOTP, generation,
saving, groups and DOM WebAuthn create/get with independent signature verification.

## One-time passwords

Configure an entry with a Base32 secret or an `otpauth://totp/` setup link. Choose
standard, Steam or custom settings, including SHA-1/SHA-256/SHA-512, code length
and period. Editing preserves upstream legacy/KeeOtp storage when possible;
custom legacy settings upgrade to an OTP URL. Removing setup requires confirmation
and also clears KeePass2 `TimeOtp-*` fields so it stays removed after reopening.

Reveal a live code in the entry row or open its separate window for a countdown
and progress bar. Passive refresh never resets inactivity lock. Codes disappear
on expiry, hide, selection change or lock; copying asks the native core for a fresh
code. The code window can also copy the resolved password followed by its code.
Repeated copies replace the clipboard provider directly, avoiding an X11
clear/reclaim race while retaining the owned-content timeout.

**Show Authenticator QR Code** displays a native-generated setup QR for 45 seconds.
Copy its setup link or explicitly save a private SVG file. QR/settings exports
are tied to the reviewed vault revision and fail after an intervening edit.
Custom/Steam settings may not work with every authenticator. Independent zbar
checks decode the generated PNG back to the exact upstream URI; RFC 6238 vectors,
clock boundaries, Steam, ten-digit arithmetic, invalid inputs and retained history
have native regression coverage. Broader authenticator and physical Wayland/desktop
clipboard acceptance remains open.

## Entry history

Open **View History**, then inspect a saved version to compare it with the
current entry or another saved version. Turn off **Only Show Changes** for a full
preview. Each field shows the selected and comparison values; passwords, custom
fields and sensitive settings require an explicit **Reveal**. Collapsing a field,
changing the comparison or closing/locking the vault clears revealed text.
Historical attachments can be saved without restoring the whole entry.

Restore, delete and delete-all require confirmation and a matching reviewed
database revision. Restore adds the previous current entry to history, subject
to the database's retention limits; deleting history keeps the current entry.
A changed vault must be reviewed again.

## Build and run

Requires Linux, Nixpkgs with KeePassXC 2.7.12, and a graphical session with GTK4,
libadwaita, PyGObject, and a session bus. The Nix package supplies runtime
libraries and the helper. Normal builds do not build or run tests.

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
Ctrl+G opens the generator; Ctrl+R refreshes; Ctrl+S saves; Ctrl+Shift+S opens Save As;
Ctrl+W closes the current window; Ctrl+Shift+L locks all databases;
Ctrl+Q quits and locks every database. With the default background preference,
closing a window hides it and keeps its vault available; disable background mode
to lock and close instead. Lock hooks cover configurable inactivity, GNOME screen
lock and logind suspend; real desktop acceptance of those hooks remains open.

Auto-Type settings are available for entries and groups. Window associations,
inherited sequences, native placeholders, modifiers, delays, TOTP and character
position picking use KeePassXC's parser. Ctrl+Shift+V opens the chooser; the GNOME
companion adds Ctrl+Alt+K. The chooser can search all unlocked vaults. X11 uses
the upstream executor. GNOME Wayland requests temporary keyboard access through
the desktop portal and uses an application-only companion interface to guard the
chosen window; changing focus revokes the typing lease. Portal event generation
is covered by a private fixture; real portal permission and input delivery still
need GNOME platform acceptance.

KeeShare settings are available for each group. Enable imports and/or exports in
Preferences to start checking configured share files every 30 seconds while their
vaults are unlocked. Standard encrypted `.kdbx` shares and legacy `.kdbx.share`
containers use upstream cloning/import/merge code. Legacy signatures are ignored
on import, as in KeePassXC 2.7.12. The helper stages encrypted input/output, rejects
the open database as a target and detects changes before committing an export.
Shares and expanded encrypted ZIP payloads are limited to 256 MiB. Signing identity
data stays in a private `keyslot/keeshare-identity.xml` under the configuration
directory. Exporting a synchronized group requires imports to be enabled first.

Each database has its own window, helper, key, view and worker queue. Opening the
same resolved path selects its existing window; opening another file keeps the
other databases available. Modal dialogs stay with their originating window.
Background results update that window, and inactive windows do not publish clipboard
results. Closing a window with background mode disabled stops its helper.
The public Quick Settings lock state
is aggregated: Locked means every database is locked, and Lock locks all databases.
There are no database tabs. Accessibility still requires manual GNOME acceptance.

Use **Copy or Move…** on an entry to choose an unlocked vault and destination
group, then review the operation. Cross-vault transfers use the pinned upstream
KDBX reader/writer and entry cloning, preserving protected fields, history,
attachments, icons and advanced metadata. Credentials and attachment contents
travel directly between authenticated native helpers; Python handles control
tokens and public review metadata. No transfer file is written to disk.
As in upstream KeePassXC, cross-vault copies and moves receive fresh entry UUIDs;
moving within a vault keeps its UUID. Field references remain as written and the
review warns when they need checking in the destination. A cross-vault move
saves and verifies the destination before removing the source entry. Failed or
unconfirmed cleanup is reported explicitly; check the destination before retrying
an uncertain transfer.

Entry and custom-attribute editors offer **Insert Field Reference** in their
header. Choose the destination field, search for an entry, and select which of
its fields to reference. The picker inserts the standard KeePass UUID reference;
it does not fetch the referenced password. Custom attributes can also be renamed
in place. An existing attribute with the new name is never overwritten by a rename.

Group editors also offer **Copy or Move Group…**, including nested and empty
groups, their entries, icons, history, notes, tags, expiry and group settings.
The review shows the total group/entry counts and warns that Auto-Type/KeeShare
settings are retained; review shared-file paths in the destination. The database
root cannot be transferred, and a group cannot be placed inside itself. Recycled
entries and groups support Copy or Move, Ctrl-copy and transfers between vaults;
Restore remains a separate original-location action. Destination recycle-bin
groups are labeled and warned about before approval. Local moves retain group
and entry UUIDs; copies and cross-vault moves assign new UUIDs, matching upstream
behavior. Local transfers honor Manual Save; transfers between vaults save the
destination before source cleanup, including existing unsaved changes.

Use the entry header's selection button, a hover checkbox, secondary click or
touch long press to select several entries. Selection mode shows checkboxes, a
count, Cancel and bottom actions for copy/move or recycling. Clicking toggles
selection; Shift-click selects a range. Ctrl+A and Ctrl+Shift+A in the entry list
select/deselect its visible entries, and Escape exits selection. Filtering never
includes hidden rows in a bulk action. Recycle confirmation is explicit and the
native operation saves the entire selection atomically; a failed save rolls it
back. Group transfers use the same saved-destination-first receipt as entries.
Touch hardware, screen readers and broader platform behavior still need acceptance.

The main header shows the database name. Navigation panes extend to the top of
the window, boxed lists fit their rows, and row actions stay vertically centered.
The generator offers lowercase, uppercase, numbers, symbol groups, additional
and excluded characters, look-alike exclusion and a require-each-group option.
It supports up to 999 characters or 100 passphrase words, word-case/separator
controls, installed and custom UTF-8/Diceware lists, and upstream strength and
entropy estimates. Small custom lists remain usable with the upstream warning.
Manage Word Lists imports a persistent copy beside the selected KeePassXC
configuration, so stock KeePassXC can use the same library. Duplicate names get
separate copies. Removal asks for confirmation and rejects changed files; the
original imported file is kept. Installed lists remain read-only. Imports use
the upstream parser and reject empty lists, with a warning below 1296 words.
Settings are remembered in a private `keyslot/generator.json`; generated results
are never saved there. Editing a result recalculates its password strength.
The package also supplies a `keepassxc` launcher for the GTK application, alongside
the pinned upstream `keepassxc-cli` with reviewed2.8 compatibility backports and
the corrected browser proxy. CLI `db-info` includes passkey and TOTP-entry counts;
stdio-open guards and failed clipboard-tool diagnostics match the newer source.
See [CLI Compatibility](engine/CliCompatibility.md). The core still reports its
actual2.7.12 version; these changes do not claim a complete2.8 CLI port.
The GUI accepts `--lock`, `--keyfile PATH`, `--pw-stdin`, `--minimized`,
`--version`/`-v` and `--debug-info`. Lock and diagnostics work without opening a
window. Stdin unlock reads one UTF-8 password line per database, including an
already-open or invalid database, with a 1 MiB limit per line. Terminal echo is
disabled while reading; lock or shutdown cancels pending input.
An empty password needs an explicit blank line; EOF without a line is an error.
Relative database and key-file paths use the invoking process’s directory. Generated passwords and
stdin credentials are never saved in application settings.
`--config PATH` and `--localconfig PATH` select KeePassXC global and local INI
files; `KPXC_CONFIG` and `KPXC_CONFIG_LOCAL` supply their defaults. Unspecified
global settings use the XDG config location; local state prefers KeePassXC2.8's
XDG state file, retaining an existing2.7 cache file when modern state is absent.
Empty CLI configuration values select the corresponding configured defaults.
An empty `KPXC_CONFIG_LOCAL` environment override, or choosing the same file for
both explicit roles, uses the global file for both roles.
See [Configuration Layouts](docs/configuration-layouts.md). Existing Keyslot private
preferences stay in use. On first launch, before private preferences have been
saved, Keyslot reuses an existing stock global/local INI profile automatically.
An unreadable stock profile produces a notice and private defaults, leaving the
original files intact. Ordinary launches reconnect to an already running app.
Explicit profile requests verify the running app's profile before forwarding;
older instances must be quit before using these options. The read-only handshake
returns a profile fingerprint, without configuration or vault paths.
Selected INI profiles share supported
remembered-vault, browser, idle/clipboard, auto-type, SSH, Secret Service and
generator options with KeePassXC. Keyslot-specific options use a separate INI
namespace. Unknown options are preserved by Qt; conflicting concurrent edits,
Qt decoding warnings and unsupported timeout ranges stop the operation without
replacing the original files. Login launchers retain explicit profile choices;
default-selected local paths are discovered again on launch.
INI profiles also restore `LastOpenedDatabases` as separate windows, with the
previously active vault selected and missing files skipped. Background startup
restores hidden windows; login-keyring unlock applies only to the enrolled vault.
The open-window list is saved on quit. `RememberLastKeyFiles` independently
controls key-file and hardware-slot choices in Qt's native dictionaries, including
stdin unlock and key changes. Explicit `--keyfile` arguments override remembered
files. Passwords and hardware secrets are never written to these dictionaries.
Other KeePassXC preferences and broader desktop/hardware acceptance remain open.

New-entry preferences support group-icon inheritance and optional automatic
password generation. The entry Generate button uses your saved generator
settings; its dropdown opens the full options without discarding the draft.
See [New-entry Defaults](docs/new-entry-defaults.md). These workflows await
manual acceptance; no new automated runs were performed.

Auto-Type includes username/password/TOTP/URL field actions, supported Enter
variants and selector Copy Field actions. Ctrl+Shift+V now types the selected
entry's sequence; global matching remains in the menu/companion shortcut.
Native flags drive field availability, including protected fields, without
fetching typing values into GTK. See [Field Actions](docs/autotype-fields.md)
for shortcuts, clipboard ownership and manual acceptance requirements.

Auto-Type supports stock always-show and selected-entry confirmation preferences,
including configured single-match execution, with one cancellable flow across
vaults. Selector approval no longer requires a redundant confirmation;
PICKCHARS, native focus/token checks and portal permissions remain.
See [Confirmation Preferences](docs/autotype-confirmation.md) for policy and
manual acceptance requirements.

Auto-Type can remember its last successful entry/sequence selection for0–60
seconds, with keyboard selection and Continue/Enter support. The setting uses
the stock INI key, and existing private Auto-Type settings retain their values.
See [Auto-Type Selection](docs/autotype-selection.md) for lifecycle, remaining
parity gaps and manual acceptance; this workflow has not been exercised here.

The desktop, window and welcome screen temporarily use the themed `keepassxc` icon.

Encrypted vault files are monitored for external changes, including atomic
replacements by sync clients. Asynchronous metadata polling also covers missed
filesystem notifications. The native core checks the ciphertext against its
current revision, so Keyslot's own saves do not cause another reload. Automatic
reload waits for jobs, forms and file choosers to finish, and preserves the open
database if the changed file cannot be opened. A persistent notice offers Save
Copy when the source is unavailable or cannot be reloaded. Preferences includes
Reload Changed Vaults; disabling it leaves a Reload action for external changes
and preserves native stale-write checks. INI profiles share `AutoReloadOnChange`.
Monitoring and the resulting search refresh do not count as user activity;
inactivity locking remains effective. Lock and Quit cancel monitors and pending
metadata requests.

Database entries and groups display KeePassXC's own standard/custom icons. Their
editors provide an icon picker with all 69 standard icons, custom-image import,
export and reviewed deletion. Deleting a custom icon replaces affected entry,
group and saved-version references with their defaults; cancelling preserves
the database. Images are normalized for previews, and original custom bytes can
be exported. SVG imports have no base URI and cannot load adjacent files.
Entry appearance includes text/background colors, URL-override metadata and
password-report exclusion. Group options include inherited search behavior,
tags and expiry. New entries inherit their group's icon. Favicon downloading
and remaining advanced options still need work.

**Open Entry URL** (Ctrl+U) uses the native KeePassXC placeholder resolver and Qt
URL normalization, then GTK's asynchronous URI launcher and your chosen handler.
It supports ordinary URI schemes and local files. A separate **Open URL Override**
action uses the entry's stored override: the pinned KeePassXC 2.7.12 normal Open
action does not read that metadata, so normal Open keeps the upstream behavior.

`cmd://` entries show a GTK confirmation with a masked preview. Protected fields,
nested references, conversions and TOTP are masked before preview expansion;
execution uses the real native values and Qt's argument tokenizer, without an
implicit shell. Remembered normal-command approvals use upstream `_EXEC_CMD`
and are revoked when the URL changes. Override approvals are separate and bound
to both URL templates. **Forget Command Approval** revokes them. Child standard
streams cannot write into the private protocol and internal helper variables are
removed from the child environment. Failed starts report an error and refresh
any saved approval state.

`kdbx://` opens another vault using its entry password and username/key-file path,
including relative paths, composite and key-only credentials, and legacy empty
password keys. Credentials are authenticated/encrypted between the native
helpers using upstream browser crypto; Python carries the sealed packet. Target
and key-file fingerprints are checked before and after opening. An already-open
vault is selected, and failed credentials fall back to its unlock screen.
Locking cancels pending launches and prevents late helper results from opening a
vault. Linked openings update the remembered path; automatic login-keyring
enrollment of the linked credential remains unfinished and currently requires
explicit enrollment through Preferences. **Preferences → Window Behavior**
controls minimize after opening links or unlocking, and minimize/lower after
copying entry data. **Hide Instead of Minimize** hides the origin window only
when Run in Background is enabled; otherwise it minimizes. Lowering requires
companion version2/package0.2.0. See [Window Behavior](docs/window-behavior.md)
for stock settings mappings, cancellation rules and pending manual acceptance.

## Entry actions

Duplicate Entry creates a new UUID in the same group, with options for the stock
title suffix, username/password references and copying history. Attachments,
icons, passkeys, one-time password setup and custom settings are retained.
Selection mode’s additional actions add or remove one tag across selected entries
and set expiry to now, Never or a reviewed timestamp. The native review fixes the
selection and choices before confirmation; changed vaults or expired reviews are
refused. Changed entries save together through the existing encrypted transaction
and history model, and no-op tag/expiry changes avoid another save.

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
KeePassXC-Browser extension. Keep Keyslot running. Its dedicated browser endpoint
also works while official KeePassXC is running. The preference
shows when the listener is ready. **Configure…** registers selected Firefox,
Chrome, Chromium, Brave, Vivaldi, Edge, Tor or Gnosis installations with the packaged
`keyslot-browser-proxy`, including a socket-message framing fix. Replacing an existing registration requires confirmation;
disabling that browser restores its original file. Registrations changed by
another application are preserved, with an error rather than silent replacement.
The package exposes `keyslot-browser-proxy`, a compatibility `keepassxc-proxy`, and the unchanged upstream `keepassxc-cli`
on PATH. Its proxy launcher clears inherited browser GUI library paths so wrapped
Nix browsers cannot load incompatible libraries into the native host. Owned browser
registrations refresh to this launcher when Keyslot starts.

In Gnosis, open **hamburger menu → Password Manager** to select Keyslot or
KeePassXC. **Forget Browser Connections…** removes saved pairings from that
Gnosis profile, with confirmation; vault entries are kept. You can then connect
again and approve a new pairing in Keyslot.

Connect from KeePassXC-Browser and approve the database connection in Keyslot.
Site requests show the origin and matching entry names/usernames; select which
entries to share. Remembered allow/deny decisions stay inside the encrypted
vault using upstream metadata. Database Settings → Browser Integration reviews
and revokes connections. Lock, disconnect or rekey cancels outstanding prompts.
Browser polling does not extend the inactivity timeout or disable the window.

Preferences → Browser Integration → Allow Browsers to List All Entries enables
KeePassXC 2.8’s `get-database-entries` operation. It is off by default and uses
the shared `Browser/AllowGetDatabaseEntriesRequest` setting. Enabling it confirms
the broader permission: any authenticated paired browser may receive entry
titles, UUIDs and resolved website fields, including entries hidden from normal
filling. Field references can reveal protected values. The request uses upstream
entry ordering and recycle-bin traversal, returns standard errors for denial or
an empty list, and refuses oversized output without truncation. Permissions are
re-read before and after enumeration; polling does not reset inactivity.

Entry Details → Browser Settings controls browser visibility, automatic form
submission and HTTP authentication. Edit Group → Browser Integration adds
inherited rules, www matching and restrictions to a paired browser connection.
The controls show when a group rule takes precedence. Disconnected restrictions
stay visible until explicitly changed; allowing all connections is distinct from
inheriting a parent restriction. Saving refuses a changed vault revision and
preserves unrelated custom data and entry history.
Additional Websites in the same entry section adds, edits and removes matching
websites. Protected addresses stay masked until edited and revealed, and literal
placeholders/references are retained. Changes use the same revision and history
guards as custom attributes.

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

Secret Service is opt-in under **Preferences → Secret Service**. Choose the
group to expose under **Database Settings → Secret Service Exposed Group**;
other groups and recycled entries remain unavailable. Enabling the provider
does not replace an existing GNOME keyring service. A conflict is reported with
a retry control. Login-unlock credentials remain bound to the GNOME login
collection and cannot be saved back into Keyslot's own provider.

The provider implements collections, items, aliases, peer-owned sessions and
GTK prompts. Plain and encrypted DH/AES sessions use the native upstream cipher;
encryption keys stay in the helper. Entry access can be allowed once or until
that client disconnects. A one-shot approval allows one password read and one
one-time code read, so metadata loading cannot consume the password permission.
Creation, replacement and deletion use separate
reviews. Locking removes grants and discards pending credential replies.
Disabling the provider releases its bus name without closing vaults. Native
fixtures and a real libsecret/private-bus GTK gate cover encrypted store, lookup,
update, delete, denial, independent clients, binary values and lock races.
Additional real-client checks create an encrypted vault through the GTK
master-credential form, cancel and complete collection closure while preserving
its file, and verify TOTP, metadata-cache updates and access-policy revocation.
Multi-vault replies share a 24 MiB bound; clients can request smaller batches.
Broader client and desktop interoperability acceptance remains open.

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

Host results: all 323 tests pass. Nineteen gates cover backend, GTK, login keyring,
terminal signals, encrypted browser workflow, GTK passkey/SSH management, GCR,
actual agent forwarding, auto-type/X11, encrypted libsecret, icon/appearance
editing, reviewed cross-vault transfers, bulk/group workflows, URL activation, history comparison and live TOTP/QR workflows.
The bulk/group gate
uses real pointer events in a private Xvfb to verify hover checkboxes, row toggles,
Shift ranges and secondary selection, and runs serially to avoid input conflicts.
The URL gate uses an actual URI handler under private XDG config/data directories,
command consent/remember/revoke, failed starts, linked-vault handoff/deduplication,
manual fallback, minimize settings and late-lock cancellation. The history gate
checks any-version comparison, on-demand reveal/hide/collapse, historical attachment
export, reviewed restore/delete-all, rapid selector changes and late-lock cleanup.
The serial OTP gate also checks actual clipboard replacement/foreign-owner
preservation, passive polling without extending idle lock, setup/removal review,
QR expiry/export and late replies after selection/hide/idle lock.
Plain XML with an encrypted-value marker is rejected before dereferencing a missing
inner stream; valid ProtectInMemory imports retain their field flags. Checks
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

ZenPkgs has separate app and extension declarations with independent published
source pins.

License: GPL-3.0-only. See `LICENSE`; the linked KeePassXC source retains its
upstream licenses and notices.

## Keyboard shortcuts

Preferences → Keyboard Shortcuts edits application and entry actions. Record a
combination, resolve conflicts, disable an action, or restore its default; Save
applies the staged changes to all windows. The shortcuts help follows the active
bindings. Common entry actions now include edit, duplicate, delete, username,
password, website and TOTP copying. Ctrl+U copies a website; Ctrl+Shift+U opens it.
Entry actions yield to text editing and open dialogs. The desktop auto-type
shortcut remains in the auto-type preferences.

With a KeePassXC configuration profile, shared actions use its `Shortcuts` keys;
Keyslot-only actions use their own namespace. Reset removes only the selected
override, retaining unrelated settings. Unsupported platform keys and manually
authored multi-stroke sequences are preserved but disabled here until changed.
The editor records one combination per action. These additions have runtime
compilation only; desktop and keyboard-layout acceptance remain manual.

## Adwaita entry icons

Standard KeePass icons are displayed with GNOME/Adwaita equivalents while their
database icon IDs stay unchanged. Existing custom icons retain their image.
In Edit Entry → Icon, choose Adwaita Icons to search the symbolic icon catalog.
Standard equivalents select their KeePass ID; additional choices are embedded
as normal custom icons for other clients, with an `Adwaita:` name marker so
Keyslot can show a theme-aware version after reopening. Adwaita assets are part
of the package. The search-options popover also uses an available Adwaita icon
and a wider, window-aware content size.

The startup unlock handoff now dismisses a pending manual prompt before login
keyring unlock begins, and successful rendering clears obsolete unlock prompts.
Locks hide sensitive content immediately; stale or locked snapshots cannot
repopulate the vault view. This addresses a reported screenshot showing vault
metadata behind an unlock prompt. Password copying/autofill before manual input
was not established, and no live startup reproduction was performed. These
changes have runtime compilation only, with manual acceptance pending.

## Proton Pass imports and attribute suggestions

Proton Pass JSON import also supports Wi-Fi and SSH-key records. Unknown record
content is retained as protected attributes, with structured values represented
as JSON. Extra-field TOTP seeds stay protected; duplicate or unnamed fields
receive distinct names. Existing login, card, note, vault and timestamp handling
is retained. Import these through Import Database and its normal review flow.

Custom Attribute → Name now offers a suggestion menu with names used by other
non-recycled entries. It searches names without reading their values and
excludes names already on the current entry. Free-form entry remains available.
Preferences → Editing → Suggest Attribute Names controls it and shares
KeePassXC's `AutocompleteSuggestions` setting for selected profiles. These
changes have runtime compilation only; manual import and desktop acceptance
remain pending.

## Generate SSH keys

Open an entry's SSH Key Settings and choose Generate New SSH Key. Select
Ed25519, RSA or ECDSA, choose an attachment name and review the public key before
saving. The key can be protected with the entry's current password; the password
stays unchanged. Without that option the private key has no separate passphrase
and relies on the encrypted vault. Private key material remains in the native
helper until saved to attachments.

Saving adds a private key and `.pub` attachment, and selects the new private
attachment in KeeAgent settings. Existing attachments/files and SSH-agent
policy are kept; loaded agent keys are unchanged. Agent integration can remain
disabled during generation. Use the existing attachment actions to export files
or the public-key preview to copy a public key. A review expires after two
minutes or when the vault changes. This batch has runtime compilation only;
manual OpenSSH and desktop acceptance remain open.


Remote synchronization is available under **Main Menu → Database → Remote Synchronization…**.
Named locations use the KeePassXC 2.8 encrypted settings format and reviewed
foreground download/upload commands. Sync saves local edits before upload;
provider atomicity and concurrent remote writers still require care. See
[workflow, attribution and limits](engine/RemoteSynchronization.md). This
candidate has compilation evidence only and awaits manual acceptance.

**Entry Properties…** in entry details and the **Group Properties** button in the
Groups header show identity, timestamps, counts and plugin data. Plugin values
are fetched only on explicit inspection/copy; selected plugin data can be removed
after native revision-bound review. See [properties and limits](engine/Properties.md).
This candidate has compilation evidence only; manual acceptance remains pending.

**Preferences → Security → System Authentication** now offers session-only Linux
Polkit unlock, using an encrypted native broker and private process keyring.
The packaged action must be installed system-wide; `nix run` alone cannot install
it. Read [requirements and limits](engine/PolkitUnlock.md). Native vault helpers
still die on lock. This candidate has compilation evidence only and awaits
manual GNOME authentication/lifecycle acceptance.

## Drag and drop

Drag entries or groups to a sidebar group; hold Ctrl to copy. In selection mode,
use an entry's grip to drag the selection. Drop a group near a row's upper/lower
edge to position it among siblings. The destination window asks you to review
the move or copy. Recycle-bin drops use the existing recycle/restore review.

Drop local `.kdbx` files on the window to open them, or regular files on an
entry's Attachments section to review a batch. Matching attachment names require
explicit replacement consent. Batches allow 32 files/256 MiB; larger individual
files can use Add Attachment. [Implementation and limits](engine/DragAndDrop.md).
This candidate has compilation evidence only; pointer/desktop acceptance is pending.

Recycled items can use **Copy or Move…** directly, including transfers to another
vault and groups inside a recycle bin. **Restore…** remains available for the
original location or a chosen ordinary group. Reviews distinguish recycled
sources and destinations, and explain permanent source cleanup for cross-vault
moves. The native helper saves the destination before removing any source items.
This extension has compilation evidence only; manual acceptance is pending.

Whole recycle-bin groups and containing ancestors can also be copied/moved.
Moving within the same vault preserves the designated bin. Copies into another
vault are ordinary groups unless placed in its bin, and do not replace its
bin metadata. Cross-vault moves review source-bin removal and create a fresh
source bin when next needed if recycling remains enabled.

## Automatic desktop locking

Preferences → Automatic Locking now includes screen lock/suspend, switching
users and minimizing/hiding a window, alongside inactivity/Never. Settings map
to KeePassXC INI profiles and private preferences. Minimize/hide locking uses
the remaining owned clipboard lifetime with a 1–20 second grace, then locks all
vaults. Screen/suspend and user-switch default on; minimize/hide defaults off.
[Monitoring and manual-acceptance limits](docs/desktop-locking.md).

## Entry preview privacy

Preferences → Entry Privacy can hide usernames and notes, configure password
preview visibility, mask empty passwords and use monospace notes. Hidden detail
fields have individual reveal controls. Password fields stay masked by default;
only requested preview fields leave the native helper. Notes have a rounded,
scrollable read-only view. Long previews show a truncation notice; Copy retrieves
the complete native field. [Details and manual acceptance](docs/entry-privacy.md).
