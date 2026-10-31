# Production release requirements

Keyslot is still a development build. The latest x86_64 Nix flake check passes
323 backend tests and all 19 application gates. Native gates pass 332 checks in
the normal build and 331 under AddressSanitizer/LeakSanitizer. This candidate is
not yet the published package or a production replacement.

## Verified checkpoint

The [2.8 security backports](../engine/SecurityBackports.md) and
[serialization corrections](../engine/SerializationFixes.md) pass native and
application regressions. Coverage includes crafted encrypted legacy files,
browser crypto bounds/reference rejection/error 34, history metadata, effective
C++ deallocation scrubbing, XML attachment retention and stream-cipher boundaries.
The new KDBX4/Argon2id defaults and all 18 advertised KDBX4 cipher/KDF/compression
combinations pass, together with upstream KDBX3/4 encrypted-copy fixtures.

The actual upstream KeePassXC-Browser 1.10.4.1 on Chromium 155 passes pairing,
login fill, TOTP, generation, saving, groups and DOM WebAuthn create/get, including
independent signature verification. These results are regression evidence, not
an independent security audit or complete platform acceptance.

Frozen code artifacts: app `/nix/store/nhcfyvijijq2hgkq1zhlcv4vkrx07ky9-keyslot-0.2.0`,
engine `/nix/store/r5vl42yi221vg3jd7wvkxfwd4w8rad45-keyslot-engine-2.7.12`.
Full log: `/tmp/keyslot-production-security-final.log`; browser acceptance:
`/tmp/keyslot-production-real-browser-final.log`. Documentation was updated after
validation without changing runtime code.

The subsequent recovery/foreground-queue implementation also passes all existing
323 backend tests and 19 application gates, plus the existing 332 native checks.
No new tests or harnesses were added for that batch, as requested by the user.
Failed edits restore a verified encrypted pre-mutation snapshot; unavailable keys
retain an encrypted copy and report its location. Unexpected native failures
preserve completed snapshots. Background status polls can queue behind foreground
saves. The updated trial app is `/nix/store/z5ilm7zc1qxsbd82gfgxvf80a3na8pr4-keyslot-0.2.0`;
log: `/tmp/keyslot-recovery-build.log`. The running user instance was preserved.

The subsequent custom-attribute/reference-editing batch passes the same existing
323 backend tests, 19 application gates and 332 native checks. Attribute renames
preserve protection and history, reject collisions and guard reviewed edits
against database changes. The GTK picker inserts standard UUID references from
paged entry metadata without fetching passwords. No tests or harnesses were
added; the new picker interaction flow still needs manual desktop acceptance.
Trial app: `/nix/store/8sky8xic5gdys620sm44pj9i6rdx8fbj-keyslot-0.2.0`;
engine: `/nix/store/c163v5g0jf9pf66kdafyin1gx47i9z71-keyslot-engine-2.7.12`;
log: `/tmp/keyslot-reference-editing-build.log`. The trial profile was updated;
the companion extension and running user instance were preserved. This remains
a development build. Documentation was updated after runtime validation.

The generator batch adds upstream word-case/separator controls, installed/custom
word lists, 999-character/100-word limits, small-list warnings, strength/entropy
display, edited-result estimates and separate private settings containing no
generated results. The same existing 323 backend tests, 19 application gates and
332 native checks pass; no new tests or harnesses were added. Existing browser
protocol acceptance exercises the richer default-generator flow. Manual custom
word-list and edited-result acceptance remains open.
Trial app: `/nix/store/g9sjyg66mkk6lkn6ry5p8q7iqp6kbwna-keyslot-0.2.0`;
engine: `/nix/store/f64jvxamcjqcmfvg67chk5pzcypypj2i-keyslot-engine-2.7.12`;
log: `/tmp/keyslot-generator-options-build.log`. Only the trial app was updated;
the companion and running user instance were preserved. Documentation was
updated after runtime validation.

The GUI command-line batch passes the existing 323 backend tests and all 19
application gates, with the native engine unchanged from the verified 332-check
checkpoint. No tests or harnesses were added. The package now supplies a
`keepassxc` GUI launcher with lock, key-file, stdin, minimized and diagnostic
options. Manual use of upstream sample vaults in a private display/bus verified
primary and remote stdin unlock, multiple-file input including a missing file,
hidden background state, headless diagnostics/lock, terminal echo restoration,
and cancellation with partially typed input. A stopped-background-process issue
found during manual use was corrected by reading the TTY in the invoking process
group and forwarding only a pipe. Cancellation terminates that reader and flushes
unfinished input. Generator validation errors now stay on their form.
The core-dump guard runs before local option processing so the TTY reader also
inherits it. The final build passes the same existing checks.
Trial app: `/nix/store/kpg714h2941y13vj1c6ckhz67ryr529d-keyslot-0.2.0`;
unchanged engine: `/nix/store/f64jvxamcjqcmfvg67chk5pzcypypj2i-keyslot-engine-2.7.12`.
Logs: `/tmp/keyslot-gui-command-line-secured-final.log` and
`/tmp/keyslot-cli-manual-acceptance.log`. The packaged alias also ran headlessly.
Only the trial app was updated; the companion and user instance were preserved.
Broader key-component/terminal and actual GNOME lifecycle acceptance remain
open. Documentation was updated after runtime validation.

Explicit `--config`/`--localconfig` profiles now use the pinned Qt INI codec and
support `KPXC_CONFIG`/`KPXC_CONFIG_LOCAL`. Supported startup, timeout, integration
and generator settings are shared with KeePassXC; other keys remain in the INI.
Private manual use verified exact-second timeout import and reopening, generator
round trips, typed Qt values, nested option changes, stale-writer rejection,
read-only two-file preservation, repeated unknown QVariant rejection, same-file
roles, symlink guards and profile-bearing login launchers. A disposable desktop
verified primary/remote same-profile commands, changed-profile rejection,
environment defaults and graceful quit. The new engine passes the existing 332
native checks. The existing 323 backend checks and all 19 application gates pass
(backend 320.47 seconds); no tests or harnesses were added. All 37 packaged
Python files match the current source. App:
`/nix/store/pwh7h4fr60k93f5ag3y1jrnv494i8avp-keyslot-0.2.0`;
engine: `/nix/store/rdxhpdrdijldl6pmv8hvpy17bydv28im-keyslot-engine-2.7.12`.
Logs: `/tmp/keyslot-ini-profile-build.log`,
`/tmp/keyslot-ini-profile-final.log` and
`/tmp/keyslot-ini-manual-observations.txt`. This batch has not been installed or
published. A subsequent batch implements remembered key-file/hardware selections
and multiple-vault startup restoration in separate windows, with independent
recent-file/session/key-component settings, hidden background restore, keyring
unlock only for the enrolled vault and open-session persistence on quit. Private
GTK use verified prefilled key files and a real password-plus-key-file unlock;
remote stdin unlock used the remembered file, while an explicit missing file
overrode it and failed without overwriting the remembered choice. Two-window
startup/background restore, active-window persistence, missing-file filtering,
last-window close, independent remember flags and hardware-slot string conversion
also passed. A disposable GNOME login keyring unlocked only the enrolled vault
and kept both windows hidden; its enrollment path stays independent of the
focused window. Physical hardware-key use remains unverified. Existing package
checks passed for the restoration work; the enrollment-path correction was also
verified against the disposable keyring. No tests/harnesses were added. Evidence:
`/tmp/keyslot-session-manual-observations.txt` and
`/tmp/keyslot-remembered-session-final.log`. Remaining config migration includes
other unsupported preferences.

First-launch compatibility now reuses an existing stock INI profile when no
private preferences have been saved. Existing private settings are retained;
unreadable stock settings queue a notice and fall back without altering either
stock file. A read-only `GetConfigurationProfile` handshake returns an opaque
fingerprint and leaves the public status properties unchanged. Explicit requests
reject older or differently configured primaries before forwarding; ordinary
launches still attach to an older running app. Private real-primary acceptance
covered legacy rejection, automatic reuse across restarts/sidecar creation,
same/different profiles, private-setting preservation and unreadable automatic
versus explicit settings. The actual live legacy user's primary was also probed
read-only with aggregate state unchanged. All existing 323 backend checks and 19
application gates pass (backend 318.44 seconds); the native engine is unchanged.
No tests/harnesses were added. Source-only checkpoint:
`/nix/store/2fxh9h5a1v2j881yass1zd8j2qv0c9q6-keyslot-0.2.0`;
logs `/tmp/keyslot-profile-upgrade-build.log` and
`/tmp/keyslot-profile-upgrade-manual-observations.txt`. This work awaits the next
package batch. Legacy INI-key migration, remaining preferences and broader
concurrent-owner replacement/desktop acceptance remain open.

External-file monitoring now combines directory events (including atomic
replacement) with asynchronous metadata polling. Native revision checks are
passive; only a confirmed reload reserves the foreground worker slot. This
preserves browser/URI actions during ordinary checks and defers reload around
forms and file choosers. The native core keeps the current open data on reload
failure; persistent notices offer Reload or encrypted Save Copy. AutoReloadOnChange
is mapped to the GNOME preference and private settings. Actual GTK use verified
external changes, no redundant reload after own saves, preserved drafts and
stale-save refusal, manual reload/revert, missing/corrupt/changed-key retention,
official-CLI-readable recovery copies, actual chooser deferral, polling fallback,
unchanged idle time with an active search and cancellation on idle lock. The
existing browser and URL gates initially exposed foreground contention in checks;
the passive-check correction passes both unchanged gates and the final full
323-backend/19-gate package run (backend 324.20 seconds). No tests or harnesses
were added. Native engine 8ibf9x passes the existing 332 checks. Checked app:
`/nix/store/f01aszsr68nb0mlqjcnamv711v1kb4is-keyslot-0.2.0`;
logs `/tmp/keyslot-file-watch-verified.log`,
`/tmp/keyslot-watch-existing-regressions.log` and
`/tmp/keyslot-watch-manual-observations.txt`. Physical network/hardware behavior,
broader concurrent-source races and changed-key reauthentication remain open.

## Release blockers

- Complete the KDBX 3/4 cipher/KDF and key-component preservation matrix. Exercise
  interrupted saves, backup failure, concurrent writers, key rotation and
  recovery when the original source disappears during a failed mutation. Keep
  the last usable state available for encrypted recovery.
- Extend browser/session acceptance for concurrent foreground actions, denied
  and revoked permissions, cancellation/lock races and fresh authentication.
- Complete real GNOME 50 lifecycle acceptance: close-to-background visibility,
  explicit quit, screen lock, suspend/resume, login-keyring unlock, idle/Never,
  quick-unlock fallback, Wayland clipboard and auto-type portal permissions.
- Finish release packaging checks for independently installed app and extension,
  native-host discovery, upgrades and migration. Publish reviewed source commits
  and update the two ZenPkgs packages only after the release candidate passes.

Hardware keys and desktop interactions require actual hardware/session evidence;
an isolated GTK test does not substitute for those checks. Do not disturb the
user's open vaults or desktop session to perform acceptance tests.

## Replacement compatibility

The [coverage matrix](parity.md) remains the full replacement checklist. Security
backports retain the pinned 2.7.12/Qt5 API and do not implement all 2.8 features.
The [official 2.8 release](https://keepassxc.org/blog/2026-10-21-2.8.0-released/)
also requires review of remote database synchronization, configurable shortcuts,
SSH key generation, Linux Polkit quick unlock, browser entry listing, additional
Proton Pass record types, passkey/TOTP statistics and custom-attribute suggestions.
Existing gaps such as broader field-reference acceptance, breach reports, advanced
preferences, import/export coverage and accessibility remain open.

The supported target is Linux/GNOME; one window per database replaces tabs at
the user's request. Platform-specific Windows/macOS features must be explicitly
scoped rather than counted as implemented on GNOME.
