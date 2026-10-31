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
Custom configuration migration, broader key-component/terminal and actual
GNOME lifecycle acceptance remain open. Documentation was updated after runtime
validation.

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
