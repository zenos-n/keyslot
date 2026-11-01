# KeePassXC configuration layouts

The global INI defaults to `$XDG_CONFIG_HOME/keepassxc/keepassxc.ini` or
`~/.config/keepassxc/keepassxc.ini`. The default local state file is selected
in this order:

1. An existing `$XDG_STATE_HOME/keepassxc/keepassxc.ini`, using
   `~/.local/state` when the base directory is unset or empty. This is the
   KeePassXC2.8 Linux layout and wins when both layouts exist.
2. An existing legacy `$XDG_CACHE_HOME/keepassxc/keepassxc.ini`, using
   `~/.cache` when unset or empty. Existing2.7 installations continue in place.
3. The modern state path when neither file exists.

Empty or relative XDG base-directory variables use their standard defaults;
relative paths are not interpreted under the launching directory. The same
config-home rule now applies to Keyslot's private startup/profile directories.
Discovery checks directory entries without following the final symlink, so a
broken modern link does not silently select an old cache file. Broken links and
path-check errors produce an error/notice through existing configuration error
handling. Settings contents are still decoded by the pinned native Qt codec;
unsupported values and decoding warnings remain explicit errors.

`--config` and `--localconfig` take precedence over their corresponding
`KPXC_CONFIG`/`KPXC_CONFIG_LOCAL` environment defaults. Explicit local paths skip
default state/cache probing entirely, including inaccessible unused defaults.
An explicitly empty local override (including `--localconfig=`) disables the
separate local file: both roles use the selected global INI, matching upstream
single-file settings behavior. An empty global override is rejected. CLI remote
URIs are rejected with a configuration error rather than an internal exception.
Relative explicit file paths retain their existing invoking-directory semantics.

First-launch stock-profile adoption still requires an existing global file
and no saved Keyslot private preferences. Ordinary secondary launches keep the
running primary's profile. Explicit requests keep the existing fingerprint
handshake and require a restart before changing active profile paths.
Unreadable auto-discovered profiles fall back to private defaults with a notice;
explicit profile errors stop that request. No existing file is moved, copied,
deleted or merged by layout discovery. Normal explicit settings saves use the
selected file and existing guarded Qt INI update path.

Automatically selected local paths are checked before and after native settings
I/O. A legacy-to-state move or other change in the authoritative default path
requires quitting and reopening Keyslot, instead of silently switching its
profile while vault windows are open. Existing symlink-retarget checks remain.
If a change is detected after a write, the error states that the settings may
already have reached the old location. These are best-effort checks, not an
atomic filesystem-wide migration lock; another process can race between them.
Per-file concurrency guards and unknown-key preservation remain unchanged.

Newly generated login launchers retain an explicit global profile but omit
`--localconfig` for default-selected local state, allowing discovery again after
a layout move. User-selected local overrides and single-file profiles stay
explicit. Older launchers that already contain an explicit `--localconfig`
remain explicit: reopen without that override and re-enable login unlock to
adopt default discovery. This update does not rewrite a user's launcher or
settings outside the application's normal preference save/launcher refresh.
Vault credentials stay in the existing login-keyring workflow.

References: upstream configuration behavior is GPL2-or-3; Keyslot's adapter is
GPL3-only. This adds layout compatibility without changing the native2.7.12
core or claiming every Qt6-encoded2.8 setting has been accepted.
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/core/Config.cpp
- https://specifications.freedesktop.org/basedir/latest/

Package/Python compilation only. No tests/harnesses or automated path/profile/
INI/login/vault/GTK behavior runs were added or performed, and no real user
settings, launchers or session were changed for this update. Manual acceptance
remains for fresh/legacy/modern/both layouts, overrides and single-file mode,
empty/relative environment variables, symlink/permission errors and races,
concurrent stock app migration, login launcher refresh, Qt encodings, startup
fallback, profile handoff, config conflicts and real desktop login behavior.
