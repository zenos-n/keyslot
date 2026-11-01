# CLI compatibility backports

`CliCompatibility.patch` adapts these KeePassXC2.8 changes to the pinned2.7.12
native CLI and core without replacing Qt5 or changing the reported version:

- Database statistics count current passkey entries and entries with TOTP
  configured. `keepassxc-cli db-info` prints both fields with the upstream labels.
  The existing traversal excludes recycled groups/entries; historical entry
  versions are not counted. Empty-password entries and entries excluded from
  password reports still contribute to these two counts, as upstream does.
- Standard streams are assigned only after their `QFile::open` succeeds.
- Clipboard tools that start but return a failing exit code are included in the
  existing failure diagnostic, alongside tools that failed to start.

The source comparison used all67 files in the official2.8 CLI directory,
not the truncated first300 files of GitHub's whole-release comparison. The
command registry has no newly named commands. LineReader extraction, defaulted
destructors and Qt6 build/codec refactors are not needed to add the behavior
above; existing interactive commands and Qt5 encoding support remain in use.
This is a targeted backport, not a claim that all terminal/encoding/version
output or platform behavior has been proven identical to2.8.

The GTK launcher's `--config` and `--localconfig` now accept empty CLI values as
requests for their configured defaults, including `KPXC_CONFIG` and
`KPXC_CONFIG_LOCAL`, matching upstream's `Config::createConfigFromFile` factory.
An empty `KPXC_CONFIG_LOCAL` environment override disables separate local state;
explicitly naming the same file for both roles does the same. Empty CLI values
alone do not disable local state. Remote URIs still fail the local-file check;
the existing profile fingerprint handshake and symlink/layout guards remain.
No real settings or launcher is changed by compiling this update.

The backported code is by the KeePassXC Team, under the original GPL2-or-3 file
headers retained in the patched source. Keyslot's integration is GPL3-only.
Sources:

- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/DatabaseStats.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/DatabaseStats.h
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/cli/DatabaseInfo.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/cli/Utils.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp

Native/package/Python compilation only. No tests/harnesses or automated CLI,
statistics, clipboard, terminal, settings, GTK or vault behavior runs were added
or performed. Manual acceptance remains for live/recycled/history/passkey/TOTP
statistics, terminal and closed-stream errors, clipboard-tool failures, encoding,
empty/nonempty CLI/environment precedence, single-file mode, profile conflicts,
login-launcher refresh, relative paths and local-URI rejection.
