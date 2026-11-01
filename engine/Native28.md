# KeePassXC 2.8 / Qt 6 native core

The migration uses the official 2.8.0 release commit
`1c2f23ef5914c0f442a00533def1689857afb5a7`, fetched with fixed unpacked hash
`sha256-821zL+xnCsHU8VvxsJh2a2LRGstSIq3tWQbWBk8g4hc=`. Dependencies still
come from the reviewed Nixpkgs lock; the engine recipe now explicitly selects
Qt6 rather than inheriting the distribution's2.7.12/Qt5 package. The visible
application is GTK4/libadwaita. Private helper/CLI/proxy binaries link the real
upstream core and retain their existing JSON protocol and opt-in integrations.

`CORE_VERSION` pairs the GTK client's strict handshake and version/debug output
with this source. Icons and all root LICENSE.* files are taken from the matching core source. A
mixed old/new native helper must fail the handshake before opening a vault.

## Upstream fixes and retained Keyslot changes

The earlier 2.7 backport patches are historical checkpoints. `Native28.patch`
is generated against the exact 2.8 release and preserves upstream attribution.
It is applied once; the older patches are not stacked onto2.8.

| Area |2.8 migration |
|---|---|
| Legacy metadata lifetime | Upstream cleanup retained; remove every UUID alias, as in Keyslot's previous boundary guard |
| Legacy count arithmetic | Upstream64-bit group check retained; Keyslot's analogous icon/entry/group bounds retained |
| Allocator/zlib clearing | Native 2.8 implementation and generated allocator feature macros; private binaries still link Alloc.cpp |
| Browser message bounds | Native 2.8 bounded crypto/messages; existing Keyslot buffered framing/socket handling and alias isolation retained |
| Browser placeholder rejection | Native 2.8 classifier with the existing whole-input REF and nested-wrapper boundary checks |
| Protected FDO metadata | Native 2.8 protected-attribute filtering; Keyslot's independent provider/reveal guards remain |
| History CustomData | Native 2.8 copyDataFrom history path, including CustomData |
| CLI statistics/stdio/clipboard errors | Native 2.8 implementation replaces the compatibility backport |
| SSH generation | Native 2.8 generator, including check values; the2.7 compatibility copy is no longer substituted |
| XML/stream serialization | Keyslot's empty stream-finalization fix, standalone XML binaries and missing-inner-stream error retained |
| TOTP bounds | Existing digit/step bounds retained |
| Remote sync settings | Native 2.8 protected key plus existing Keyslot merge exclusion; local trusted locations are preserved |
| KeeShare containers | Existing bounded ZIP expansion and filesystem-safe names retained |
| Passkey consent | Existing confirmed flag prevents the native Qt prompt after GTK approval |
| Proton Pass | Upstream Wi-Fi/SSH branches used once; protected structured unknown content, unique extra-field names and extra-TOTP protection retained |
| Auto-Type | Native 2.8 parser/executor with Keyslot PICKCHARS callback and headless X11 guards; no Qt GUI singleton is required to own an X display |

Qt6 changes include QKeyCombination key/modifier extraction, qsizetype-safe
pagination, QStringConverter CSV validation, EntryPlaceholders reference APIs,
UrlTools namespace/header and the existing X11 executor reference. The X11
platform is linked once from the native static library and its executor is
released on destruction, including failed display initialization.

The split native static archives have circular GUI/Auto-Type/browser/Secret
Service/KeeShare/SSH references. CMake RESCAN groups resolve those archives for
the private helpers and official CLI. These are linked runtime dependencies;
no stock Qt window is launched by the build. Package-local qt6.conf supplies
trusted QtBase/SVG plugin paths while keeping helper/broker executable identities
as ELF files. No shell wrapping is introduced for authenticated helpers.

CSV codecs are validated against the Qt6 parser's encoding enumeration before
calling it. Unsupported legacy codec names are rejected rather than silently
falling back to UTF-8. Existing mapping, protected review and imported-data
semantics still require manual acceptance across native versions.

Runtime/native/Python compilation only. No tests/harnesses added or run, no
sanitizer/runtime/CLI/GUI/vault/clipboard/browser/passkey/TOTP/hardware/Polkit/
keyring/portal/SSH/Secret Service behavior execution, no live app/profile/config
or system activation. Historical 2.7 test results do not establish2.8 behavior.
Manual acceptance is required for every existing workflow, data-preservation
boundary and protocol, including old/large/corrupt files, encodings, saved
profiles, authentication and cancellation/recovery, both display backends and
all browser/passkey integrations. GTK feature gaps documented in the parity
matrix remain separate; compiling the2.8 core does not establish full replacement
parity or production readiness.

Sources: KeePassXC Team/Felix Geyer and file-specific upstream authors,
GPL2-or-3; Keyslot's independent integration is GPL3-only.

- https://github.com/keepassxreboot/keepassxc/releases/tag/2.8.0
- https://github.com/keepassxreboot/keepassxc/tree/1c2f23ef5914c0f442a00533def1689857afb5a7
- https://doc.qt.io/qt-6/qkeycombination.html
- https://doc.qt.io/qt-6/qstringconverter.html
- https://doc.qt.io/qt-6/qt-conf.html
- https://cmake.org/cmake/help/latest/manual/cmake-generator-expressions.7.html#genex:LINK_GROUP
