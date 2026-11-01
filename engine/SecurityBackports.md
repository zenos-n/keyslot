# Pinned engine security backports

Historical2.7.12/Qt5 checkpoint. The current engine source/retained changes are
documented in [Native2.8 Migration](Native28.md); older patches are not applied
as a stack to2.8, and their historical verification is not reused as2.8 evidence.

Keyslot retains the reviewed KeePassXC 2.7.12 / Qt 5 API. `SecurityBackports.patch`
adapts the following upstream 2.8 fixes; it is not a claim of 2.8 feature parity.
Original upstream file headers and licenses remain in the patched source.
KeePassXC Team, Felix Geyer, Janek Bevendorff and Sami Vänttinen retain attribution.

| Upstream change | Keyslot adaptation |
|---|---|
| [Metastream lifetime, 6e65a36](https://github.com/keepassxreboot/keepassxc/commit/6e65a36b3ec61b58498bb3412a6ab8089d7f6491), [GHSA-4642-49vv-4p43](https://github.com/keepassxreboot/keepassxc/security/advisories/GHSA-4642-49vv-4p43) | Remove every UUID alias and the group mapping before deleting a legacy metadata entry. |
| [Legacy group length, 745faba](https://github.com/keepassxreboot/keepassxc/commit/745fabae8ca1feaff50a47b7d3bb65e882a341ee), [GHSA-rq29-wgrv-xgh4](https://github.com/keepassxreboot/keepassxc/security/advisories/GHSA-rq29-wgrv-xgh4) | Use 64-bit count arithmetic; also guard analogous custom-icon length/count calculations. |
| [Browser message bounds, 3e23bad](https://github.com/keepassxreboot/keepassxc/commit/3e23baddda5f1a5a5126dbe0d943698b6de839c9), [GHSA-3448-gh8j-3227](https://github.com/keepassxreboot/keepassxc/security/advisories/GHSA-3448-gh8j-3227) | Preserve 2.7 function signatures; allocate exact-sized vectors, enforce plaintext/wire/nonce/key bounds, reject invalid Base64 and return exact decrypted lengths. Existing Keyslot stream framing remains in use. |
| [Browser reference rejection, PR 13580](https://github.com/keepassxreboot/keepassxc/pull/13580), [nested placeholders, PR 13670](https://github.com/keepassxreboot/keepassxc/pull/13670), [deep references, PR 13688](https://github.com/keepassxreboot/keepassxc/pull/13688), [GHSA-2vm2-vmc3-vccr](https://github.com/keepassxreboot/keepassxc/security/advisories/GHSA-2vm2-vmc3-vccr) | Reuse the 2.7 Entry classifier with 2.8 balanced/nested matching in `KeyslotBrowserValues.h`. Reject browser-supplied expressions in both native save boundaries and return protocol error 34 before presenting consent. Existing locally authored references remain supported. |
| [Protected FDO attributes, d1dd8e7](https://github.com/keepassxreboot/keepassxc/commit/d1dd8e7dd93c02019a02d79ffdfd9cdd721cb3c7) | Skip protected attributes in upstream FDO metadata enumeration; Keyslot's separate provider already filters them. |
| [Zlib allocation, 2cfab3d](https://github.com/keepassxreboot/keepassxc/commit/2cfab3db2daa8dae95089d90d9d98d8681748f31), [Linux allocator detection, 541feb5](https://github.com/keepassxreboot/keepassxc/commit/541feb536eb231d32c9245ab7da9808a6a876ddd) | Export detected allocator features into the generated header; explicitly link the delete hooks into private native executables and route zlib allocations through them. |
| [History CustomData, 27984ff](https://github.com/keepassxreboot/keepassxc/commit/27984ff86f730292f6556fc9cce4e94f4fe172d5) | Copy CustomData in the existing 2.7 history snapshot path. |

The memory changes reduce residual decrypted buffers. They do not resolve all
Qt/XML memory retention or guarantee removal of every secret from process memory.

`SecurityCheck.cpp` is a mandatory build-time executable, never installed. It
checks message boundaries and malformed inputs, nested references, authenticated
encrypted legacy-file regressions, history metadata, and a wrapped `free` call
that observes bytes before deallocation. This is regression coverage, not an
independent security audit. Integration coverage also checks rejected browser
saves leave vault bytes unchanged and propagate error 34 over the encrypted
browser protocol without a GTK prompt. Exact successful builds are recorded in
the project coverage/release documentation after validation.
