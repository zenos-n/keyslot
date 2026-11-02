# Replacement checklist and fixed candidate

This is the current finish list, replacing vague “advanced settings/import-export”
backlogs in older progress notes. It does not shrink the goal: the target remains
a GTK4/libadwaita GNOME HIG replacement for the Linux KeePassXC2.8.0 application,
including data, workflows, CLI and integration compatibility. Tabs are omitted at
the user's explicit request. GTK language work is **English, Polish and Romanian
only**; other languages are deferred by the user. English is the existing source
language, not a completed internationalization implementation.

## Fixed candidate

- App/code: `4a650938be4587fed5c39d34f3eb240958237120` (development0.2.0).
- Native release: KeePassXC2.8.0, upstream commit `1c2f23ef5914c0f442a00533def1689857afb5a7`, Qt6.
- Native build: `/nix/store/klxby7v877nhgcmniaysihg474fbwmvw-keyslot-engine-2.8.0`.
- App build: `/nix/store/wqllphhipchaznd5vvplrhnvzinvgjp9-keyslot-0.2.0`.
- Companion: `fcd5109e808d46a5f2056093a82993bb3d744479`, package0.3.0/metadata3, GNOME50.
- ZenPkgs checkpoint: `59e658d3ad228f0bf1b0e081aea0066c6c175615`; app and companion are separate packages.

On this PC, launch the pinned build:

```sh
~/.private/State/keyslot-candidate/result/bin/keyslot
```

Or obtain the same code using its fixed public revision:

```sh
nix run github:zenos-n/keyslot/4a650938be4587fed5c39d34f3eb240958237120
```

Fully Quit the older background Keyslot first: the shared application D-Bus name
otherwise forwards a new invocation to that old primary process. The agent has
not quit/restarted your app or loaded the companion. Installing a new companion
does not reload an already-running old extension.

The candidate has native/GTK/runtime/Python build evidence and static artifact
inspection:69Python source/bytecode modules and9native ELF executables. These
are not behavior/security acceptance. Historical2.7 automated results do not
prove this2.8 candidate. No new tests/harnesses, simulated logins or automated
vault/browser/GTK/input runs were added/performed for this handoff.

## Confirmed implementation work and compatibility decisions

Each item needs a concrete upstream requirement/source before it becomes code.
Do not add unrelated polish to this list. Completion needs implementation evidence
and user acceptance; compilation alone cannot close an item.

| ID | Remaining item | Source evidence / precise boundary |
|---|---|---|
| R01 | Implemented in newer development source; manual acceptance pending: KeeShare signer-name editing, fingerprint display and certificate regeneration | [Stock settings widget](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/keeshare/SettingsWidgetKeeShare.cpp); [Keyslot UI](../keyslot/keeshare_views.py) exposes group sync/import/export switches, while [native identity creation](../engine/KeyslotKeeShare.cpp) is private/automatic. Stock2.8 does **not** expose the identity import/export UI previously claimed as missing. [R01 implementation/limits](keeshare-identity.md); the frozen4a65093 candidate above predates this change. |
| R02 | GTK localization infrastructure and Polish/Romanian catalogs; English baseline | [GTK views](../keyslot/preferences.py) currently use English literals; no GTK gettext setup/PO catalogs. Only en/pl/ro are requested. Native core catalogs are separate existing upstream assets. |
| R03 | Resolve exact Qt/GLib Auto-Type sort compatibility | [Native model/view](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/autotype/AutoTypeMatchView.cpp) uses Qt locale/case sorting; [GTK chooser](../keyslot/autotype_views.py) uses GLib collation over casefolded strings. [Resolved display](autotype-display.md) is implemented; exact locale behavior is still unproven/divergent. |
| R04 | Stock backup enable/naming preference compatibility | Native keys `BackupBeforeSave`/`BackupFilePathPattern`; [current native saves](../engine/main.cpp) use fixed `.keyslot.bak` safety copies and [configuration schema](../keyslot/configuration.py) does not map these keys. Existing backups are implemented; the stock controls/semantics are missing. |
| R05 | Stock non-data autosave preference compatibility | Native `AutoSaveNonDataChanges`; [startup/config adapter](../keyslot/configuration.py) maps normal/exit autosave, but not this key. Audit non-data change call paths before changing save semantics. |
| R06 | Stock expiry warning after unlock and look-ahead preference | Native `GUI/ShowExpiredEntriesOnDatabaseUnlock` and `GUI/ShowExpiredEntriesOnDatabaseUnlockOffsetDays`; [unlock display](../keyslot/application.py) and [preferences](../keyslot/preferences.py) have no mapped warning hook/options. Manual expiry reports already exist. |
| R07 | Decide and map stock field double-click preferences into GNOME UI | Native `Security/EnableCopyOnDoubleClick`/`URLDoubleClickAction`; no corresponding [configuration keys](../keyslot/configuration.py). Existing copy/open actions are present. HIG layout differences need an explicit behavioral adaptation, not Qt widget duplication. |
| R08 | Finish the bounded stock-setting compatibility review | [All166fixed directives](settings-inventory.md) are enumerated:61literal/enum references,23dynamic-prefix candidates,82without a direct reference. None of those counts proves accepted behavior or82missing features. Classify each relevant key as supported, missing, GNOME adaptation, or outside Linux/en-pl-ro scope, with evidence. Dynamic action/entry/plugin settings also remain tied to the workflows below. |

R08 is a finite review queue, not an excuse to keep inventing features. The earlier
claim that only three implementation gaps remained was not an exhaustive audit.
Likewise “broader import/export fixtures,” network/hardware failure matrices,
accessibility review and platform acceptance are verification work until a
concrete absent behavior is identified. A faster offline HIBP algorithm is not
a new feature requirement without a demonstrated performance need.

## Implemented workflows awaiting current-candidate acceptance

“Present” below means source implementation exists, not production approval.
Every row remains unaccepted for the current candidate unless user evidence is
recorded. This is a user handoff list, not an automated test program.

| ID | Required workflow currently present | Source entry points |
|---|---|---|
| W01 | Create/open KDBX3/4; password/key-file/key-only/hardware composite keys | [Vault frontend](../keyslot/core_backend.py), [native engine](../engine/main.cpp), [auth UI](../keyslot/application.py) |
| W02 | Save/manual save, Save As, encrypted copies, interrupted-save recovery, changed-key reload | [Saving](../keyslot/saving.py), [file changes](../keyslot/file_changes.py), [native engine](../engine/main.cpp) |
| W03 | Entry/group create/edit/duplicate/move, tags/expiry/icons/colors/properties | [Entry UI](../keyslot/application.py), [properties](../keyslot/property_views.py), [native actions](../engine/KeyslotEntryActions.cpp) |
| W04 | Attributes, attachments, history comparison/restore, references | [Attribute UI](../keyslot/attribute_views.py), [history](../keyslot/history_views.py), [references](../keyslot/reference_views.py), [native history](../engine/KeyslotHistory.cpp) |
| W05 | Recycle/restore/permanent deletion, disabled bin, nested groups | [Trash UI](../keyslot/trash_views.py), [native trash](../engine/KeyslotTrash.cpp) |
| W06 | Multiple databases, cross-vault entry/group transfer and app-local drag/drop | [Transfers](../keyslot/transfers.py), [drag/drop](../keyslot/drag_drop.py), [native transfer](../engine/KeyslotTransfer.cpp) |
| W07 | Native query search, scopes/protected fields/recursive groups | [Search UI](../keyslot/search_view.py), [native engine](../engine/main.cpp) |
| W08 | Password/passphrase generation, character policies, custom word lists | [Generator](../keyslot/generator_views.py), [word lists](../keyslot/wordlists.py), [native engine](../engine/main.cpp) |
| W09 | TOTP standard/Steam/custom/legacy, current codes, QR and copy | [TOTP UI](../keyslot/totp_views.py), [native TOTP](../engine/KeyslotTotp.cpp) |
| W10 | Passkey management and browser WebAuthn create/get | [Passkey UI](../keyslot/passkey_views.py), [native passkeys](../engine/KeyslotPasskeys.cpp), [browser transport](../engine/BrowserTransport.cpp) |
| W11 | Browser pairing/forget/switch, fill/save/update/TOTP/generator/access rules | [Browser UI](../keyslot/browser_dialogs.py), [requests](../keyslot/browser_requests.py), [native database](../engine/BrowserDatabase.cpp) |
| W12 | Browser visibility/associations/additional sites/HTTP auth/auto-submit/www matching | [Browser options](../keyslot/browser_options.py), [native transport](../engine/BrowserTransport.cpp) |
| W13 | Owned regular/primary clipboard, expiry/Never, lock cleanup and portal Copy | [Clipboard](../keyslot/clipboard.py), [portal Copy](../keyslot/portal_clipboard.py) |
| W14 | Auto-Type matching/search, field actions, PICKCHARS, references, X11/Wayland focus/permission/session lifetimes | [Auto-Type UI](../keyslot/autotype_views.py), [native parser/executor](../engine/KeyslotAutoType.cpp), [portal connections](../keyslot/portal_connections.py) |
| W15 | SSH generation/import/agent constraints, external/managed agents, forwarding and cleanup | [SSH UI](../keyslot/ssh_views.py), [native SSH](../engine/KeyslotSSH.cpp) |
| W16 | Opt-in Secret Service collections/items/sessions/prompts and protected payloads | [Service](../keyslot/secret_service.py), [native secrets](../engine/KeyslotSecrets.cpp) |
| W17 | KeeShare group references/import/merge/export/polling and automatic persistent signing identity | [KeeShare UI](../keyslot/keeshare_views.py), [native KeeShare](../engine/KeyslotKeeShare.cpp); R01 covers missing identity controls |
| W18 | Merge/file synchronization and remote encrypted locations with explicit command approval | [Remote UI](../keyslot/remote_views.py), [native remote](../engine/KeyslotRemote.cpp) |
| W19 | XML/KeePass1/Bitwarden/1PUX/OPVault/Proton/CSV imports; XML/CSV/HTML/attachment export | [Database UI](../keyslot/database_views.py), [native engine](../engine/main.cpp) |
| W20 | Health/reuse/expiry/statistics/browser-permission reports and online/offline HIBP | [Reports](../keyslot/reports_views.py), [breach UI](../keyslot/breach_views.py), [native reports](../engine/KeyslotReports.cpp) |
| W21 | Cipher/KDF/history/compression/recycle/defaults and master-key rotation | [Database settings](../keyslot/database_views.py), [native engine](../engine/main.cpp) |
| W22 | Public keepassxc GUI/CLI/proxy commands, explicit/stock INI profiles and remote primary dispatch | [CLI adapter](../keyslot/command_line.py), [configuration](../keyslot/configuration.py), [native package](../engine/default.nix) |
| W23 | Lock/idle/Never/screen/suspend/user-switch, login-keyring background unlock, session PIN/Polkit | [App](../keyslot/app.py), [desktop lock](../keyslot/desktop_lock.py), [startup](../keyslot/startup.py), [system auth](../keyslot/system_auth.py) |
| W24 | GNOME HIG adaptive layout, row/dialog sizing, keyboard actions/help and accessibility | [Window UI](../keyslot/application.py), [shortcuts](../keyslot/shortcut_views.py); screen-reader/keyboard acceptance remains unproven |
| W25 | Separate ZenPkgs app/extension, MIME Open With, Quick Settings/background row/global shortcut editor | [Desktop file](../data/com.neg-zero.keyslot.desktop.in), [app packaging](../default.nix), [companion source](https://github.com/doromiert/keyslot-gnome-extension/tree/fcd5109e808d46a5f2056093a82993bb3d744479) |

## Completion rule

Full replacement remains **incomplete**. Close R01–R08 with evidence, record
current-candidate manual acceptance for W01–W25, and resolve concrete discrepancies
instead of converting “not exercised yet” into new feature development. Exact
format/protocol/data preservation and reported boot/lock confidentiality need
acceptance; a build or a manifest cannot substitute for that evidence. Physical
hardware, real login cycles, network failures and other clients need real user
acceptance under the user's no-new-automated-tests constraint. Keep unknowns
explicit. No production/100%-parity claim follows from this handoff.
