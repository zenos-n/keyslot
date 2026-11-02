# Fixed upstream settings inventory

Frozen against KeePassXC2.8.0 `src/core/Config.cpp` and Keyslot code
`4a650938be4587fed5c39d34f3eb240958237120`, 2026-11-02.
This enumerates every directive in that source file's `configStrings` map,
including platform-specific entries. It is a bounded source-review queue,
not an automatically inferred missing-feature list.

**Literal/enum reference** means implementation source mentions the INI key
or its upstream enum. It does not prove a GTK control or behavioral parity.
**Dynamic prefix candidate** means the suffix exists and Keyslot constructs
that namespace dynamically; review is still needed. **No direct reference**
means no exact match was found, not that the behavior is necessarily absent:
private preferences, inherited defaults and GNOME adaptations can differ.
No row is marked behaviorally accepted by this inventory. Unknown keys being
preserved in an INI file does not prove that their behavior is implemented.
Do not promote an unmatched row to feature work without a call-path and
Linux-platform review.

This map is not all of KeePassXC: dynamic shortcuts, per-database/entry metadata
and integration protocols are covered as workflows in the
[replacement checklist](replacement-checklist.md). Qt toolbar/menu controls
need explicit GNOME adaptation decisions rather than blind widget duplication.
GTK translation scope is English, Polish and Romanian only; other languages
are deferred by the user.

Directives: **166**. Literal/enum references: **61**; dynamic-prefix candidates: **23**; no direct reference: **82**.

| INI key | Enum | Upstream source | Review status | Keyslot trace |
|---|---|---|---|---|
| `SingleInstance` | `SingleInstance` | [native:56](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L56) | no direct reference; review | — |
| `RememberLastDatabases` | `RememberLastDatabases` | [native:57](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L57) | literal/enum reference | [keyslot/configuration.py:61](../keyslot/configuration.py#L61), [keyslot/configuration.py:319](../keyslot/configuration.py#L319) |
| `NumberOfRememberedLastDatabases` | `NumberOfRememberedLastDatabases` | [native:58](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L58) | literal/enum reference | [keyslot/configuration.py:63](../keyslot/configuration.py#L63), [keyslot/configuration.py:328](../keyslot/configuration.py#L328) |
| `RememberLastKeyFiles` | `RememberLastKeyFiles` | [native:59](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L59) | literal/enum reference | [keyslot/configuration.py:62](../keyslot/configuration.py#L62), [keyslot/configuration.py:226](../keyslot/configuration.py#L226) |
| `OpenPreviousDatabasesOnStartup` | `OpenPreviousDatabasesOnStartup` | [native:60](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L60) | literal/enum reference | [keyslot/configuration.py:61](../keyslot/configuration.py#L61), [keyslot/configuration.py:199](../keyslot/configuration.py#L199) |
| `AutoSaveAfterEveryChange` | `AutoSaveAfterEveryChange` | [native:61](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L61) | literal/enum reference | [keyslot/configuration.py:27](../keyslot/configuration.py#L27) |
| `AutoReloadOnChange` | `AutoReloadOnChange` | [native:62](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L62) | literal/enum reference | [keyslot/configuration.py:26](../keyslot/configuration.py#L26) |
| `AutoSaveOnExit` | `AutoSaveOnExit` | [native:63](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L63) | literal/enum reference | [keyslot/configuration.py:28](../keyslot/configuration.py#L28) |
| `AutoSaveNonDataChanges` | `AutoSaveNonDataChanges` | [native:64](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L64) | no direct reference; review | — |
| `BackupBeforeSave` | `BackupBeforeSave` | [native:65](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L65) | no direct reference; review | — |
| `BackupFilePathPattern` | `BackupFilePathPattern` | [native:66](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L66) | no direct reference; review | — |
| `UseAtomicSaves` | `UseAtomicSaves` | [native:67](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L67) | no direct reference; review | — |
| `UseDirectWriteSaves` | `UseDirectWriteSaves` | [native:68](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L68) | no direct reference; review | — |
| `SearchLimitGroup` | `SearchLimitGroup` | [native:69](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L69) | literal/enum reference | [keyslot/configuration.py:59](../keyslot/configuration.py#L59) |
| `MinimizeOnOpenUrl` | `MinimizeOnOpenUrl` | [native:70](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L70) | literal/enum reference | [keyslot/configuration.py:18](../keyslot/configuration.py#L18) |
| `OpenURLOnDoubleClick` | `OpenURLOnDoubleClick` | [native:71](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L71) | no direct reference; review | — |
| `URLDoubleClickAction` | `URLDoubleClickAction` | [native:72](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L72) | no direct reference; review | — |
| `HideWindowOnCopy` | `HideWindowOnCopy` | [native:73](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L73) | literal/enum reference | [keyslot/configuration.py:19](../keyslot/configuration.py#L19) |
| `MinimizeOnCopy` | `MinimizeOnCopy` | [native:74](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L74) | literal/enum reference | [keyslot/configuration.py:20](../keyslot/configuration.py#L20) |
| `AutocompleteSuggestions` | `AutocompleteSuggestions` | [native:75](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L75) | literal/enum reference | [keyslot/attribute_views.py:8](../keyslot/attribute_views.py#L8) |
| `AutoGeneratePasswordForNewEntries` | `AutoGeneratePasswordForNewEntries` | [native:76](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L76) | literal/enum reference | [keyslot/configuration.py:25](../keyslot/configuration.py#L25) |
| `MinimizeAfterUnlock` | `MinimizeAfterUnlock` | [native:77](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L77) | literal/enum reference | [keyslot/configuration.py:22](../keyslot/configuration.py#L22) |
| `DropToBackgroundOnCopy` | `DropToBackgroundOnCopy` | [native:78](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L78) | literal/enum reference | [keyslot/configuration.py:21](../keyslot/configuration.py#L21) |
| `UseGroupIconOnEntryCreation` | `UseGroupIconOnEntryCreation` | [native:79](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L79) | literal/enum reference | [keyslot/configuration.py:24](../keyslot/configuration.py#L24) |
| `AutoTypeEntryTitleMatch` | `AutoTypeEntryTitleMatch` | [native:80](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L80) | literal/enum reference | [keyslot/configuration.py:42](../keyslot/configuration.py#L42) |
| `AutoTypeEntryURLMatch` | `AutoTypeEntryURLMatch` | [native:81](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L81) | literal/enum reference | [keyslot/configuration.py:42](../keyslot/configuration.py#L42) |
| `AutoTypeDelay` | `AutoTypeDelay` | [native:82](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L82) | literal/enum reference | [keyslot/configuration.py:44](../keyslot/configuration.py#L44) |
| `AutoTypeStartDelay` | `AutoTypeStartDelay` | [native:83](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L83) | literal/enum reference | [keyslot/configuration.py:44](../keyslot/configuration.py#L44) |
| `AutoTypeHideExpiredEntry` | `AutoTypeHideExpiredEntry` | [native:84](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L84) | literal/enum reference | [keyslot/configuration.py:43](../keyslot/configuration.py#L43) |
| `AutoTypeDialogSortColumn` | `AutoTypeDialogSortColumn` | [native:85](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L85) | literal/enum reference | [keyslot/configuration.py:46](../keyslot/configuration.py#L46) |
| `AutoTypeDialogSortOrder` | `AutoTypeDialogSortOrder` | [native:86](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L86) | literal/enum reference | [keyslot/configuration.py:46](../keyslot/configuration.py#L46) |
| `AutoTypeDesktopPortalPersistConnection` | `AutoTypeDesktopPortalPersistConnection` | [native:87](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L87) | literal/enum reference | [keyslot/configuration.py:47](../keyslot/configuration.py#L47) |
| `AutoTypeDesktopPortalUseClipboard` | `AutoTypeDesktopPortalUseClipboard` | [native:88](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L88) | literal/enum reference | [keyslot/configuration.py:48](../keyslot/configuration.py#L48) |
| `AutoTypeDesktopPortalPersistMode` | `AutoTypeDesktopPortalPersistMode` | [native:89](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L89) | literal/enum reference | [keyslot/configuration.py:47](../keyslot/configuration.py#L47) |
| `AutoTypeDesktopPortalRestoreToken` | `AutoTypeDesktopPortalRestoreToken` | [native:90](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L90) | literal/enum reference | [keyslot/portal_permissions.py:7](../keyslot/portal_permissions.py#L7) |
| `AutoTypePreferDesktopPortals` | `AutoTypePreferDesktopPortals` | [native:91](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L91) | no direct reference; review | — |
| `GlobalAutoTypeKey` | `GlobalAutoTypeKey` | [native:92](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L92) | no direct reference; review | — |
| `GlobalAutoTypeModifiers` | `GlobalAutoTypeModifiers` | [native:93](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L93) | no direct reference; review | — |
| `GlobalAutoTypeRetypeTime` | `GlobalAutoTypeRetypeTime` | [native:94](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L94) | literal/enum reference | [keyslot/configuration.py:44](../keyslot/configuration.py#L44) |
| `FaviconDownloadTimeout` | `FaviconDownloadTimeout` | [native:95](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L95) | literal/enum reference | [keyslot/configuration.py:68](../keyslot/configuration.py#L68), [keyslot/configuration.py:374](../keyslot/configuration.py#L374) |
| `UpdateCheckMessageShown` | `UpdateCheckMessageShown` | [native:96](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L96) | no direct reference; review | — |
| `DefaultDatabaseFileName` | `DefaultDatabaseFileName` | [native:97](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L97) | no direct reference; review | — |
| `LastDatabases` | `LastDatabases` | [native:99](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L99) | literal/enum reference | [keyslot/configuration.py:70](../keyslot/configuration.py#L70), [keyslot/configuration.py:322](../keyslot/configuration.py#L322) |
| `LastKeyFiles` | `LastKeyFiles` | [native:100](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L100) | literal/enum reference | [keyslot/configuration.py:71](../keyslot/configuration.py#L71), [keyslot/configuration.py:237](../keyslot/configuration.py#L237) |
| `LastChallengeResponse` | `LastChallengeResponse` | [native:101](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L101) | literal/enum reference | [keyslot/configuration.py:71](../keyslot/configuration.py#L71), [keyslot/configuration.py:242](../keyslot/configuration.py#L242) |
| `LastActiveDatabase` | `LastActiveDatabase` | [native:102](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L102) | literal/enum reference | [keyslot/configuration.py:70](../keyslot/configuration.py#L70), [keyslot/configuration.py:201](../keyslot/configuration.py#L201) |
| `LastOpenedDatabases` | `LastOpenedDatabases` | [native:103](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L103) | literal/enum reference | [keyslot/configuration.py:70](../keyslot/configuration.py#L70), [keyslot/configuration.py:204](../keyslot/configuration.py#L204) |
| `LastDir` | `LastDir` | [native:104](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L104) | no direct reference; review | — |
| `GUI/Language` | `GUI_Language` | [native:107](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L107) | no direct reference; review | — |
| `GUI/HideMenubar` | `GUI_HideMenubar` | [native:108](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L108) | no direct reference; review | — |
| `GUI/HideToolbar` | `GUI_HideToolbar` | [native:109](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L109) | no direct reference; review | — |
| `GUI/MovableToolbar` | `GUI_MovableToolbar` | [native:110](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L110) | no direct reference; review | — |
| `GUI/HideGroupPanel` | `GUI_HideGroupPanel` | [native:111](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L111) | no direct reference; review | — |
| `GUI/HidePreviewPanel` | `GUI_HidePreviewPanel` | [native:112](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L112) | no direct reference; review | — |
| `GUI/GUI_AlwaysOnTop` | `GUI_AlwaysOnTop` | [native:113](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L113) | no direct reference; review | — |
| `GUI/ToolButtonStyle` | `GUI_ToolButtonStyle` | [native:114](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L114) | no direct reference; review | — |
| `GUI/LaunchAtStartup` | `GUI_LaunchAtStartup` | [native:115](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L115) | no direct reference; review | — |
| `GUI/ShowTrayIcon` | `GUI_ShowTrayIcon` | [native:116](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L116) | no direct reference; review | — |
| `GUI/TrayIconAppearance` | `GUI_TrayIconAppearance` | [native:117](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L117) | no direct reference; review | — |
| `GUI/MinimizeToTray` | `GUI_MinimizeToTray` | [native:118](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L118) | literal/enum reference | [keyslot/configuration.py:23](../keyslot/configuration.py#L23) |
| `GUI/MinimizeOnStartup` | `GUI_MinimizeOnStartup` | [native:119](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L119) | no direct reference; review | — |
| `GUI/MinimizeOnClose` | `GUI_MinimizeOnClose` | [native:120](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L120) | no direct reference; review | — |
| `GUI/HideUsernames` | `GUI_HideUsernames` | [native:121](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L121) | literal/enum reference | [keyslot/configuration.py:32](../keyslot/configuration.py#L32) |
| `GUI/HidePasswords` | `GUI_HidePasswords` | [native:122](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L122) | no direct reference; review | — |
| `GUI/ColorPasswords` | `GUI_ColorPasswords` | [native:123](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L123) | no direct reference; review | — |
| `GUI/MonospaceNotes` | `GUI_MonospaceNotes` | [native:124](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L124) | literal/enum reference | [keyslot/configuration.py:35](../keyslot/configuration.py#L35) |
| `GUI/ApplicationTheme` | `GUI_ApplicationTheme` | [native:125](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L125) | no direct reference; review | — |
| `GUI/CompactMode` | `GUI_CompactMode` | [native:126](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L126) | no direct reference; review | — |
| `GUI/CheckForUpdates` | `GUI_CheckForUpdates` | [native:127](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L127) | no direct reference; review | — |
| `GUI/CheckForUpdatesNextCheck` | `GUI_CheckForUpdatesNextCheck` | [native:128](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L128) | no direct reference; review | — |
| `GUI/CheckForUpdatesIncludeBetas` | `GUI_CheckForUpdatesIncludeBetas` | [native:129](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L129) | no direct reference; review | — |
| `GUI/SearchWaitForEnter` | `GUI_SearchWaitForEnter` | [native:130](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L130) | literal/enum reference | [keyslot/configuration.py:59](../keyslot/configuration.py#L59) |
| `GUI/ShowExpiredEntriesOnDatabaseUnlock` | `GUI_ShowExpiredEntriesOnDatabaseUnlock` | [native:131](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L131) | no direct reference; review | — |
| `GUI/ShowExpiredEntriesOnDatabaseUnlockOffsetDays` | `GUI_ShowExpiredEntriesOnDatabaseUnlockOffsetDays` | [native:132](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L132) | no direct reference; review | — |
| `GUI/FontSizeOffset` | `GUI_FontSizeOffset` | [native:133](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L133) | no direct reference; review | — |
| `GUI/XDPGlobalShortcutsConfigured` | `GUI_XDPGlobalShortcutsConfigured` | [native:134](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L134) | no direct reference; review | — |
| `GUI/MainWindowGeometry` | `GUI_MainWindowGeometry` | [native:136](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L136) | no direct reference; review | — |
| `GUI/MainWindowState` | `GUI_MainWindowState` | [native:137](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L137) | no direct reference; review | — |
| `GUI/ListViewState` | `GUI_ListViewState` | [native:138](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L138) | no direct reference; review | — |
| `GUI/SearchViewState` | `GUI_SearchViewState` | [native:139](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L139) | no direct reference; review | — |
| `GUI/SplitterState` | `GUI_SplitterState` | [native:140](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L140) | no direct reference; review | — |
| `GUI/GroupSplitterState` | `GUI_GroupSplitterState` | [native:141](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L141) | no direct reference; review | — |
| `GUI/PreviewSplitterState` | `GUI_PreviewSplitterState` | [native:142](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L142) | no direct reference; review | — |
| `GUI/AutoTypeSelectDialogSize` | `GUI_AutoTypeSelectDialogSize` | [native:143](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L143) | no direct reference; review | — |
| `Security/ClearClipboard` | `Security_ClearClipboard` | [native:146](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L146) | literal/enum reference | [keyslot/configuration.py:64](../keyslot/configuration.py#L64), [keyslot/configuration.py:291](../keyslot/configuration.py#L291) |
| `Security/ClearClipboardTimeout` | `Security_ClearClipboardTimeout` | [native:147](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L147) | literal/enum reference | [keyslot/configuration.py:65](../keyslot/configuration.py#L65), [keyslot/configuration.py:291](../keyslot/configuration.py#L291) |
| `Security/ClearSearch` | `Security_ClearSearch` | [native:148](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L148) | no direct reference; review | — |
| `Security/ClearSearchTimeout` | `Security_ClearSearchTimeout` | [native:149](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L149) | no direct reference; review | — |
| `Security/Security_HideNotes` | `Security_HideNotes` | [native:150](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L150) | literal/enum reference | [keyslot/configuration.py:33](../keyslot/configuration.py#L33) |
| `Security/LockDatabaseIdle` | `Security_LockDatabaseIdle` | [native:151](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L151) | literal/enum reference | [keyslot/configuration.py:63](../keyslot/configuration.py#L63), [keyslot/configuration.py:290](../keyslot/configuration.py#L290) |
| `Security/LockDatabaseIdleSeconds` | `Security_LockDatabaseIdleSeconds` | [native:152](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L152) | literal/enum reference | [keyslot/configuration.py:64](../keyslot/configuration.py#L64), [keyslot/configuration.py:290](../keyslot/configuration.py#L290) |
| `Security/LockDatabaseMinimize` | `Security_LockDatabaseMinimize` | [native:153](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L153) | literal/enum reference | [keyslot/configuration.py:31](../keyslot/configuration.py#L31) |
| `Security/LockDatabaseScreenLock` | `Security_LockDatabaseScreenLock` | [native:154](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L154) | literal/enum reference | [keyslot/configuration.py:29](../keyslot/configuration.py#L29) |
| `Security/LockDatabaseOnUserSwitch` | `Security_LockDatabaseOnUserSwitch` | [native:155](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L155) | literal/enum reference | [keyslot/configuration.py:30](../keyslot/configuration.py#L30) |
| `Security/RelockAutoType` | `Security_RelockAutoType` | [native:156](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L156) | literal/enum reference | [keyslot/configuration.py:43](../keyslot/configuration.py#L43) |
| `Security/PasswordsHidden` | `Security_PasswordsHidden` | [native:157](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L157) | no direct reference; review | — |
| `Security/PasswordEmptyPlaceholder` | `Security_PasswordEmptyPlaceholder` | [native:158](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L158) | literal/enum reference | [keyslot/configuration.py:36](../keyslot/configuration.py#L36) |
| `Security/HidePasswordPreviewPanel` | `Security_HidePasswordPreviewPanel` | [native:159](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L159) | literal/enum reference | [keyslot/configuration.py:34](../keyslot/configuration.py#L34) |
| `Security/HideTotpPreviewPanel` | `Security_HideTotpPreviewPanel` | [native:160](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L160) | no direct reference; review | — |
| `Security/AutotypeAsk` | `Security_AutoTypeAsk` | [native:161](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L161) | literal/enum reference | [keyslot/configuration.py:45](../keyslot/configuration.py#L45) |
| `Security/AutoTypeSkipMainWindowConfirmation` | `Security_AutoTypeSkipMainWindowConfirmation` | [native:162](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L162) | literal/enum reference | [keyslot/configuration.py:45](../keyslot/configuration.py#L45) |
| `Security/IconDownloadFallback` | `Security_IconDownloadFallback` | [native:163](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L163) | literal/enum reference | [keyslot/configuration.py:69](../keyslot/configuration.py#L69), [keyslot/configuration.py:377](../keyslot/configuration.py#L377) |
| `Security/NoConfirmMoveEntryToRecycleBin` | `Security_NoConfirmMoveEntryToRecycleBin` | [native:164](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L164) | no direct reference; review | — |
| `Security/EnableCopyOnDoubleClick` | `Security_EnableCopyOnDoubleClick` | [native:165](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L165) | no direct reference; review | — |
| `Security/QuickUnlock` | `Security_QuickUnlock` | [native:166](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L166) | no direct reference; review | — |
| `Security/DatabasePasswordMinimumQuality` | `Security_DatabasePasswordMinimumQuality` | [native:167](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L167) | no direct reference; review | — |
| `Browser/Enabled` | `Browser_Enabled` | [native:170](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L170) | literal/enum reference | [keyslot/configuration.py:17](../keyslot/configuration.py#L17) |
| `Browser/ShowNotification` | `Browser_ShowNotification` | [native:171](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L171) | no direct reference; review | — |
| `Browser/BestMatchOnly` | `Browser_BestMatchOnly` | [native:172](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L172) | no direct reference; review | — |
| `Browser/UnlockDatabase` | `Browser_UnlockDatabase` | [native:173](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L173) | no direct reference; review | — |
| `Browser/MatchUrlScheme` | `Browser_MatchUrlScheme` | [native:174](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L174) | no direct reference; review | — |
| `Browser/SupportBrowserProxy` | `Browser_SupportBrowserProxy` | [native:175](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L175) | no direct reference; review | — |
| `Browser/UseCustomProxy` | `Browser_UseCustomProxy` | [native:176](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L176) | no direct reference; review | — |
| `Browser/CustomProxyLocation` | `Browser_CustomProxyLocation` | [native:177](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L177) | no direct reference; review | — |
| `Browser/UpdateBinaryPath` | `Browser_UpdateBinaryPath` | [native:178](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L178) | no direct reference; review | — |
| `Browser/AllowGetDatabaseEntriesRequest` | `Browser_AllowGetDatabaseEntriesRequest` | [native:179](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L179) | literal/enum reference | [keyslot/configuration.py:69](../keyslot/configuration.py#L69), [keyslot/configuration.py:283](../keyslot/configuration.py#L283) |
| `Browser/AllowExpiredCredentials` | `Browser_AllowExpiredCredentials` | [native:180](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L180) | no direct reference; review | — |
| `Browser/AlwaysAllowAccess` | `Browser_AlwaysAllowAccess` | [native:181](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L181) | no direct reference; review | — |
| `Browser/AlwaysAllowUpdate` | `Browser_AlwaysAllowUpdate` | [native:182](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L182) | no direct reference; review | — |
| `Browser/HttpAuthPermission` | `Browser_HttpAuthPermission` | [native:183](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L183) | no direct reference; review | — |
| `Browser/SearchInAllDatabases` | `Browser_SearchInAllDatabases` | [native:184](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L184) | no direct reference; review | — |
| `Browser/SupportKphFields` | `Browser_SupportKphFields` | [native:185](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L185) | no direct reference; review | — |
| `Browser/NoMigrationPrompt` | `Browser_NoMigrationPrompt` | [native:186](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L186) | no direct reference; review | — |
| `Browser/UseCustomBrowser` | `Browser_UseCustomBrowser` | [native:187](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L187) | no direct reference; review | — |
| `Browser/CustomBrowserType` | `Browser_CustomBrowserType` | [native:188](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L188) | no direct reference; review | — |
| `Browser/CustomBrowserLocation` | `Browser_CustomBrowserLocation` | [native:189](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L189) | no direct reference; review | — |
| `Browser/Browser_AllowLocalhostWithPasskeys` | `Browser_AllowLocalhostWithPasskeys` | [native:190](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L190) | no direct reference; review | — |
| `Browser/CustomExtensionId` | `Browser_CustomExtensionId` | [native:192](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L192) | no direct reference; review | — |
| `SSHAgent/Enabled` | `SSHAgent_Enabled` | [native:196](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L196) | literal/enum reference | [keyslot/configuration.py:37](../keyslot/configuration.py#L37) |
| `SSHAgent/UseOpenSSH` | `SSHAgent_UseOpenSSH` | [native:197](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L197) | no direct reference; review | — |
| `SSHAgent/UsePageant` | `SSHAgent_UsePageant` | [native:198](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L198) | no direct reference; review | — |
| `SSHAgent/AuthSockOverride` | `SSHAgent_AuthSockOverride` | [native:199](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L199) | literal/enum reference | [keyslot/configuration.py:38](../keyslot/configuration.py#L38) |
| `SSHAgent/SecurityKeyProviderOverride` | `SSHAgent_SecurityKeyProviderOverride` | [native:200](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L200) | literal/enum reference | [keyslot/configuration.py:39](../keyslot/configuration.py#L39) |
| `FdoSecrets/Enabled` | `FdoSecrets_Enabled` | [native:203](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L203) | dynamic prefix candidate; review | [engine/KeyslotHistory.cpp:46](../engine/KeyslotHistory.cpp#L46), [keyslot/application.py:893](../keyslot/application.py#L893) |
| `FdoSecrets/ShowNotification` | `FdoSecrets_ShowNotification` | [native:204](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L204) | dynamic prefix candidate; review | [keyslot/configuration.py:49](../keyslot/configuration.py#L49) |
| `FdoSecrets/ConfirmDeleteItem` | `FdoSecrets_ConfirmDeleteItem` | [native:205](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L205) | dynamic prefix candidate; review | [keyslot/configuration.py:49](../keyslot/configuration.py#L49) |
| `FdoSecrets/ConfirmAccessItem` | `FdoSecrets_ConfirmAccessItem` | [native:206](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L206) | dynamic prefix candidate; review | [keyslot/configuration.py:50](../keyslot/configuration.py#L50) |
| `FdoSecrets/UnlockBeforeSearch` | `FdoSecrets_UnlockBeforeSearch` | [native:207](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L207) | dynamic prefix candidate; review | [keyslot/configuration.py:50](../keyslot/configuration.py#L50) |
| `KeeShare/QuietSuccess` | `KeeShare_QuietSuccess` | [native:210](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L210) | no direct reference; review | — |
| `KeeShare/Own` | `KeeShare_Own` | [native:211](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L211) | no direct reference; review | — |
| `KeeShare/Foreign` | `KeeShare_Foreign` | [native:212](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L212) | no direct reference; review | — |
| `KeeShare/Active` | `KeeShare_Active` | [native:213](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L213) | no direct reference; review | — |
| `PasswordGenerator/LowerCase` | `PasswordGenerator_LowerCase` | [native:216](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L216) | dynamic prefix candidate; review | [keyslot/configuration.py:51](../keyslot/configuration.py#L51) |
| `PasswordGenerator/UpperCase` | `PasswordGenerator_UpperCase` | [native:217](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L217) | dynamic prefix candidate; review | [keyslot/configuration.py:51](../keyslot/configuration.py#L51) |
| `PasswordGenerator/Numbers` | `PasswordGenerator_Numbers` | [native:218](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L218) | dynamic prefix candidate; review | [keyslot/configuration.py:52](../keyslot/configuration.py#L52) |
| `PasswordGenerator/EASCII` | `PasswordGenerator_EASCII` | [native:219](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L219) | dynamic prefix candidate; review | [keyslot/configuration.py:52](../keyslot/configuration.py#L52) |
| `PasswordGenerator/AdvancedMode` | `PasswordGenerator_AdvancedMode` | [native:220](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L220) | literal/enum reference | [keyslot/configuration.py:66](../keyslot/configuration.py#L66), [keyslot/configuration.py:393](../keyslot/configuration.py#L393) |
| `PasswordGenerator/SpecialChars` | `PasswordGenerator_SpecialChars` | [native:221](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L221) | literal/enum reference | [keyslot/configuration.py:67](../keyslot/configuration.py#L67), [keyslot/configuration.py:393](../keyslot/configuration.py#L393) |
| `PasswordGenerator/Braces` | `PasswordGenerator_Braces` | [native:222](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L222) | dynamic prefix candidate; review | [keyslot/configuration.py:57](../keyslot/configuration.py#L57) |
| `PasswordGenerator/Punctuation` | `PasswordGenerator_Punctuation` | [native:223](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L223) | dynamic prefix candidate; review | [keyslot/configuration.py:57](../keyslot/configuration.py#L57) |
| `PasswordGenerator/Quotes` | `PasswordGenerator_Quotes` | [native:224](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L224) | dynamic prefix candidate; review | [keyslot/configuration.py:57](../keyslot/configuration.py#L57), [keyslot/generator_views.py:153](../keyslot/generator_views.py#L153) |
| `PasswordGenerator/Dashes` | `PasswordGenerator_Dashes` | [native:225](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L225) | dynamic prefix candidate; review | [keyslot/configuration.py:58](../keyslot/configuration.py#L58) |
| `PasswordGenerator/Math` | `PasswordGenerator_Math` | [native:226](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L226) | dynamic prefix candidate; review | [keyslot/configuration.py:58](../keyslot/configuration.py#L58) |
| `PasswordGenerator/Logograms` | `PasswordGenerator_Logograms` | [native:227](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L227) | dynamic prefix candidate; review | [keyslot/configuration.py:58](../keyslot/configuration.py#L58) |
| `PasswordGenerator/AdditionalChars` | `PasswordGenerator_AdditionalChars` | [native:228](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L228) | dynamic prefix candidate; review | [keyslot/configuration.py:54](../keyslot/configuration.py#L54) |
| `PasswordGenerator/ExcludedChars` | `PasswordGenerator_ExcludedChars` | [native:229](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L229) | dynamic prefix candidate; review | [keyslot/configuration.py:54](../keyslot/configuration.py#L54) |
| `PasswordGenerator/ExcludeAlike` | `PasswordGenerator_ExcludeAlike` | [native:230](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L230) | dynamic prefix candidate; review | [keyslot/configuration.py:53](../keyslot/configuration.py#L53) |
| `PasswordGenerator/EnsureEvery` | `PasswordGenerator_EnsureEvery` | [native:231](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L231) | dynamic prefix candidate; review | [keyslot/configuration.py:53](../keyslot/configuration.py#L53) |
| `PasswordGenerator/Length` | `PasswordGenerator_Length` | [native:232](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L232) | dynamic prefix candidate; review | [keyslot/configuration.py:55](../keyslot/configuration.py#L55), [keyslot/generator_views.py:117](../keyslot/generator_views.py#L117) |
| `PasswordGenerator/WordCount` | `PasswordGenerator_WordCount` | [native:233](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L233) | dynamic prefix candidate; review | [keyslot/configuration.py:55](../keyslot/configuration.py#L55) |
| `PasswordGenerator/WordSeparator` | `PasswordGenerator_WordSeparator` | [native:234](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L234) | dynamic prefix candidate; review | [keyslot/configuration.py:55](../keyslot/configuration.py#L55) |
| `PasswordGenerator/WordList` | `PasswordGenerator_WordList` | [native:235](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L235) | dynamic prefix candidate; review | [keyslot/configuration.py:56](../keyslot/configuration.py#L56) |
| `PasswordGenerator/WordCase` | `PasswordGenerator_WordCase` | [native:236](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L236) | literal/enum reference | [keyslot/configuration.py:67](../keyslot/configuration.py#L67), [keyslot/configuration.py:396](../keyslot/configuration.py#L396) |
| `PasswordGenerator/Type` | `PasswordGenerator_Type` | [native:237](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L237) | literal/enum reference | [keyslot/configuration.py:68](../keyslot/configuration.py#L68), [keyslot/configuration.py:396](../keyslot/configuration.py#L396) |
| `Messages/NoLegacyKeyFileWarning` | `Messages_NoLegacyKeyFileWarning` | [native:240](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L240) | no direct reference; review | — |
| `Messages/HidePreReleaseWarning` | `Messages_HidePreReleaseWarning` | [native:241](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp#L241) | no direct reference; review | — |

## Implemented after the frozen inventory

The table/counts above remain the original bounded review snapshot. Current
source now maps AutoSaveNonDataChanges, GUI/ShowExpiredEntriesOnDatabaseUnlock,
GUI/ShowExpiredEntriesOnDatabaseUnlockOffsetDays,
Security/EnableCopyOnDoubleClick, URLDoubleClickAction and GUI/Language.
See [behavior preferences](behavior-preferences.md) and [localization](localization.md).
These six old “no direct reference” rows now have implementation evidence;
manual acceptance and the rest of the finite R08 review remain open.

R08 read-path follow-up: the deprecated OpenURLOnDoubleClick boolean now supplies
the effective URLDoubleClickAction for pre-version-2 profiles only when that
modern key is absent (true→0 Open, false→2 Edit), as in stock Config::migrate. The Qt INI helper applies the
same conversion for reads and write comparisons; unrelated writes preserve the
original keys and do not silently insert a modern default. An explicit modern
value always wins. This is an implementation fix, not manual acceptance.
Optional backup failure behavior now also matches stock best-effort primary save;
[backup constraints](backups.md) preserve the main-file conflict/atomic guards.

The browser matching follow-up now maps Browser/BestMatchOnly,
Browser/AllowExpiredCredentials, Browser/MatchUrlScheme and Browser/SupportKphFields
through profiles/private preferences, GTK controls and the existing native
best_match/allow_expired/match_scheme/custom_fields request fields. Immutable
policy capture invalidates pending requests on a preference change while
retaining browser associations. See [matching behavior](browser-matching.md).
These four formerly unmatched frozen rows now have concrete implementation;
manual acceptance, other Browser/* settings and the finite166-row review remain
incomplete. Per-entry rules/trust are still distinct from global matching policy.
