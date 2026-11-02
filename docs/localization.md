# English, Polish and Romanian

English is the source and fallback language. Keyslot's GTK gettext catalogs are
limited to Polish (`pl`) and Romanian (`ro`). The marked GTK and diagnostic
corpus is translated; unmarked or dynamic messages can still appear in English.
This does not change the upstream native-core translation assets.

The application follows the desktop/process language environment by default.
Preferences also offers System Language, English, Polish and Romanian. An
explicit choice is stored in Keyslot's startup settings and takes effect after
restarting the application. Unknown saved language codes are preserved and use
the desktop/process language until the user chooses a supported option. No
system-wide locale or user's environment is modified. The separate `keyslot`
gettext domain loads `$out/share/locale` from its installed module location;
Meson installs the compiled MO catalogs.

To apply a changed language, fully Quit the existing Keyslot process, including
its background instance, and open it again. A second launch that reaches an
already-running primary process does not reload its catalog. The GNOME
companion has its own gettext domain (`keyslot@neg-zero`) and ships Polish and
Romanian catalogs with the extension. Its UI follows the desktop language
independently of Keyslot's per-app language choice.

Translation is applied at presentation boundaries. IDs, shortcut actions,
Auto-Type sequences, reference codes, CSV delimiters, database contents and
custom field names stay unchanged. Shared caption tables use a no-op marker so
their English internal values remain available to code. File-format, encryption
and browser protocol parameters continue to use their original values.

Formatted messages are looked up before inserting entry names, paths and other
values. Runtime formatting falls back to the English template if the translated
placeholder names, conversions or format specifications differ. Entry counts,
timeouts and similar integer quantities use Polish/Romanian plural forms.
Unknown custom history-field names stay literal; only known standard-field
captions are translated. Native protocol/error codes stay unchanged; known
static error messages can be translated when presented by GTK.

Desktop entry, AppStream metainfo, PolicyKit prompts and companion preferences
provide Polish and Romanian labels. `po/README.md` records attribution for
phrases adapted from the upstream KeePassXC 2.8.0 Polish/Romanian catalogs and
the GPL-3.0-only terms of the combined catalogs. New Keyslot phrases are
maintained alongside those translations.

Current validation is resource compilation and static source review; ordinary
runtime packaging is separate. No tests or behavior probes are part of this
localization work.
