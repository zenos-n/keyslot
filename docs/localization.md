# English, Polish and Romanian

English is the source and fallback language. Keyslot's GTK gettext catalogs are
limited to Polish (`pl`) and Romanian (`ro`). Translation is still in progress;
untranslated messages appear in English. This does not change the existing
upstream native-core translation assets.

The application follows the desktop/process language environment. The separate
`keyslot` gettext domain loads `$out/share/locale` from its installed module
location. Meson installs the two compiled MO catalogs. No system-wide locale,
vault setting or user's environment is modified. A per-app language selector is
not implemented yet.

To review another language, first fully Quit the existing Keyslot process,
including its background instance, then launch the updated package with
`LANGUAGE=pl keyslot` or `LANGUAGE=ro keyslot`. A second launch that reaches an
already-running primary process does not reload its language environment. The
compiled catalogs alone do not demonstrate that the actual GTK layout and
wording have been accepted in either language.

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

`po/README.md` records attribution for phrases adapted from the upstream
KeePassXC2.8.0 Polish/Romanian catalogs and the GPL-3.0-only terms of the combined
catalogs. New Keyslot phrases are maintained alongside those translations.

R02 remains open: remaining GTK messages and diagnostics, source-caption
coverage, desktop/metainfo/polkit and companion surfaces, language-setting
compatibility and user manual linguistic/layout/accessibility acceptance.
Current validation is resource compilation and static source review; ordinary
runtime packaging is separate. No tests or behavior probes are part of this
localization work.
