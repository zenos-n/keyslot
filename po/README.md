# Keyslot translations

English is the source/fallback language. Only Polish (`pl`) and Romanian (`ro`)
are compiled here, matching the user-approved scope. Catalogs are UTF-8.

Use `_tr` only for source-owned messages. `_trf` and `_ntrf` look up a static
format before inserting values; keep placeholder names, conversions and format
specifiers unchanged. `_mark` is the gettext-noop marker for captions shared
with internal tables: translate at the presentation boundary, not in stored data.
Do not mark entry content, custom field names, paths, IDs or protocol values.
Native protocol payloads remain unchanged; known static errors are translated
only at the GTK error-presentation boundary. Review the source context before
reusing another translation.

Unambiguous matching phrases are adapted from KeePassXC2.8.0's `keepassxc_pl.ts`
and `keepassxc_ro.ts`. Copyright belongs to the KeePassXC Team and the respective
community translators. Upstream code/translations are licensed GPL-2 or GPL-3;
these combined catalogs are distributed under GPL-3.0-only, as is Keyslot.
Original sources: https://github.com/keepassxreboot/keepassxc/tree/2.8.0/share/translations
and https://github.com/keepassxreboot/keepassxc/blob/2.8.0/README.md#license .
Keyslot additions are by Keyslot Contributors. Preserve this attribution.

Missing translations fall back to English. Runtime format validation also falls
back to the English template if a translation changes its placeholder signature.
This is not proof of linguistic/GUI acceptance; the user reviews en/pl/ro.
