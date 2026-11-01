# Proton Pass record backport

The Wi-Fi, SSH-key and unknown-record handling in `ProtonPassRecords.patch`
comes from KeePassXC 2.8.0's `src/format/ProtonPassReader.cpp`:
https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/format/ProtonPassReader.cpp

The original KeePassXC copyright and GPL-2.0-or-later license remain in the
pinned source file. The patch applies to the 2.7.12 reader, preserving its
existing login/card/note/custom-field/vault/timestamp handling.

Wi-Fi SSID/password map to username/password, with a security attribute. SSH
public/private keys map to custom attributes, with the private key protected.
Unknown record types are annotated in notes and retain their content fields as
attributes. Keyslot additionally protects unknown fields, preserves structured,
numeric, boolean, empty and null content values through compact JSON where
needed, and protects extra-field TOTP URIs. Duplicate/unnamed extra fields use
collision-free names instead of replacing an existing value. The importer's
source export remains unchanged.

The name-suggestion RPC follows upstream 2.8's non-recycled custom-key inventory,
case-insensitive numeric sorting and exclusion of keys on the current entry.
Keyslot also excludes reserved passkey keys, pages results in batches of 100,
bounds query/name size and reports omitted oversized names. It returns names
only, without attribute values or source-entry metadata. GTK uses an explicit
suggestion menu; the shared `AutocompleteSuggestions` boolean controls it.
Sources:
https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Database.cpp
https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/entry/EditEntryWidget.cpp

Runtime compilation only is performed for this batch. Real-export import,
field protection, collisions, review/save/recovery, suggestion pagination,
configuration and lock/desktop acceptance remain for manual stress testing.
No tests or harnesses were added or run.
