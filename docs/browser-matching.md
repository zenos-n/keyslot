# Browser matching preferences

Preferences → Browser Matching exposes the stock global matching policy:

| GTK control | Roaming INI key | Stock default | Native request field |
|---|---|---|---|
| Return Only the Best Website Match | Browser/BestMatchOnly | false | best_match |
| Allow Expired Browser Logins | Browser/AllowExpiredCredentials | false | allow_expired |
| Match Website Protocol | Browser/MatchUrlScheme | true | match_scheme |
| Include Legacy KPH Fields | Browser/SupportKphFields | true | custom_fields |

The same values are saved in private startup preferences when no INI profile is
selected. Old private files without this object gain the stock defaults; invalid
objects do not prevent unrelated startup/privacy options from loading. The typed
profile adapter reads/writes these exact keys and preserves unrelated settings.
Changing one row merges just that field into the current shared policy so a stale
second preferences window does not overwrite the other matching choices.

Each login-lookup request captures one immutable tuple published after a successful
preference save. Login lookup forwards all four fields to the existing native
browser helper. No URL matching or result construction is duplicated in GTK.
The native request already retains best-match/expired/custom-field options for
release, reduces best matches after selection/permission checks, and checks
entry access again before returning results. Scheme matching is used by native
candidate search. Legacy KPH fields appear only in approved browser results.

Preference changes cancel pending login lookups and dismiss their GTK/Shell prompts;
workers check the captured policy before operations and before replying. A late
result cannot be returned through an old request after policy changes. The
existing database-state notification lets the browser refresh/retry. Browser
associations are retained; changing matching does not pair/unpair a browser or
grant access. Unrelated save/delete/pair/passkey operations keep their original
request lifetimes. Already returned data in a browser is outside this request lifetime.

Per-connection trust, remembered site decisions, hidden/recycled entries,
connection restrictions, HTTP-auth rules, one-use native requests and vault/
client/epoch/identity guards remain enforced. Expired entries can match only when
Allow Expired Browser Logins is explicitly enabled. This does not change save,
delete, pairing, unlocking or passkey approval workflows, and is not an
implementation of every other stock global Browser/* preference.

Evidence is ordinary runtime/Python/gettext compilation and static source/
artifact inspection only. No tests, harnesses or browser/vault/GTK/clipboard/
credential behavior probes were added or run. Manual acceptance remains for
best-match permission ordering, HTTP/HTTPS, expired/trusted/denied entries,
KPH fields, profile persistence, concurrent preferences, pending prompt/worker
cancellation, retry, locked/closed vaults, and English/Polish/Romanian labels.
No full replacement or production-readiness claim follows from compilation.

Stock behavior source: KeePassXC Team GPL2-or-3, independent integration GPL3-only.

- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/browser/BrowserService.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/browser/BrowserSettings.cpp
