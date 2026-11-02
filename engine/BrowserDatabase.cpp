// SPDX-License-Identifier: GPL-3.0-only
#include "BrowserDatabase.h"
#include "KeyslotBrowserValues.h"
#include "browser/BrowserSettings.h"
#include "browser/BrowserShared.h"
#include "core/CustomData.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/EntryAttributes.h"
#include "core/Group.h"
#include "core/Global.h"
#include "core/Metadata.h"
#include "core/Tools.h"
#include <QDateTime>
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QMap>
#include <QSet>
#include <QUrl>
#include <QUuid>
#include <cmath>

namespace KeyslotBrowser {
[[noreturn]] void reject(const char* code, const char* message) { throw BrowserFailure{code, message}; }
QString text(const QJsonObject& args, const char* name, bool required) {
    if ((required || args.contains(name)) && !args.value(name).isString())
        reject("invalid_request", "A browser request has an invalid text field.");
    const auto value = args.value(name).toString();
    if ((required && value.isEmpty()) || value.size() > 16384 || value.contains(QChar('\0')))
        reject("invalid_request", "A browser request has an invalid text field.");
    return value;
}

bool flag(const QJsonObject& args, const char* name, bool fallback) {
    if (args.contains(name) && !args.value(name).isBool())
        reject("invalid_request", "A browser request has an invalid option.");
    return args.contains(name) ? args.value(name).toBool() : fallback;
}
void authenticate(const QSharedPointer<Database>& db, const QString& id, const QString& key) {
    const auto expected = db->metadata()->customData()->value(CustomData::BrowserKeyPrefix + id);
    if (key.isEmpty() || expected.isEmpty() || expected != key)
        reject("association_failed", "The browser is not connected to this database.");
}
QString trustKey(const QString& id) { return QStringLiteral("Keyslot/TrustedBrowser/") + id; }
QString connectionRevision(const QString& key) {
    return QString::fromLatin1(QCryptographicHash::hash(key.toUtf8(), QCryptographicHash::Sha256).toHex());
}
bool trusted(const QSharedPointer<Database>& db, const QString& id, const QString& key) {
    const auto* data = db->metadata()->customData();
    return !key.isEmpty() && data->value(CustomData::BrowserKeyPrefix + id) == key
        && data->value(trustKey(id)) == connectionRevision(key);
}
QString groupPath(QString path) {
    if (path.startsWith('/')) path.remove(0, 1);
    if (path.endsWith('/')) path.chop(1);
    const auto components = path.split('/');
    if (components.size() > 128 || components.contains(QString()))
        reject("invalid_request", "Choose a nonempty group path without empty components.");
    return path;
}

bool validUrl(const QUrl& url) {
    return url.isValid() && ((url.scheme() == "http" || url.scheme() == "https")
        ? !url.host().isEmpty() : url.scheme() == "file" || url.scheme() == "keepassxc");
}
}

using namespace KeyslotBrowser;

namespace {
const QMap<QString, QString>& optionNames() {
    static const QMap<QString, QString> names{
        {"hide", BrowserService::OPTION_HIDE_ENTRY}, {"skip_submit", BrowserService::OPTION_SKIP_AUTO_SUBMIT},
        {"only_http", BrowserService::OPTION_ONLY_HTTP_AUTH}, {"not_http", BrowserService::OPTION_NOT_HTTP_AUTH},
        {"omit_www", BrowserService::OPTION_OMIT_WWW}};
    return names;
}
struct OptionTarget {
    Entry* entry = nullptr;
    Group* group = nullptr;
    CustomData* data() const { return entry ? entry->customData() : group->customData(); }
    Group* parent() const { return entry ? entry->group() : group->parentGroup(); }
};
OptionTarget optionTarget(const QSharedPointer<Database>& db, const QJsonObject& args) {
    if (args.contains("entry") == args.contains("group")) reject("invalid_request", "Choose an entry or group for browser settings.");
    OptionTarget result;
    const bool entry = args.contains("entry");
    const QUuid id(text(args, entry ? "entry" : "group", true));
    if (id.isNull()) reject("invalid_request", "Choose a valid browser settings target.");
    int count = 0;
    if (entry) {
        for (auto* item : db->rootGroup()->entriesRecursive()) if (item->uuid() == id) { result.entry = item; ++count; }
    } else {
        for (auto* item : db->rootGroup()->groupsRecursive(true)) if (item->uuid() == id) { result.group = item; ++count; }
    }
    if (!count) reject("not_found", "This browser settings target no longer exists.");
    if (count != 1) reject("conflict", "This browser settings target is ambiguous.");
    if (entry ? result.entry->isRecycled() : result.group->isRecycled())
        reject("denied", "Restore this item before editing browser settings.");
    return result;
}
int localOption(const CustomData* data, const QString& key) {
    return !data->contains(key) ? Group::Inherit : data->value(key) == TRUE_STR ? Group::Enable : Group::Disable;
}
}

QJsonObject KeyslotBrowserDatabase::options(const QSharedPointer<Database>& db, const QJsonObject& args,
                                           const QByteArray& fingerprint) {
    const auto target = optionTarget(db, args);
    const auto* data = target.data();
    const auto* parent = target.parent();
    QJsonObject values, inherited, effective, forced;
    const auto& browserOptions = optionNames();
    for (auto it = browserOptions.cbegin(); it != browserOptions.cend(); ++it) {
        if (target.entry && it.key() == "omit_www") continue;
        const auto local = localOption(data, it.value());
        const auto source = parent ? parent->resolveCustomDataTriState(it.value()) : Group::Inherit;
        const bool override = target.entry && (it.key() == "hide" || it.key() == "skip_submit"
            ? source != Group::Inherit : source == Group::Enable);
        values.insert(it.key(), local); inherited.insert(it.key(), source); forced.insert(it.key(), override);
        effective.insert(it.key(), override ? source == Group::Enable : local == Group::Enable
            || (local == Group::Inherit && source == Group::Enable));
    }
    const auto key = BrowserService::OPTION_RESTRICT_KEY;
    const auto connection = data->value(key);
    QJsonArray connections;
    for (const auto& name : db->metadata()->customData()->keys()) if (name.startsWith(CustomData::BrowserKeyPrefix))
        connections.append(name.mid(CustomData::BrowserKeyPrefix.size()));
    QJsonObject restriction{{"inherited", parent ? parent->resolveCustomDataString(key) : QString()},
                            {"connections", connections}};
    if (target.entry) {
        restriction.insert("mode", "inherit"); restriction.insert("id", QString());
    } else {
        restriction.insert("mode", !data->contains(key) ? "inherit" : connection.isEmpty() ? "all" : "connection");
        restriction.insert("id", connection);
    }
    return {{"values", values}, {"inherited", inherited}, {"effective", effective}, {"forced", forced},
            {"restriction", restriction}, {"revision", QString::fromLatin1(fingerprint.toHex())}};
}

void KeyslotBrowserDatabase::saveOptions(const QSharedPointer<Database>& db, const QJsonObject& args,
                                         const QByteArray& fingerprint,
                                         const std::function<void(const std::function<void()>&)>& commit) {
    if (text(args, "revision", true) != QString::fromLatin1(fingerprint.toHex()))
        reject("conflict", "The database changed since browser settings were opened. Open them again before saving.");
    const auto target = optionTarget(db, args);
    if (!args.value("values").isObject()) reject("invalid_request", "Specify the browser options to change.");
    QMap<QString, int> changes;
    const auto values = args.value("values").toObject();
    const auto& browserOptions = optionNames();
    for (auto it = values.begin(); it != values.end(); ++it) {
        const auto value = it.value().toDouble(-1);
        if (!browserOptions.contains(it.key()) || (target.entry && it.key() == "omit_www") || !it.value().isDouble()
            || !std::isfinite(value) || std::floor(value) != value || value < 0 || value > 2)
            reject("invalid_request", "Choose supported browser settings.");
        const auto key = browserOptions.value(it.key());
        const auto* data = target.data();
        if (int(value) == Group::Inherit ? data->contains(key)
            : !data->contains(key) || data->value(key) != (int(value) == Group::Enable ? TRUE_STR : FALSE_STR))
            changes.insert(key, int(value));
    }
    const auto key = BrowserService::OPTION_RESTRICT_KEY;
    bool restrict = false;
    QString mode, id;
    if (args.contains("restriction")) {
        if (target.entry || !args.value("restriction").isObject())
            reject("invalid_request", "Connection restrictions belong to groups.");
        const auto value = args.value("restriction").toObject();
        for (const auto& name : value.keys()) if (name != "mode" && name != "id")
            reject("invalid_request", "Choose a supported connection restriction.");
        mode = text(value, "mode", true); id = text(value, "id");
        if ((mode != "inherit" && mode != "all" && mode != "connection") || (mode != "connection" && !id.isEmpty()))
            reject("invalid_request", "Choose a supported connection restriction.");
        if (mode == "connection" && (id.isEmpty() || !db->metadata()->customData()->contains(CustomData::BrowserKeyPrefix + id)))
            reject("not_found", "This browser connection is no longer paired. Choose another connection.");
        restrict = mode == "inherit" ? target.data()->contains(key)
            : !target.data()->contains(key) || target.data()->value(key) != id;
    }
    if (changes.isEmpty() && !restrict) return;
    commit([&] {
        if (target.entry) target.entry->beginUpdate();
        for (auto it = changes.cbegin(); it != changes.cend(); ++it) {
            if (target.group) target.group->setCustomDataTriState(it.key(), Group::TriState(it.value()));
            else if (it.value() == Group::Inherit) target.data()->remove(it.key());
            else target.data()->set(it.key(), it.value() == Group::Enable ? TRUE_STR : FALSE_STR);
        }
        if (restrict) {
            if (mode == "inherit") target.data()->remove(key);
            else target.data()->set(key, id);
        }
        if (target.entry) target.entry->endUpdate();
    });
}

QJsonObject KeyslotBrowserDatabase::prepareDelete(const QSharedPointer<Database>& db, const QJsonObject& args,
                                                  const QByteArray& fingerprint) {
    const auto id = text(args, "id", true), key = text(args, "key", true);
    authenticate(db, id, key);
    const auto uuid = text(args, "entry", true);
    if (!Tools::isValidUuid(uuid)) reject("invalid_uuid", "The browser supplied an invalid entry identifier.");
    auto* entry = db->rootGroup()->findEntryByUuid(Tools::hexToUuid(uuid));
    if (!entry) return {{"found", false}};
    const auto now = clock.elapsed();
    for (auto it = deletions.begin(); it != deletions.end();) {
        if (it->expires <= now || it->database.isNull()) it = deletions.erase(it);
        else ++it;
    }
    if (deletions.size() >= 128) reject("busy", "Too many browser deletions are waiting for confirmation.");
    const auto token = QUuid::createUuid().toString(QUuid::WithoutBraces);
    deletions.insert(token, {db, fingerprint, id, key, uuid, now + 30000});
    return {{"found", true}, {"token", token}, {"title", entry->title()}, {"group", entry->group()->fullPath()},
            {"permanent", !db->metadata()->recycleBinEnabled()}};
}

bool KeyslotBrowserDatabase::remove(const QSharedPointer<Database>& db, const QJsonObject& args,
        const QByteArray& fingerprint, const std::function<void(const std::function<void()>&)>& commit) {
    const auto token = text(args, "token", true);
    if (!deletions.contains(token)) reject("expired", "The browser deletion confirmation is no longer valid.");
    const auto request = deletions.take(token);
    if (request.database.toStrongRef() != db || request.fingerprint != fingerprint || request.expires <= clock.elapsed())
        reject("conflict", "The database changed or the deletion confirmation expired. Try again.");
    authenticate(db, request.id, request.key);
    if (!flag(args, "approved")) return false;
    auto* entry = db->rootGroup()->findEntryByUuid(Tools::hexToUuid(request.entry));
    if (!entry) return false;
    if (entry->isRecycled() && db->metadata()->recycleBinEnabled()) return true;
    commit([&] { db->recycleEntry(entry); });
    return true;
}

QString KeyslotBrowserDatabase::totp(const QSharedPointer<Database>& db, const QJsonObject& args) {
    const auto id = text(args, "id", true), key = text(args, "key", true);
    authenticate(db, id, key);
    const auto uuid = text(args, "entry", true);
    if (!Tools::isValidUuid(uuid)) reject("invalid_uuid", "The browser supplied an invalid entry identifier.");
    // Keep the upstream group/entry visibility and connection-key restrictions for direct UUID requests.
    const auto matches = service.searchEntries(db, "keepassxc://by-uuid/" + uuid, QString(), QStringList{id});
    return matches.isEmpty() ? QString() : matches.first()->totp();
}

QJsonObject KeyslotBrowserDatabase::databaseGroups(const QSharedPointer<Database>& db, const QJsonObject& args) {
    authenticate(db, text(args, "id", true), text(args, "key", true));
    auto* root = db->rootGroup();
    return {{"groups", QJsonArray{QJsonObject{{"name", root->name()}, {"uuid", root->uuidToHex()},
                                             {"children", service.getChildrenFromGroup(root)}}}}};
}

// Field names, resolution and ordering follow KeePassXC 2.8 BrowserService::getDatabaseEntries
// (KeePassXC Team, GPL-3.0-or-later); this opt-in grants an inventory beyond site-matched filling.
QJsonArray KeyslotBrowserDatabase::databaseEntries(const QSharedPointer<Database>& db, const QJsonObject& args) {
    authenticate(db, text(args, "id", true), text(args, "key", true));
    if (!flag(args, "allowed")) reject("listing_denied", "Access to all entries is denied.");
    QJsonArray entries;
    qint64 bytes = 32;
    for (const auto* group : db->rootGroup()->groupsRecursive(true)) {
        if (group == db->metadata()->recycleBin()) continue;
        for (const auto* entry : group->entries()) {
            const QJsonObject item{{"title", entry->resolveMultiplePlaceholders(entry->title())},
                                   {"uuid", entry->uuidToHex()},
                                   {"url", entry->resolveMultiplePlaceholders(entry->url())}};
            bytes += QJsonDocument(item).toJson(QJsonDocument::Compact).size() + 1;
            if (bytes > BrowserShared::SOCKET_BUFFER_SIZE / 2 - 1024)
                reject("too_large", "The entry list exceeds the browser message limit.");
            entries.append(item);
        }
    }
    if (entries.isEmpty()) reject("no_groups", "No groups found.");
    return entries;
}

QJsonObject KeyslotBrowserDatabase::prepareGroup(const QSharedPointer<Database>& db, const QJsonObject& args,
                                                 const QByteArray& fingerprint) {
    const auto id = text(args, "id", true), key = text(args, "key", true);
    authenticate(db, id, key);
    const auto path = groupPath(text(args, "name", true));
    const auto components = path.split('/');
    QString prefix;
    for (const auto& component : components) {
        prefix += (prefix.isEmpty() ? "" : "/") + component;
        const auto existing = db->rootGroup()->findGroupByPath(prefix);
        if (existing && existing->isRecycled()) reject("denied", "Choose a group outside the recycle bin.");
    }
    if (auto* existing = db->rootGroup()->findGroupByPath(path))
        return {{"exists", true}, {"name", existing->name()}, {"uuid", existing->uuidToHex()}};
    const auto now = clock.elapsed();
    for (auto it = groups.begin(); it != groups.end();) {
        if (it->expires <= now || it->database.isNull()) it = groups.erase(it);
        else ++it;
    }
    if (groups.size() >= 128) reject("busy", "Too many browser group requests are waiting for confirmation.");
    const auto token = QUuid::createUuid().toString(QUuid::WithoutBraces);
    groups.insert(token, {db, fingerprint, id, key, path, now + 30000});
    return {{"exists", false}, {"token", token}, {"path", path}, {"database", db->metadata()->name()}};
}

Group* KeyslotBrowserDatabase::ensureGroup(const QSharedPointer<Database>& db, const QString& requestedPath, bool passkey) {
    Group* previous = db->rootGroup();
    QString path;
    for (const auto& name : requestedPath.split('/')) {
        path += (path.isEmpty() ? "" : "/") + name;
        auto* group = db->rootGroup()->findGroupByPath(path);
        if (!group) {
            group = new Group();
            group->setName(name);
            group->setUuid(QUuid::createUuid());
            group->setParent(previous);
            group->setCustomDataTriState(BrowserService::OPTION_HIDE_ENTRY, Group::Disable);
            if (passkey && path == requestedPath) group->setIcon(13);
        }
        previous = group;
    }
    return previous;
}

QJsonObject KeyslotBrowserDatabase::createGroup(const QSharedPointer<Database>& db, const QJsonObject& args,
        const QByteArray& fingerprint, const std::function<void(const std::function<void()>&)>& commit) {
    const auto token = text(args, "token", true);
    if (!groups.contains(token)) reject("expired", "The browser group confirmation is no longer valid.");
    const auto request = groups.take(token);
    if (request.database.toStrongRef() != db || request.fingerprint != fingerprint || request.expires <= clock.elapsed())
        reject("conflict", "The database changed or the group confirmation expired. Try again.");
    authenticate(db, request.id, request.key);
    if (!flag(args, "approved")) return {};
    Group* previous = nullptr;
    commit([&] { previous = ensureGroup(db, request.path); });
    return {{"name", previous->name()}, {"uuid", previous->uuidToHex()}};
}

QJsonObject KeyslotBrowserDatabase::prepareSave(const QSharedPointer<Database>& db, const QJsonObject& args,
                                                const QByteArray& fingerprint) {
    const auto id = text(args, "id", true), key = text(args, "key", true);
    authenticate(db, id, key);
    const auto site = text(args, "url", true), form = text(args, "submit_url");
    const QUrl url(site), formUrl(form);
    if (!validUrl(url) || (!form.isEmpty() && !validUrl(formUrl)))
        reject("invalid_request", "The browser supplied an invalid website address.");
    const auto uuid = text(args, "entry");
    if (!uuid.isEmpty() && !Tools::isValidUuid(uuid))
        reject("invalid_request", "The browser supplied an invalid entry identifier.");
    auto* entry = uuid.isEmpty() ? nullptr : db->rootGroup()->findEntryByUuid(Tools::hexToUuid(uuid));
    QSet<QUuid> visited;
    while (entry) {
        if (entry->isRecycled() || visited.contains(entry->uuid()))
            reject("denied", "The requested entry is recycled or has a circular password reference.");
        visited.insert(entry->uuid());
        if (!entry->attributes()->isReference(EntryAttributes::PasswordKey)) break;
        const auto reference = entry->attributes()->referenceUuid(EntryAttributes::PasswordKey);
        entry = reference.isNull() ? nullptr : db->rootGroup()->findEntryByUuid(reference);
        if (!entry) reject("not_found", "The original password entry could not be found.");
    }
    if (entry && entry->username().isEmpty()) reject("denied", "This entry has no username to update.");
    const auto login = text(args, "login"), password = text(args, "password");
    if (keyslotBrowserHasPlaceholder(login) || keyslotBrowserHasPlaceholder(password))
        reject("references_not_allowed", "Browser-supplied credentials cannot contain field placeholders or references.");
    const auto now = clock.elapsed();
    for (auto it = saves.begin(); it != saves.end();) {
        if (it->expires <= now || it->database.isNull()) it = saves.erase(it);
        else ++it;
    }
    if (saves.size() >= 128) reject("busy", "Too many browser saves are waiting for confirmation.");
    SaveRequest request{db, fingerprint, id, key, site, form, login, password,
        entry ? entry->uuidToHex() : QString(), {},
        !entry || entry->username() != login || entry->password() != password, now + 30000};
    QJsonArray groups;
    for (auto* group : db->rootGroup()->groupsRecursive(true)) {
        if (group->isRecycled()) continue;
        request.groups.insert(group->uuidToHex());
        groups.append(QJsonObject{{"uuid", group->uuidToHex()}, {"name", group->fullPath()}});
    }
    const auto requestedGroup = text(args, "group_uuid");
    const auto token = QUuid::createUuid().toString(QUuid::WithoutBraces);
    saves.insert(token, request);
    return {{"token", token}, {"changed", request.changed}, {"update", bool(entry)},
        {"title", entry ? entry->title() : url.host()}, {"username", login}, {"url", site}, {"submit_url", form},
        {"entry_url", entry ? entry->url() : QString()}, {"reference", entry && entry->uuidToHex() != uuid},
        {"group", entry ? entry->group()->fullPath() : QString()}, {"groups", groups},
        {"selected_group", request.groups.contains(requestedGroup) ? requestedGroup : QString()}};
}

bool KeyslotBrowserDatabase::save(const QSharedPointer<Database>& db, const QJsonObject& args,
        const QByteArray& fingerprint, const std::function<void(const std::function<void()>&)>& commit, QString* savedEntry) {
    if (savedEntry) savedEntry->clear();
    const auto token = text(args, "token", true);
    if (!saves.contains(token)) reject("expired", "The browser save confirmation is no longer valid.");
    const auto request = saves.take(token);
    if (request.database.toStrongRef() != db || request.fingerprint != fingerprint || request.expires <= clock.elapsed())
        reject("conflict", "The database changed or the browser save confirmation expired. Try again.");
    authenticate(db, request.id, request.key);
    if (!flag(args, "approved") || !request.changed) return false;
    const auto group = text(args, "group");
    if (!group.isEmpty() && !request.groups.contains(group))
        reject("denied", "Choose a group from this browser save request.");
    auto* entry = request.target.isEmpty() ? nullptr : db->rootGroup()->findEntryByUuid(Tools::hexToUuid(request.target));
    if (!request.target.isEmpty() && (!entry || entry->isRecycled()))
        reject("not_found", "The entry is no longer available.");
    commit([&] {
        if (entry) {
            entry->beginUpdate();
            if (!entry->attributes()->isReference(EntryAttributes::UserNameKey)) entry->setUsername(request.login);
            entry->setPassword(request.password);
            entry->endUpdate();
        } else {
            QSet<const Entry*> previous;
            if (savedEntry) for (const auto* item : db->rootGroup()->entriesRecursive()) previous.insert(item);
            EntryParameters parameters{};
            parameters.dbid = request.id;
            parameters.login = request.login;
            parameters.password = request.password;
            parameters.siteUrl = request.site;
            parameters.formUrl = request.form;
            service.addEntry(parameters, group, group, false, db);
            if (savedEntry) {
                for (auto* item : db->rootGroup()->entriesRecursive()) if (!previous.contains(item)) {
                    if (entry) reject("conflict", "The new browser entry could not be identified unambiguously.");
                    entry = item;
                }
                if (!entry) reject("not_found", "The new browser entry could not be identified.");
            }
        }
    });
    if (savedEntry) *savedEntry = entry->uuid().toString(QUuid::WithoutBraces);
    return true;
}

QJsonObject KeyslotBrowserDatabase::lookup(const QSharedPointer<Database>& db, const QJsonObject& args,
                                          const QByteArray& fingerprint) {
    const auto id = text(args, "id", true), key = text(args, "key", true);
    authenticate(db, id, key);
    const auto site = text(args, "url", true), form = text(args, "submit_url");
    const QUrl siteUrl(site), formUrl(form);
    if (!validUrl(siteUrl) || (!form.isEmpty() && !validUrl(formUrl)))
        reject("invalid_request", "The browser supplied an invalid website address.");
    const auto realm = text(args, "realm");
    const bool httpAuth = flag(args, "http_auth");
    browserSettings()->setMatchUrlScheme(flag(args, "match_scheme", true));
    // Best-match reduction belongs after selection/permission checks, as in upstream findEntries.
    browserSettings()->setBestMatchOnly(false);
    browserSettings()->setAllowExpiredCredentials(flag(args, "allow_expired"));
    browserSettings()->setSupportKphFields(flag(args, "custom_fields", true));

    const auto now = clock.elapsed();
    for (auto it = requests.begin(); it != requests.end();) {
        if (it->expires <= now || it->database.isNull()) it = requests.erase(it);
        else ++it;
    }
    if (requests.size() >= 128) reject("busy", "Too many browser requests are waiting for confirmation.");
    Request request{db, fingerprint, id, key, site, form, siteUrl.host(), formUrl.host(), realm,
        flag(args, "best_match"), flag(args, "allow_expired"), flag(args, "custom_fields", true), {}, now + 30000};
    auto candidates = service.searchEntries(db, site, form, QStringList{id});
    candidates = service.sortEntries(candidates, site, form);
    const bool connectionTrusted = trusted(db, id, key);
    QJsonArray entries;
    for (auto* entry : candidates) {
        const auto* data = entry->customData();
        if ((!httpAuth && (data->value(BrowserService::OPTION_ONLY_HTTP_AUTH) == "true"
                         || entry->group()->resolveCustomDataTriState(BrowserService::OPTION_ONLY_HTTP_AUTH) == Group::Enable))
            || (httpAuth && (data->value(BrowserService::OPTION_NOT_HTTP_AUTH) == "true"
                         || entry->group()->resolveCustomDataTriState(BrowserService::OPTION_NOT_HTTP_AUTH) == Group::Enable))) continue;
        const auto access = service.checkAccess(entry, request.siteHost, request.formHost, realm);
        if (access == BrowserService::Denied) continue;
        const bool allowed = connectionTrusted || (access == BrowserService::Allowed && !httpAuth);
        request.entries.insert(entry->uuidToHex(), allowed);
        // Raw display fields cannot expand a password reference before consent.
        entries.append(QJsonObject{{"uuid", entry->uuidToHex()}, {"title", entry->title()},
            {"username", entry->username()}, {"group", entry->group()->name()}, {"allowed", allowed}});
    }
    const auto token = QUuid::createUuid().toString(QUuid::WithoutBraces);
    requests.insert(token, request);
    return {{"token", token}, {"entries", entries}};
}

QJsonArray KeyslotBrowserDatabase::release(const QSharedPointer<Database>& db, const QJsonObject& args,
        const QByteArray& fingerprint, const std::function<void(const std::function<void()>&)>& commit) {
    const auto token = text(args, "token", true);
    if (!requests.contains(token)) reject("expired", "The browser confirmation is no longer valid.");
    const auto request = requests.take(token);
    if (request.database.toStrongRef() != db || request.fingerprint != fingerprint
        || request.expires <= clock.elapsed())
        reject("conflict", "The database changed or the browser confirmation expired. Try again.");
    authenticate(db, request.id, request.key);
    browserSettings()->setBestMatchOnly(request.bestMatch);
    browserSettings()->setAllowExpiredCredentials(request.allowExpired);
    browserSettings()->setSupportKphFields(request.customFields);
    if (!args.value("entries").isArray()) reject("invalid_request", "Select browser entries explicitly.");
    const bool approved = flag(args, "approved"), remember = flag(args, "remember"), denied = flag(args, "deny");
    const bool trust = flag(args, "trust");
    if (approved && denied) reject("invalid_request", "Choose one browser access decision.");
    if (trust && (!approved || denied)) reject("denied", "Trusting a browser requires explicit approval.");
    QSet<QString> selected;
    QList<Entry*> entries;
    for (const auto& value : args.value("entries").toArray()) {
        const auto uuid = value.toString();
        if (!value.isString() || !request.entries.contains(uuid) || selected.contains(uuid))
            reject("denied", "An entry was not part of this browser request.");
        if (!denied && !request.entries.value(uuid) && !approved)
            reject("denied", "This browser request requires confirmation.");
        auto* entry = db->rootGroup()->findEntryByUuid(Tools::hexToUuid(uuid));
        if (!entry || entry->isRecycled()) reject("not_found", "A requested browser entry is no longer available.");
        if (service.checkAccess(entry, request.siteHost, request.formHost, request.realm) == BrowserService::Denied)
            reject("denied", "The requested browser entry is no longer permitted.");
        selected.insert(uuid);
        entries.append(entry);
    }
    if (trust && entries.isEmpty()) reject("denied", "Select an entry before trusting this browser.");
    if ((remember || trust) && !entries.isEmpty()) {
        if (!approved && !denied) reject("denied", "Saving browser permissions requires confirmation.");
        commit([&] {
            if (trust) db->metadata()->customData()->set(trustKey(request.id), connectionRevision(request.key));
            for (auto* entry : entries) {
                if (!remember) continue;
                if (denied) service.denyEntry(entry, request.siteHost, request.formHost, request.realm);
                else service.allowEntry(entry, request.siteHost, request.formHost, request.realm);
            }
        });
    }
    QJsonArray result;
    if (denied) return result;
    entries = service.sortEntries(entries, request.site, request.form);
    for (auto* entry : entries) result.append(service.prepareEntry(entry));
    return result;
}
