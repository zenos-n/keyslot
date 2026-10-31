// SPDX-License-Identifier: GPL-3.0-only
#include "BrowserDatabase.h"
#include "KeyslotBrowserValues.h"
#include "browser/BrowserSettings.h"
#include "core/CustomData.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/EntryAttributes.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "core/Tools.h"
#include <QDateTime>
#include <QSet>
#include <QUrl>
#include <QUuid>

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
    QJsonArray entries;
    for (auto* entry : candidates) {
        const auto* data = entry->customData();
        if ((!httpAuth && (data->value(BrowserService::OPTION_ONLY_HTTP_AUTH) == "true"
                         || entry->group()->resolveCustomDataTriState(BrowserService::OPTION_ONLY_HTTP_AUTH) == Group::Enable))
            || (httpAuth && (data->value(BrowserService::OPTION_NOT_HTTP_AUTH) == "true"
                         || entry->group()->resolveCustomDataTriState(BrowserService::OPTION_NOT_HTTP_AUTH) == Group::Enable))) continue;
        const auto access = service.checkAccess(entry, request.siteHost, request.formHost, realm);
        if (access == BrowserService::Denied) continue;
        const bool allowed = access == BrowserService::Allowed && !httpAuth;
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
    if (approved && denied) reject("invalid_request", "Choose one browser access decision.");
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
    if (remember && !entries.isEmpty()) {
        if (!approved && !denied) reject("denied", "Saving browser permissions requires confirmation.");
        commit([&] {
            for (auto* entry : entries) {
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
