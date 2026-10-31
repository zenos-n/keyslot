// SPDX-License-Identifier: GPL-3.0-only
// Item conventions and session crypto are reused from the pinned GPL upstream implementation.
#include "KeyslotSecrets.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/EntryAttributes.h"
#include "core/EntrySearcher.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "fdosecrets/FdoSecretsSettings.h"
#include "fdosecrets/objects/Collection.h"
#include "fdosecrets/objects/Item.h"
#include "fdosecrets/objects/SessionCipher.h"
#include <QJsonArray>
#include <QRegularExpression>

namespace FdoSecrets {
    DBusResult setEntrySecret(Entry* entry, const QByteArray& data, const QString& contentType);
    Secret getEntrySecret(Entry* entry);
}
namespace {
constexpr int MaxSecret = 8 * 1024 * 1024;
[[noreturn]] void reject(const char* code, const char* message) { throw SecretFailure{code, message}; }
QString text(const QJsonObject& o, const char* name, int maximum = 65536, const QString& fallback = {}) {
    if (!o.contains(name)) return fallback;
    if (!o.value(name).isString() || o.value(name).toString().size() > maximum || o.value(name).toString().contains(QChar('\0')))
        reject("invalid_request", "A Secret Service text field is invalid.");
    return o.value(name).toString();
}
QString peer(const QJsonObject& args) {
    const auto value = text(args, "peer", 255);
    if (!QRegularExpression("^:[A-Za-z0-9_-]+(?:\\.[A-Za-z0-9_-]+)+$").match(value).hasMatch())
        reject("invalid_request", "A Secret Service peer is invalid.");
    return value;
}
bool flag(const QJsonObject& args, const char* name, bool fallback = false) {
    if (!args.contains(name)) return fallback;
    if (!args.value(name).isBool()) reject("invalid_request", "A Secret Service switch is invalid.");
    return args.value(name).toBool();
}
QByteArray bytes(const QJsonObject& args, const char* name, int maximum = MaxSecret) {
    const auto value = text(args, name, (maximum + 2) / 3 * 4);
    const auto raw = value.toLatin1();
    const auto result = QByteArray::fromBase64(raw, QByteArray::AbortOnBase64DecodingErrors);
    if (result.size() > maximum || result.toBase64() != raw)
        reject("invalid_request", "A Secret Service byte field is invalid or too large.");
    return result;
}
QString uid(const QUuid& value) { return value.toString(QUuid::WithoutBraces); }
QJsonObject attributes(const QJsonObject& args) {
    if (!args.value("attributes").isObject() || args.value("attributes").toObject().size() > 1024)
        reject("invalid_request", "Secret Service attributes must be a text dictionary.");
    auto result = args.value("attributes").toObject();
    for (auto it = result.begin(); it != result.end(); ++it) {
        if (it.key().isEmpty() || it.key().size() > 1024 || it.key().contains(QChar('\0')) || !it.value().isString()
            || it.value().toString().size() > 65536 || it.value().toString().contains(QChar('\0')))
            reject("invalid_request", "A Secret Service lookup attribute is invalid.");
    }
    return result;
}
void setAttributes(Entry* entry, const QJsonObject& values, bool creating = false) {
    EntryAttributes candidate;
    candidate.copyDataFrom(entry->attributes());
    for (auto it = values.begin(); it != values.end(); ++it) {
        if (it.key() == "Uuid" || it.key() == "Path" || it.key() == "TOTP") {
            if (creating) continue;
            reject("invalid_request", "A read-only Secret Service attribute cannot be changed.");
        }
        if (it.key() == EntryAttributes::PasswordKey || candidate.isProtected(it.key())
            || EntryAttributes::matchReference(it.value().toString()).hasMatch())
            reject("invalid_request", "Protected fields and references cannot be assigned through lookup attributes.");
        candidate.set(it.key(), it.value().toString());
    }
    entry->attributes()->copyDataFrom(&candidate);
}
void setSecret(Entry* entry, const QJsonObject& args) {
    const auto value = bytes(args, "value");
    if (EntryAttributes::matchReference(value).hasMatch())
        reject("invalid_request", "Secret Service secrets cannot contain KeePass reference expressions.");
    if (!FdoSecrets::setEntrySecret(entry, value, text(args, "content_type", 1024, "text/plain")).ok())
        reject("invalid_request", "The secret content type or value is invalid.");
}
void setLabel(Entry* entry, const QString& label) {
    if (EntryAttributes::matchReference(label).hasMatch())
        reject("invalid_request", "Secret Service labels cannot contain KeePass reference expressions.");
    entry->setTitle(label);
}
QJsonObject publicAttributes(const Entry* entry, const Group* root, bool authorized) {
    QJsonObject attrs;
    for (const auto& name : entry->attributes()->keys()) {
        if (name == EntryAttributes::PasswordKey || entry->attributes()->isProtected(name)) continue;
        // Lookup metadata is literal: resolving references here could reveal a protected value before consent.
        attrs.insert(name, entry->attribute(name));
    }
    attrs.insert("Uuid", entry->uuidToHex());
    QStringList components{entry->title()};
    for (const auto* group = entry->group(); group && group != root; group = group->parentGroup()) components.prepend(group->name());
    attrs.insert("Path", "/" + components.join('/'));
    if (authorized && entry->hasValidTotp()) attrs.insert("TOTP", entry->totp());
    return attrs;
}
}

QJsonObject KeyslotSecretSessions::call(const QString& method, const QJsonObject& args) {
    const auto caller = peer(args);
    if (method == "secret.session.drop-peer") {
        for (auto it = sessions.begin(); it != sessions.end();) {
            if (it.value().peer == caller) it = sessions.erase(it); else ++it;
        }
        return {};
    }
    if (method == "secret.session.open") {
        int count = 0;
        for (const auto& session : sessions) if (session.peer == caller) ++count;
        if (count >= 16 || sessions.size() >= 256) reject("busy", "There are too many Secret Service sessions.");
        const auto algorithm = text(args, "algorithm", 128);
        QSharedPointer<FdoSecrets::CipherPair> cipher;
        if (algorithm == FdoSecrets::PlainCipher::Algorithm) {
            if (!text(args, "input", 0).isEmpty()) reject("invalid_request", "Plain sessions require an empty negotiation input.");
            cipher.reset(new FdoSecrets::PlainCipher());
        } else if (algorithm == FdoSecrets::DhIetf1024Sha256Aes128CbcPkcs7::Algorithm) {
            const auto input = bytes(args, "input", 128);
            if (input.isEmpty()) reject("invalid_request", "The Secret Service DH public key is empty.");
            cipher.reset(new FdoSecrets::DhIetf1024Sha256Aes128CbcPkcs7(input));
        } else reject("unsupported", "This Secret Service session algorithm is unsupported.");
        if (!cipher->isValid()) reject("invalid_request", "The Secret Service session negotiation failed.");
        const auto identifier = QUuid::createUuid().toString(QUuid::WithoutBraces).remove('-');
        const bool plain = algorithm == FdoSecrets::PlainCipher::Algorithm;
        sessions.insert(identifier, {caller, cipher, plain});
        return {{"session", identifier}, {"plain", plain},
            {"output", plain ? QString() : QString::fromLatin1(cipher->negotiationOutput().toByteArray().toBase64())}};
    }
    const auto identifier = text(args, "session", 64);
    auto found = sessions.find(identifier);
    if (found == sessions.end() || found->peer != caller) reject("no_session", "The Secret Service session does not belong to this caller.");
    if (method == "secret.session.close") { sessions.erase(found); return {}; }
    FdoSecrets::Secret secret{};
    secret.value = bytes(args, "value", MaxSecret + 16);
    secret.parameters = bytes(args, "parameters", 16);
    secret.contentType = text(args, "content_type", 1024, "text/plain");
    if (method == "secret.session.encode") {
        if (!secret.parameters.isEmpty() || secret.value.size() > MaxSecret)
            reject("invalid_request", "The plaintext secret parameters are invalid.");
        secret = found->cipher->encrypt(secret);
        if (!found->plain && (secret.parameters.size() != 16 || secret.value.isEmpty() || secret.value.size() % 16))
            reject("crypto_error", "The Secret Service secret could not be encrypted.");
    } else if (method == "secret.session.decode") {
        if ((found->plain && !secret.parameters.isEmpty()) || (!found->plain
            && (secret.parameters.size() != 16 || secret.value.isEmpty() || secret.value.size() % 16)))
            reject("invalid_request", "The encrypted secret parameters are invalid.");
        secret = found->cipher->decrypt(secret);
        // Upstream leaves the original IV in place on a decryption/padding failure.
        if (!secret.parameters.isEmpty() || secret.value.size() > MaxSecret)
            reject("crypto_error", "The Secret Service secret could not be decrypted.");
    } else reject("invalid_request", "Unknown Secret Service session operation.");
    return {{"value", QString::fromLatin1(secret.value.toBase64())},
            {"parameters", QString::fromLatin1(secret.parameters.toBase64())}, {"content_type", secret.contentType}};
}

void KeyslotSecrets::clear() { pending.clear(); grants.clear(); }
void KeyslotSecrets::dropPeer(const QString& caller) {
    grants.remove(caller);
    for (auto it = pending.begin(); it != pending.end();) {
        if (it.value().peer == caller) it = pending.erase(it); else ++it;
    }
}
void KeyslotSecrets::configure(const QJsonObject& args) {
    const auto confirm = flag(args, "confirm_access", true);
    const auto instance = text(args, "instance", 128);
    if (confirm != confirmAccess || instance != providerInstance) clear();
    confirmAccess = confirm;
    providerInstance = instance;
}
Group* KeyslotSecrets::root(const QSharedPointer<Database>& db) const {
    const auto id = FdoSecrets::settings()->exposedGroup(db);
    auto* result = id.isNull() ? nullptr : db->rootGroup()->findGroupByUuid(id);
    if (!result || result->isRecycled()) reject("disabled", "This vault has no exposed Secret Service group.");
    return result;
}
Entry* KeyslotSecrets::item(const QSharedPointer<Database>& db, const QString& identifier) const {
    auto* exposed = root(db);
    const QUuid id(identifier);
    auto* result = id.isNull() ? nullptr : exposed->findEntryByUuid(id);
    if (!result || result->isRecycled()) reject("not_found", "The Secret Service item is no longer exposed.");
    return result;
}
bool KeyslotSecrets::authorized(const QString& caller, const QUuid& identifier) const {
    const auto& grant = grants.value(caller);
    return !confirmAccess || grant.allowed.contains(identifier) || grant.once.contains(identifier);
}
bool KeyslotSecrets::consume(const QString& caller, const QUuid& identifier) {
    const bool result = authorized(caller, identifier);
    if (grants.contains(caller)) grants[caller].once.remove(identifier);
    return result;
}
QJsonObject KeyslotSecrets::settings(const QSharedPointer<Database>& db) const {
    const auto id = FdoSecrets::settings()->exposedGroup(db);
    return {{"group", id.isNull() ? QString() : uid(id)}};
}
void KeyslotSecrets::saveSettings(const QSharedPointer<Database>& db, const QJsonObject& args) {
    const auto value = text(args, "group", 64);
    const QUuid id(value);
    if (!value.isEmpty()) {
        auto* group = id.isNull() ? nullptr : db->rootGroup()->findGroupByUuid(id);
        if (!group || group->isRecycled()) reject("invalid_request", "Choose an exposed group outside the recycle bin.");
    }
    FdoSecrets::settings()->setExposedGroup(db, id);
    clear();
}
QJsonObject KeyslotSecrets::info(const QSharedPointer<Database>& db, const QJsonObject& args) {
    const auto caller = peer(args);
    auto* exposed = root(db);
    if (args.contains("entry")) {
        const auto* entry = item(db, text(args, "entry", 64));
        const auto& grant = grants.value(caller);
        const bool totp = flag(args, "include_totp") && entry->hasValidTotp()
            && (!confirmAccess || grant.allowed.contains(entry->uuid()) || grant.onceTotp.contains(entry->uuid()));
        if (totp && grants.contains(caller)) grants[caller].onceTotp.remove(entry->uuid());
        return {{"entry", uid(entry->uuid())}, {"label", entry->title()}, {"locked", !authorized(caller, entry->uuid())},
            {"attributes", publicAttributes(entry, exposed, totp)},
            {"created", entry->timeInfo().creationTime().toSecsSinceEpoch()},
            {"modified", entry->timeInfo().lastModificationTime().toSecsSinceEpoch()}};
    }
    QJsonArray items;
    for (const auto* entry : exposed->entriesRecursive(false)) if (!entry->isRecycled()) items.append(uid(entry->uuid()));
    return {{"group", uid(exposed->uuid())}, {"label", db->metadata()->name()}, {"items", items},
            {"created", db->rootGroup()->timeInfo().creationTime().toSecsSinceEpoch()},
            {"modified", db->rootGroup()->timeInfo().lastModificationTime().toSecsSinceEpoch()}};
}
QJsonObject KeyslotSecrets::search(const QSharedPointer<Database>& db, const QJsonObject& args) const {
    const auto caller = peer(args);
    const auto values = attributes(args);
    auto* exposed = root(db);
    QList<Entry*> matches;
    if (values.contains("Uuid")) {
        const auto id = QUuid::fromRfc4122(QByteArray::fromHex(values.value("Uuid").toString().toLatin1()));
        if (auto* entry = exposed->findEntryByUuid(id)) matches.append(entry);
    } else if (values.contains("Path")) {
        if (auto* entry = exposed->findEntryByPath(values.value("Path").toString())) matches.append(entry);
    } else {
        for (auto* entry : exposed->entriesRecursive(false)) {
            const auto publicValues = publicAttributes(entry, exposed, false);
            bool match = true;
            for (auto it = values.begin(); it != values.end(); ++it) {
                const auto term = FdoSecrets::Collection::attributeToTerm(it.key(), it.value().toString());
                if (!publicValues.contains(it.key()) || !term.regex.match(publicValues.value(it.key()).toString()).hasMatch()) {
                    match = false;
                    break;
                }
            }
            if (match) matches.append(entry);
        }
    }
    QJsonArray unlocked, locked, all;
    for (const auto* entry : matches) {
        if (entry->isRecycled() || exposed->findEntryByUuid(entry->uuid()) != entry) continue;
        all.append(uid(entry->uuid()));
        (authorized(caller, entry->uuid()) ? unlocked : locked).append(uid(entry->uuid()));
    }
    return {{"unlocked", unlocked}, {"locked", locked}, {"all", all}};
}
QJsonObject KeyslotSecrets::get(const QSharedPointer<Database>& db, const QJsonObject& args) {
    const auto caller = peer(args);
    if (!args.value("entries").isArray() || args.value("entries").toArray().size() > 1024)
        reject("invalid_request", "Choose a bounded list of Secret Service items.");
    QJsonArray result;
    int size = 0;
    for (const auto& value : args.value("entries").toArray()) {
        if (!value.isString()) reject("invalid_request", "A Secret Service item identifier is invalid.");
        auto* entry = item(db, value.toString());
        if (!consume(caller, entry->uuid())) {
            if (flag(args, "skip_locked")) continue;
            reject("denied", "Authorize this Secret Service item before reading its secret.");
        }
        const auto secret = FdoSecrets::getEntrySecret(entry);
        size += secret.value.size();
        if (secret.value.size() > MaxSecret || size > 24 * 1024 * 1024)
            reject("invalid_request", "This Secret Service transfer is too large.");
        result.append(QJsonObject{{"entry", uid(entry->uuid())}, {"value", QString::fromLatin1(secret.value.toBase64())},
                                  {"content_type", secret.contentType}});
    }
    return {{"secrets", result}};
}
QJsonObject KeyslotSecrets::prepare(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint) {
    const auto caller = peer(args), kind = text(args, "kind", 32);
    root(db);
    for (auto it = pending.begin(); it != pending.end();) {
        if (it.value().database.isNull() || it.value().expires < clock.elapsed()) it = pending.erase(it); else ++it;
    }
    if (pending.size() >= 128) reject("busy", "There are too many pending Secret Service requests.");
    QJsonArray labels;
    QJsonObject request = args;
    if (kind == "authorize") {
        if (!args.value("entries").isArray() || args.value("entries").toArray().size() > 1024)
            reject("invalid_request", "Choose a bounded list of items to authorize.");
        for (const auto& value : args.value("entries").toArray()) {
            if (!value.isString()) reject("invalid_request", "An item identifier is invalid.");
            const auto* entry = item(db, value.toString());
            labels.append(QJsonObject{{"entry", uid(entry->uuid())}, {"title", entry->title()}});
        }
    } else if (kind == "delete") {
        const auto* entry = item(db, text(args, "entry", 64));
        labels.append(QJsonObject{{"entry", uid(entry->uuid())}, {"title", entry->title()}});
    } else if (kind == "create") {
        const auto values = attributes(args);
        const auto label = text(args, "label");
        Entry validation;
        setLabel(&validation, label);
        setAttributes(&validation, values, true);
        setSecret(&validation, args);
        QString target;
        if (flag(args, "replace")) {
            const auto found = search(db, args);
            const auto all = found.value("all").toArray();
            if (!all.isEmpty()) target = all.first().toString();
        }
        request.insert("target", target);
        labels.append(QJsonObject{{"entry", target}, {"title", target.isEmpty() ? validation.title() : item(db, target)->title()},
                                   {"new_label", validation.title()}});
    } else reject("invalid_request", "Unknown Secret Service approval request.");
    const auto token = uid(QUuid::createUuid());
    pending.insert(token, {db, fingerprint, caller, kind, request, clock.elapsed() + 120000});
    return {{"token", token}, {"kind", kind}, {"items", labels}};
}
QJsonObject KeyslotSecrets::finish(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint,
    const std::function<void(const std::function<void()>&)>& transaction) {
    const auto token = text(args, "token", 64), caller = peer(args);
    const auto found = pending.find(token);
    if (found == pending.end() || found->peer != caller)
        reject("expired", "This Secret Service approval does not belong to the caller.");
    const auto request = found.value();
    pending.erase(found);
    if (request.database.toStrongRef() != db || request.fingerprint != fingerprint || request.expires < clock.elapsed())
        reject("expired", "Secret Service approval expired or the vault changed. Try again.");
    if (!flag(args, "approved")) return {{"approved", false}};
    root(db);
    if (request.kind == "authorize") {
        const auto remember = flag(args, "remember");
        QJsonArray identifiers;
        for (const auto& value : request.request.value("entries").toArray()) {
            const auto* entry = item(db, value.toString());
            (remember ? grants[caller].allowed : grants[caller].once).insert(entry->uuid());
            if (!remember) grants[caller].onceTotp.insert(entry->uuid());
            identifiers.append(uid(entry->uuid()));
        }
        return {{"approved", true}, {"entries", identifiers}};
    }
    if (request.kind == "delete") {
        auto* entry = item(db, text(request.request, "entry", 64));
        const auto identifier = entry->uuid();
        transaction([&] { db->recycleEntry(entry); });
        for (auto& grant : grants) {
            grant.allowed.remove(identifier);
            grant.once.remove(identifier);
            grant.onceTotp.remove(identifier);
        }
        return {{"approved", true}};
    }
    QString identifier;
    transaction([&] {
        const auto data = request.request;
        auto* entry = data.value("target").toString().isEmpty() ? nullptr : item(db, data.value("target").toString());
        const bool creating = !entry;
        if (creating) {
            auto* group = root(db);
            const auto values = attributes(data);
            auto components = values.value("Path").toString().split('/', Qt::SkipEmptyParts);
            if (!components.isEmpty()) components.removeLast();
            if (components.size() > 64) reject("invalid_request", "The Secret Service item path is too deep.");
            for (const auto& component : components) {
                auto* child = group->findChildByName(component);
                if (!child) { child = new Group(); child->setUuid(QUuid::createUuid()); child->setName(component); child->setParent(group); }
                if (child->isRecycled()) reject("invalid_request", "An item cannot be created in the recycle bin.");
                group = child;
            }
            entry = new Entry();
            entry->setUuid(QUuid::createUuid());
            entry->setUsername(db->metadata()->defaultUserName());
            group->applyGroupIconOnCreateTo(entry);
            entry->setGroup(group);
        }
        entry->beginUpdate();
        setLabel(entry, text(data, "label"));
        setAttributes(entry, attributes(data), true);
        setSecret(entry, data);
        entry->endUpdate();
        if (creating) entry->removeHistoryItems(entry->historyItems());
        identifier = uid(entry->uuid());
    });
    grants[caller].allowed.insert(QUuid(identifier));
    return {{"approved", true}, {"entry", identifier}};
}
QJsonObject KeyslotSecrets::mutate(const QSharedPointer<Database>& db, const QJsonObject& args,
    const std::function<void(const std::function<void()>&)>& transaction) {
    const auto caller = peer(args), kind = text(args, "kind", 32);
    root(db);
    if (kind == "collection-label") {
        const auto label = text(args, "label");
        if (EntryAttributes::matchReference(label).hasMatch()) reject("invalid_request", "Collection labels cannot contain references.");
        transaction([&] { db->metadata()->setName(label); });
        return {};
    }
    auto* entry = item(db, text(args, "entry", 64));
    if (!consume(caller, entry->uuid())) reject("denied", "Authorize this Secret Service item before changing it.");
    transaction([&] {
        entry->beginUpdate();
        if (kind == "set-label") setLabel(entry, text(args, "label"));
        else if (kind == "set-attributes") setAttributes(entry, attributes(args));
        else if (kind == "set-secret") setSecret(entry, args);
        else reject("invalid_request", "Unknown Secret Service item mutation.");
        entry->endUpdate();
    });
    return {};
}
