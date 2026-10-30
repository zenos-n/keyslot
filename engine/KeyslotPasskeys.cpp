// SPDX-License-Identifier: GPL-3.0-only
#include "BrowserDatabase.h"
#include "BrowserDeadline.h"
#include "browser/BrowserMessageBuilder.h"
#include "browser/BrowserPasskeys.h"
#include "browser/BrowserPasskeysClient.h"
#include "browser/PasskeyUtils.h"
#include "core/Database.h"
#include "core/EntryAttributes.h"
#include "core/Group.h"
#include "core/Tools.h"
#include <QJsonDocument>
#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QUuid>
#include <botan/data_src.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

using namespace KeyslotBrowser;
static_assert(DEFAULT_TIMEOUT == PasskeyTimeoutDefault, "Review the upstream passkey timeout on upgrade");

namespace {
// Field mapping/validation follows KeePassXC2.7.12 PasskeyImporter/PasskeyExporter (GPL-3.0-or-later).
QJsonObject transferData(const Entry* entry) {
    if (!entry || !entry->hasPasskey()) reject("not_found", "This entry has no passkey.");
    const auto* attributes = entry->attributes();
    return {{"relyingParty", attributes->value(EntryAttributes::KPEX_PASSKEY_RELYING_PARTY)},
        {"url", entry->url()}, {"username", passkeyUtils()->getUsernameFromEntry(entry)},
        {"credentialId", passkeyUtils()->getCredentialIdFromEntry(entry)},
        {"userHandle", attributes->value(EntryAttributes::KPEX_PASSKEY_USER_HANDLE)},
        {"privateKey", attributes->value(EntryAttributes::KPEX_PASSKEY_PRIVATE_KEY_PEM)}};
}

QJsonObject publicTransferData(QJsonObject data) {
    data.remove("privateKey");
    return data;
}

QJsonObject readTransfer(const QJsonObject& args, QByteArray* fingerprint) {
    const auto path = text(args, "source", true);
    const auto descriptor = ::open(QFile::encodeName(path).constData(), O_RDONLY | O_NONBLOCK);
    if (descriptor < 0) reject("file_error", "The passkey file could not be opened.");
    QFile input;
    if (!input.open(descriptor, QIODevice::ReadOnly, QFileDevice::AutoCloseHandle)) {
        ::close(descriptor);
        reject("file_error", "The passkey file could not be read.");
    }
    struct stat info {};
    constexpr qint64 Limit = 1024 * 1024;
    if (::fstat(descriptor, &info) || !S_ISREG(info.st_mode) || info.st_size > Limit)
        reject("invalid_request", "Choose a regular passkey file smaller than 1 MiB.");
    auto bytes = input.read(Limit + 1);
    if (input.error() != QFileDevice::NoError || bytes.size() > Limit)
        reject("file_error", "The passkey file could not be read completely.");
    *fingerprint = QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex();
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(bytes, &error);
    bytes.fill('\0');
    if (error.error != QJsonParseError::NoError || !document.isObject())
        reject("import_error", "Choose a valid KeePassXC passkey file.");
    const auto source = document.object();
    QJsonObject data;
    for (const auto* field : {"relyingParty", "url", "username", "credentialId", "userHandle", "privateKey"}) {
        if (!source.value(field).isString()) reject("import_error", "The passkey file is missing required text fields.");
        data.insert(field, source.value(field));
    }
    const auto key = data.value("privateKey").toString();
    if (!key.startsWith(EntryAttributes::KPEX_PASSKEY_PRIVATE_KEY_START)
        || !key.trimmed().endsWith(EntryAttributes::KPEX_PASSKEY_PRIVATE_KEY_END))
        reject("import_error", "The passkey private key is missing or malformed.");
    try {
        const auto bytes = key.toUtf8();
        Botan::DataSource_Memory source(reinterpret_cast<const uint8_t*>(bytes.constData()), bytes.size());
        const auto parsed = Botan::PKCS8::load_key(source);
        if (!parsed || (parsed->algo_name() != "ECDSA" && parsed->algo_name() != "RSA" && parsed->algo_name() != "Ed25519"))
            reject("import_error", "This passkey private key algorithm is not supported.");
    } catch (const std::exception&) {
        reject("import_error", "The passkey private key is missing or malformed.");
    }
    return data;
}
}

QJsonObject KeyslotBrowserDatabase::passkeyInfo(const Entry* entry) const {
    auto data = publicTransferData(transferData(entry));
    const auto name = Tools::cleanFilename(entry->title());
    data.insert("filename", (name.isEmpty() ? "Passkey" : name) + ".passkey");
    return data;
}

QJsonObject KeyslotBrowserDatabase::inspectPasskeyImport(const QJsonObject& args) const {
    QByteArray fingerprint;
    auto result = publicTransferData(readTransfer(args, &fingerprint));
    result.insert("source_fingerprint", QString::fromLatin1(fingerprint));
    return result;
}

void KeyslotBrowserDatabase::importPasskey(const QSharedPointer<Database>& db, const QJsonObject& args,
        const std::function<void(const std::function<void()>&)>& commit) {
    QByteArray fingerprint;
    const auto data = readTransfer(args, &fingerprint);
    if (text(args, "source_fingerprint", true) != QString::fromLatin1(fingerprint))
        reject("conflict", "The passkey file changed since review. Review it again before importing.");
    const auto entryId = text(args, "entry"), groupId = text(args, "group");
    auto* entry = entryId.isEmpty() ? nullptr : db->rootGroup()->findEntryByUuid(QUuid(entryId));
    auto* group = groupId.isEmpty() ? nullptr : db->rootGroup()->findGroupByUuid(QUuid(groupId));
    if ((!entryId.isEmpty() && !entry) || (!groupId.isEmpty() && !group))
        reject("not_found", "The passkey destination no longer exists.");
    if ((entry && entry->isRecycled()) || (group && group->isRecycled()))
        reject("denied", "Restore this entry or group before importing a passkey.");
    if (entry && entry->hasPasskey() && !flag(args, "replace"))
        reject("denied", "Replacing this entry's passkey requires confirmation.");
    if (!entry && !group) {
        group = db->rootGroup()->findGroupByPath("Imported Passkeys");
        if (group && group->isRecycled()) reject("denied", "Choose a group outside the recycle bin.");
    }
    commit([&] {
        if (entry) {
            service.addPasskeyToEntry(entry, data.value("relyingParty").toString(), data.value("relyingParty").toString(),
                data.value("username").toString(), data.value("credentialId").toString(),
                data.value("userHandle").toString(), data.value("privateKey").toString(), true);
        } else {
            if (!group) {
                group = new Group();
                group->setName("Imported Passkeys");
                group->setUuid(QUuid::createUuid());
                group->setParent(db->rootGroup());
            }
            service.addPasskeyToGroup(db, group, data.value("url").toString(), data.value("relyingParty").toString(),
                data.value("relyingParty").toString(), data.value("username").toString(),
                data.value("credentialId").toString(), data.value("userHandle").toString(), data.value("privateKey").toString());
        }
    });
}

void KeyslotBrowserDatabase::exportPasskey(const Entry* entry, const QJsonObject& args) const {
    const auto data = transferData(entry);
    const QFileInfo destination(text(args, "path", true));
    QTemporaryDir temporary(destination.absolutePath() + "/.keyslot-passkey-XXXXXX");
    if (!temporary.isValid()) reject("file_error", "The passkey export could not be staged.");
    const auto stage = temporary.path() + "/passkey";
    QFile output(stage);
    auto bytes = QJsonDocument(data).toJson();
    if (!output.open(QIODevice::WriteOnly | QIODevice::NewOnly)
        || !output.setPermissions(QFile::ReadOwner | QFile::WriteOwner)
        || output.write(bytes) != bytes.size() || !output.flush() || ::fsync(output.handle()) != 0) {
        bytes.fill('\0');
        reject("file_error", "The passkey export could not be written completely.");
    }
    bytes.fill('\0');
    output.close();
    if (::link(QFile::encodeName(stage).constData(), QFile::encodeName(destination.absoluteFilePath()).constData()) != 0)
        reject("file_error", "The passkey destination already exists or cannot be written.");
}

QJsonObject KeyslotBrowserDatabase::preparePasskey(const QSharedPointer<Database>& db, const QJsonObject& args,
                                                   const QByteArray& fingerprint) {
    const auto id = text(args, "id", true), key = text(args, "key", true);
    authenticate(db, id, key);
    const auto mode = text(args, "mode", true);
    if (mode != "register" && mode != "get") reject("invalid_request", "Choose a supported passkey operation.");
    const auto origin = text(args, "origin", true);
    if (!passkeyUtils()->isOriginAllowedWithLocalhost(false, origin))
        return {{"error_code", ERROR_PASSKEYS_INVALID_URL_PROVIDED}};
    if (!args.value("public_key").isObject() || args.value("public_key").toObject().isEmpty())
        return {{"error_code", ERROR_PASSKEYS_EMPTY_PUBLIC_KEY}};
    const auto publicKey = args.value("public_key").toObject();
    if (QJsonDocument(publicKey).toJson(QJsonDocument::Compact).size() > 256 * 1024)
        reject("invalid_request", "The passkey request is too large.");
    if (publicKey.value("challenge").toString().size() < 16)
        return {{"error_code", ERROR_PASSKEYS_INVALID_CHALLENGE}};
    const bool registration = mode == "register";
    QJsonObject options;
    const int error = registration
        ? browserPasskeysClient()->getCredentialCreationOptions(publicKey, origin, &options)
        : browserPasskeysClient()->getAssertionOptions(publicKey, origin, &options);
    if (error) return {{"error_code", error}};
    if (registration ? !passkeyUtils()->checkCredentialCreationOptions(options)
                     : !passkeyUtils()->checkCredentialAssertionOptions(options))
        return {{"error_code", ERROR_PASSKEYS_UNKNOWN_ERROR}};
    const auto rp = registration ? options.value("rp").toObject().value("id").toString()
                                 : options.value("rpId").toString();
    const auto user = options.value("user").toObject();
    const auto allowed = passkeyUtils()->getAllowedCredentialsFromAssertionOptions(options);
    const auto excluded = options.value("excludeCredentials").toArray();
    auto candidates = service.searchEntries(db, rp, QString(), QStringList{id}, true);
    QJsonArray entries;
    QSet<QString> eligible;
    for (auto* entry : candidates) {
        if (!entry->hasPasskey()) continue;
        const auto credentialId = passkeyUtils()->getCredentialIdFromEntry(entry);
        if (registration) {
            for (const auto& descriptor : excluded)
                if (descriptor.toObject().value("id").toString() == credentialId)
                    return {{"error_code", ERROR_PASSKEYS_CREDENTIAL_IS_EXCLUDED}};
            if (entry->attributes()->value(EntryAttributes::KPEX_PASSKEY_USER_HANDLE) != user.value("id").toString()) continue;
        } else if (!options.value("allowCredentials").toArray().isEmpty() ? !allowed.contains(credentialId)
                   : !entry->attributes()->hasKey(EntryAttributes::KPEX_PASSKEY_USER_HANDLE)) continue;
        eligible.insert(entry->uuidToHex());
        entries.append(QJsonObject{{"uuid", entry->uuidToHex()}, {"title", entry->title()},
            {"username", passkeyUtils()->getUsernameFromEntry(entry)}, {"group", entry->group()->fullPath()}});
    }
    if (!registration && entries.isEmpty()) return {{"error_code", ERROR_KEEPASS_NO_LOGINS_FOUND}};
    const auto requestedGroup = text(args, "group_name");
    const auto destination = registration ? groupPath(requestedGroup.isEmpty() ? "KeePassXC-Browser Passkeys" : requestedGroup) : QString();
    QString prefix;
    for (const auto& component : destination.split('/')) {
        prefix += (prefix.isEmpty() ? "" : "/") + component;
        auto* group = db->rootGroup()->findGroupByPath(prefix);
        if (group && group->isRecycled()) reject("denied", "Choose a passkey group outside the recycle bin.");
    }
    QSet<QString> groupIds;
    if (registration) {
        for (auto* group : db->rootGroup()->groupsRecursive(true))
            if (!group->isRecycled()) groupIds.insert(group->uuidToHex());
        // Manual attachment to a normal entry is allowed only by the later explicit GTK selection.
        for (auto* entry : db->rootGroup()->entriesRecursive())
            if (!entry->isRecycled()) eligible.insert(entry->uuidToHex());
    }
    const auto now = clock.elapsed();
    for (auto it = passkeys.begin(); it != passkeys.end();) {
        if (it->expires <= now || it->database.isNull()) it = passkeys.erase(it);
        else ++it;
    }
    if (passkeys.size() >= 128) reject("busy", "Too many passkey requests are waiting for confirmation.");
    const auto token = QUuid::createUuid().toString(QUuid::WithoutBraces);
    const auto timeout = passkeyRequestTimeout(publicKey);
    passkeys.insert(token, {db, fingerprint, id, key, origin, rp, destination, options, registration, eligible, groupIds, now + timeout});
    return {{"token", token}, {"registration", registration}, {"origin", origin}, {"rp", rp},
        {"username", user.value("name")}, {"display_name", user.value("displayName")},
        {"entries", entries}, {"group_path", destination}, {"timeout_ms", int(timeout)}};
}

QJsonObject KeyslotBrowserDatabase::finishPasskey(const QSharedPointer<Database>& db, const QJsonObject& args,
        const QByteArray& fingerprint, const std::function<void(const std::function<void()>&)>& commit) {
    const auto token = text(args, "token", true);
    if (!passkeys.contains(token)) reject("expired", "The passkey confirmation is no longer valid.");
    const auto request = passkeys.take(token);
    if (request.expires <= clock.elapsed()) reject("expired", "The passkey confirmation expired. Try again.");
    if (request.database.toStrongRef() != db || request.fingerprint != fingerprint)
        reject("conflict", "The database changed or the passkey confirmation expired. Try again.");
    authenticate(db, request.id, request.key);
    if (!flag(args, "approved")) return {{"errorCode", ERROR_PASSKEYS_REQUEST_CANCELED}};
    const auto uuid = text(args, "entry");
    if (!uuid.isEmpty() && !request.entries.contains(uuid)) reject("denied", "The entry was not part of this passkey request.");
    auto* entry = uuid.isEmpty() ? nullptr : db->rootGroup()->findEntryByUuid(Tools::hexToUuid(uuid));
    if (!uuid.isEmpty() && (!entry || entry->isRecycled())) reject("not_found", "The selected passkey entry is no longer available.");
    if (request.registration) {
        if (entry && entry->hasPasskey() && !flag(args, "replace")) reject("denied", "Replacing an existing passkey requires explicit confirmation.");
        const auto groupId = text(args, "group");
        if (!groupId.isEmpty() && !request.groups.contains(groupId)) reject("denied", "Choose a group from this passkey request.");
        auto credential = browserPasskeys()->buildRegisterPublicKeyCredential(request.options);
        if (credential.credentialId.isEmpty() || credential.key.isEmpty() || credential.response.isEmpty())
            return {{"errorCode", ERROR_PASSKEYS_UNKNOWN_ERROR}};
        const auto user = request.options.value("user").toObject();
        const auto rpName = request.options.value("rp").toObject().value("name").toString();
        commit([&] {
            if (entry) {
                service.addPasskeyToEntry(entry, request.rp, rpName, user.value("name").toString(), credential.credentialId,
                    user.value("id").toString(), QString::fromUtf8(credential.key), true);
            } else {
                auto* group = groupId.isEmpty() ? ensureGroup(db, request.groupPath, true)
                    : db->rootGroup()->findGroupByUuid(Tools::hexToUuid(groupId));
                service.addPasskeyToGroup(db, group, request.origin, request.rp, rpName, user.value("name").toString(),
                    credential.credentialId, user.value("id").toString(), QString::fromUtf8(credential.key));
            }
        });
        credential.key.fill('\0');
        return credential.response;
    }
    if (!entry || !entry->hasPasskey()) reject("denied", "Select a passkey explicitly before signing in.");
    const auto* attributes = entry->attributes();
    const auto backupFlag = [attributes](const QString& name, bool fallback) {
        return attributes->hasKey(name) ? attributes->value(name) == "1" || attributes->value(name) == "true" : fallback;
    };
    const auto response = browserPasskeys()->buildGetPublicKeyCredential(request.options,
        passkeyUtils()->getCredentialIdFromEntry(entry), attributes->value(EntryAttributes::KPEX_PASSKEY_USER_HANDLE),
        attributes->value(EntryAttributes::KPEX_PASSKEY_PRIVATE_KEY_PEM),
        backupFlag(EntryAttributes::KPEX_PASSKEY_FLAG_BE, DEFAULT_BE_FLAG),
        backupFlag(EntryAttributes::KPEX_PASSKEY_FLAG_BS, DEFAULT_BS_FLAG));
    return response.isEmpty() ? QJsonObject{{"errorCode", ERROR_PASSKEYS_UNKNOWN_ERROR}} : response;
}
