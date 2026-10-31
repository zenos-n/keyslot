// SPDX-License-Identifier: GPL-3.0-only
// Reuses the pinned Entry resolver, Qt command tokenizer and upstream authenticated browser crypto.
#include "KeyslotLaunch.h"
#include "browser/BrowserMessageBuilder.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/EntryAttributes.h"
#include "core/CustomData.h"
#include "core/Group.h"
#include "crypto/Random.h"
#include "keys/CompositeKey.h"
#include "keys/PasswordKey.h"
#include "keys/FileKey.h"
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QUrl>

namespace {
constexpr auto OverridePermission = "Keyslot/UrlOverrideCommand";
[[noreturn]] void reject(const char* code, const char* message) { throw LaunchFailure{code, message}; }
QString text(const QJsonObject& value, const char* key, int maximum = 65536) {
    const auto item = value.value(key);
    if (!item.isString() || item.toString().size() > maximum || item.toString().contains(QChar('\0')))
        reject("invalid_request", "A URL launch field is invalid.");
    return item.toString();
}
bool flag(const QJsonObject& value, const char* key) {
    if (!value.value(key).isBool()) reject("invalid_request", "A URL launch choice is invalid.");
    return value.value(key).toBool();
}
QString random(int count) { return QString::fromLatin1(randomGen()->randomArray(count).toBase64()); }
QString token() { return QString::fromLatin1(QByteArray::fromBase64(random(32).toLatin1()).toHex()); }
bool base64(const QString& encoded, int size) {
    const auto data = QByteArray::fromBase64(encoded.toLatin1());
    return data.size() == size && data.toBase64() == encoded.toLatin1();
}
QByteArray digest(const QString& path) {
    QFile file(path);
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!QFileInfo(path).isFile() || !file.open(QIODevice::ReadOnly) || !hash.addData(&file))
        reject("file_error", "A linked vault or key file is unavailable.");
    return hash.result();
}
QString fingerprint(const QString& path) { return QString::fromLatin1(digest(path).toHex()); }
QString localFile(QString value, const QString& base, bool required = true) {
    if (value.startsWith("file://")) value = QUrl(value).toLocalFile();
    QFileInfo file(value);
    if (file.isRelative()) file.setFile(QDir(base), value);
    if (!file.isFile() || file.canonicalFilePath().isEmpty()) {
        if (!required) return {};
        reject("file_error", "A linked vault or key file was not found.");
    }
    return file.canonicalFilePath();
}
QString permission(const Entry* entry) {
    return QString::fromLatin1(QCryptographicHash::hash((entry->url() + QChar('\0') + entry->overrideUrl()).toUtf8(), QCryptographicHash::Sha256).toHex());
}
QString preview(const QSharedPointer<Database>& db, const Entry* original, bool override) {
    // Resolve against a separate current-entry tree, so nested references/conversions cannot expose protected values.
    Database masked;
    delete masked.setRootGroup(db->rootGroup()->clone(Entry::CloneNoFlags, Group::CloneIncludeEntries));
    masked.setFilePath(db->filePath());
    const QRegularExpression otp("\\{TOTP\\}", QRegularExpression::CaseInsensitiveOption);
    for (auto* entry : masked.rootGroup()->entriesRecursive()) {
        for (const auto& name : entry->attributes()->keys()) {
            auto value = entry->attribute(name);
            if (name == EntryAttributes::PasswordKey || entry->attributes()->isProtected(name)) value = "[Hidden]";
            else value.replace(otp, "[Hidden]");
            entry->attributes()->set(name, value, entry->attributes()->isProtected(name));
        }
        entry->setOverrideUrl(entry->overrideUrl().replace(otp, "[Hidden]"));
        entry->setTotp({});
    }
    const auto* entry = masked.rootGroup()->findEntryByUuid(original->uuid());
    const auto value = override ? entry->overrideUrl() : entry->url();
    return entry->resolveMultiplePlaceholders(value);
}
void validTarget(const QJsonObject& args) {
    const auto path = text(args, "path"), hash = text(args, "hash", 64), keyfile = text(args, "keyfile");
    if (fingerprint(path) != hash || (!keyfile.isEmpty() && fingerprint(keyfile) != text(args, "keyfile_hash", 64)))
        reject("conflict", "The linked vault or key file changed. Open the link again.");
}
}

void KeyslotLaunch::clear() { pending = {}; incoming = {}; }
void KeyslotLaunch::cancel(const QJsonObject& args) {
    const auto value = text(args, "token", 128);
    if (value == pending.token) pending = {};
    if (value == incoming.token) incoming = {};
}
bool KeyslotLaunch::approved(const Entry* entry) {
    return entry->attributes()->value(EntryAttributes::RememberCmdExecAttr) == "1"
        || entry->customData()->value(OverridePermission) == permission(entry);
}
void KeyslotLaunch::forget(Entry* entry) {
    entry->beginUpdate();
    entry->attributes()->remove(EntryAttributes::RememberCmdExecAttr);
    entry->customData()->remove(OverridePermission);
    entry->endUpdate();
}
QJsonObject KeyslotLaunch::prepare(const QSharedPointer<Database>& db, Entry* entry, const QJsonObject& args, const QByteArray& hash) {
    pending = {};
    Pending item;
    item.database = db; item.fingerprint = hash; item.token = token(); item.expires = clock.elapsed() + 120000;
    item.entry = entry->uuid().toString(QUuid::WithoutBraces); item.override = flag(args, "override");
    const auto raw = item.override ? entry->overrideUrl() : entry->url();
    item.value = entry->resolveMultiplePlaceholders(raw);
    if (item.value.isEmpty() || item.value.size() > 1024 * 1024 || item.value.contains(QChar('\0')))
        reject("invalid_request", "This entry has no supported URL to open.");
    auto display = preview(db, entry, item.override);
    item.kind = "uri";
    if (item.value.startsWith("cmd://")) {
        item.kind = "command";
        if (QProcess::splitCommand(item.value.mid(6)).isEmpty()) reject("invalid_request", "This command URL is empty.");
        item.remembered = item.override ? entry->customData()->value(OverridePermission) == permission(entry)
            : entry->attributes()->value(EntryAttributes::RememberCmdExecAttr) == "1";
        display = display.mid(6);
    } else if (item.value.startsWith("kdbx://")) {
        item.kind = "database";
        const auto base = QFileInfo(db->filePath()).absolutePath();
        item.path = localFile(item.value.mid(7), base);
        const auto keyfile = entry->resolveMultiplePlaceholders(entry->username());
        // Upstream passes an empty canonical path when the username/key-file path does not exist.
        item.keyfile = keyfile.isEmpty() ? QString() : localFile(keyfile, base, false);
        item.targetHash = fingerprint(item.path);
        item.keyfileHash = item.keyfile.isEmpty() ? QString() : fingerprint(item.keyfile);
        item.keys = BrowserMessageBuilder::instance()->getKeyPair();
        display = item.path;
    } else {
        const auto url = QUrl::fromUserInput(item.value);
        if (url.isEmpty() || !url.isValid()) reject("invalid_request", "This URL is invalid.");
        item.value = url.toString(QUrl::FullyEncoded);
        display = QUrl::fromUserInput(display).toDisplayString(QUrl::RemovePassword);
    }
    if (display.size() > 400) display = display.left(400) + " […]";
    pending = item;
    return {{"token", item.token}, {"kind", item.kind}, {"display", display}, {"title", entry->title()},
        {"remembered", item.remembered}, {"path", item.path}, {"hash", item.targetHash},
        {"keyfile", item.keyfile}, {"keyfile_hash", item.keyfileHash}, {"public_key", item.keys.first}};
}
QJsonObject KeyslotLaunch::finish(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& hash, const Commit& commit) {
    const auto value = text(args, "token", 128);
    if (pending.token.isEmpty() || value != pending.token || pending.database.toStrongRef() != db
        || pending.fingerprint != hash || pending.expires < clock.elapsed())
        reject("expired", "This URL launch expired or the vault changed. Open the entry again.");
    const auto item = pending; pending = {};
    if (item.kind == "uri") return {{"kind", item.kind}, {"uri", item.value}};
    if (item.kind == "command") {
        if (!item.remembered && !flag(args, "approved")) reject("denied", "This command was not approved.");
        if (flag(args, "remember") && !item.remembered) commit([&] {
            auto* entry = db->rootGroup()->findEntryByUuid(QUuid(item.entry));
            if (!entry) reject("not_found", "The command entry is unavailable.");
            if (item.override) entry->customData()->set(OverridePermission, permission(entry));
            else entry->attributes()->set(EntryAttributes::RememberCmdExecAttr, "1", false);
        });
        auto command = QProcess::splitCommand(item.value.mid(6));
        QProcess process;
        process.setProgram(command.takeFirst()); process.setArguments(command);
        auto environment = QProcessEnvironment::systemEnvironment();
        for (const auto& name : environment.keys()) if (name.startsWith("KEYSLOT_")) environment.remove(name);
        process.setProcessEnvironment(environment);
        process.setStandardInputFile(QProcess::nullDevice());
        process.setStandardOutputFile(QProcess::nullDevice());
        process.setStandardErrorFile(QProcess::nullDevice());
        qint64 pid = 0;
        if (!process.startDetached(&pid)) return {{"kind", item.kind}, {"launched", false},
            {"error", "The command could not be started. Check its program and arguments."}};
        return {{"kind", item.kind}, {"launched", true}};
    }
    const auto target = args.value("destination").toObject();
    const auto publicKey = text(target, "public_key", 128), nonce = text(target, "nonce", 128);
    if (!base64(publicKey, 32) || !base64(nonce, 24) || text(target, "path") != item.path
        || text(target, "hash", 64) != item.targetHash || text(target, "source_token", 128) != item.token
        || text(target, "keyfile") != item.keyfile || text(target, "keyfile_hash", 64) != item.keyfileHash)
        reject("denied", "The linked-vault recipient does not match this launch.");
    validTarget(target);
    const auto* entry = db->rootGroup()->findEntryByUuid(QUuid(item.entry));
    if (!entry) reject("not_found", "The linked-vault entry is unavailable.");
    const auto password = entry->resolveMultiplePlaceholders(entry->password());
    const QJsonObject credentials{{"kind", "keyslot-linked-vault-1"}, {"source_token", item.token},
        {"token", text(target, "token", 128)}, {"path", item.path}, {"hash", item.targetHash},
        {"keyfile", item.keyfile}, {"keyfile_hash", item.keyfileHash}, {"password", password}, {"no_password", password.isEmpty()}};
    if (QJsonDocument(credentials).toJson(QJsonDocument::Compact).size() > 65536)
        reject("invalid_request", "The linked-vault credential is too large.");
    const auto message = BrowserMessageBuilder::instance()->encryptMessage(credentials, nonce, publicKey, item.keys.second);
    if (message.isEmpty()) reject("crypto_error", "The linked-vault credential could not be sealed.");
    return {{"kind", item.kind}, {"message", message}, {"token", text(target, "token", 128)}};
}
QJsonObject KeyslotLaunch::offer(const QJsonObject& args) {
    incoming = {};
    validTarget(args);
    Offer item;
    item.sourceKey = text(args, "public_key", 128);
    if (!base64(item.sourceKey, 32)) reject("invalid_request", "The linked-vault source key is invalid.");
    item.sourceToken = text(args, "token", 128); item.token = token(); item.nonce = random(24);
    item.keys = BrowserMessageBuilder::instance()->getKeyPair();
    item.path = text(args, "path"); item.hash = text(args, "hash", 64);
    item.keyfile = text(args, "keyfile"); item.keyfileHash = text(args, "keyfile_hash", 64);
    item.expires = clock.elapsed() + 120000;
    incoming = item;
    return {{"token", item.token}, {"public_key", item.keys.first}, {"nonce", item.nonce}, {"path", item.path},
        {"hash", item.hash}, {"keyfile", item.keyfile}, {"keyfile_hash", item.keyfileHash}, {"source_token", item.sourceToken}};
}
KeyslotLaunch::Opened KeyslotLaunch::accept(const QJsonObject& args) {
    if (incoming.token.isEmpty() || text(args, "token", 128) != incoming.token || incoming.expires < clock.elapsed())
        reject("expired", "The linked-vault recipient expired.");
    const auto item = incoming; incoming = {};
    const auto message = text(args, "message", 131072);
    const auto bytes = QByteArray::fromBase64(message.toLatin1());
    if (bytes.size() < 16 || bytes.toBase64() != message.toLatin1()) reject("invalid_request", "The linked-vault envelope is invalid.");
    const auto credentials = BrowserMessageBuilder::instance()->decryptMessage(message, item.nonce, item.sourceKey, item.keys.second);
    if (credentials.isEmpty() || text(credentials, "kind") != "keyslot-linked-vault-1"
        || text(credentials, "token", 128) != item.token || text(credentials, "source_token", 128) != item.sourceToken
        || text(credentials, "path") != item.path || text(credentials, "hash", 64) != item.hash
        || text(credentials, "keyfile") != item.keyfile || text(credentials, "keyfile_hash", 64) != item.keyfileHash)
        reject("denied", "The linked-vault credential could not be authenticated.");
    validTarget(credentials);
    auto key = QSharedPointer<CompositeKey>::create();
    if (!flag(credentials, "no_password")) key->addKey(QSharedPointer<PasswordKey>::create(text(credentials, "password")));
    if (!item.keyfile.isEmpty()) {
        auto file = QSharedPointer<FileKey>::create();
        if (!file->load(item.keyfile)) reject("key_error", "The linked-vault key file could not be loaded.");
        key->addKey(file);
    }
    auto candidate = QSharedPointer<Database>::create();
    if (!candidate->open(item.path, key)) {
        // Upstream retries an empty password key after trying a key-file-only/empty composite key.
        if (!flag(credentials, "no_password")) reject("key_error", "The linked-vault credential was not accepted. Unlock it manually.");
        key->addKey(QSharedPointer<PasswordKey>::create(QString()));
        if (!candidate->open(item.path, key)) reject("key_error", "The linked-vault credential was not accepted. Unlock it manually.");
    }
    validTarget(credentials);
    return {candidate, item.path, QByteArray::fromHex(item.hash.toLatin1())};
}
