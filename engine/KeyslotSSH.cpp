// SPDX-License-Identifier: GPL-3.0-only
// Key parsing, KeeAgent XML and private/public encoding are the pinned upstream implementation.
#include "KeyslotSSH.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/EntryAttachments.h"
#include "sshagent/BinaryStream.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QProcessEnvironment>
#include <QUuid>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QXmlStreamReader>
#include <QRegularExpression>
#include <QSet>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <chrono>

namespace {
[[noreturn]] void fail(const char* code, const char* message) { throw SSHFailure{code, message}; }
QString text(const QJsonObject& args, const char* name, const QString& fallback = {}) {
    if (!args.contains(name)) return fallback;
    if (!args.value(name).isString()) fail("invalid_request", "Invalid SSH text field.");
    const auto result = args.value(name).toString();
    if (result.size() > 16384 || result.contains(QChar('\0'))) fail("invalid_request", "Invalid SSH text field.");
    return result;
}
bool flag(const QJsonObject& args, const char* name, bool fallback = false) {
    if (!args.contains(name)) return fallback;
    if (!args.value(name).isBool()) fail("invalid_request", "Invalid SSH option.");
    return args.value(name).toBool();
}
KeeAgentSettings readSettings(const Entry* entry) {
    KeeAgentSettings settings;
    if (KeeAgentSettings::inEntryAttachments(entry->attachments())) {
        const auto bytes = entry->attachments()->value("KeeAgent.settings");
        if (bytes.size() > 1024 * 1024) fail("invalid_request", "The KeeAgent settings attachment is too large.");
        // Upstream fromXml can accept a partially parsed document; never silently replace it.
        QXmlStreamReader check(bytes);
        while (!check.atEnd()) {
            if (check.readNext() == QXmlStreamReader::DTD) fail("invalid_request", "KeeAgent settings cannot contain a document type declaration.");
        }
        if (check.hasError() || !settings.fromEntry(entry))
            fail("invalid_request", "This entry's KeeAgent settings could not be read. Preserve or remove its settings attachment before replacing it.");
    }
    return settings;
}
QString keyPath(const QString& filename) {
    // Preserve upstream ~/ and $NAME syntax, but bound recursive substitutions.
    const auto environment = QProcessEnvironment::systemEnvironment();
    auto path = filename;
    if (path.startsWith("~/") || path.startsWith("~\\")) path.replace(0, 1, environment.value("HOME"));
    const QRegularExpression variable("\\$([A-Za-z][A-Za-z0-9_]*)");
    QSet<QString> seen;
    for (int substitutions = 0; substitutions < 128; ++substitutions) {
        if (path.size() > 16384 || path.contains(QChar('\0')) || seen.contains(path))
            fail("key_error", "The SSH key path is too large or contains an environment-variable cycle.");
        seen.insert(path);
        const auto match = variable.match(path);
        if (!match.hasMatch()) return path;
        path.replace(match.capturedStart(), match.capturedLength(), environment.value(match.captured(1)));
    }
    fail("key_error", "The SSH key path contains too many environment-variable substitutions.");
}
bool loadKey(KeeAgentSettings settings, const Entry* entry, OpenSSHKey& key, bool decrypt = true) {
    constexpr qint64 limit = 1024 * 1024;
    if (settings.selectedType() == "attachment") {
        if (entry->attachments()->value(settings.attachmentName()).size() > limit) return false;
        return settings.toOpenSSHKey(entry, key, decrypt);
    }
    auto path = keyPath(settings.fileName());
    if (QFileInfo(path).isRelative()) path = QFileInfo(entry->database()->filePath()).absolutePath() + "/" + path;
    const auto descriptor = ::open(QFile::encodeName(path).constData(), O_RDONLY | O_NONBLOCK);
    if (descriptor < 0) return false;
    QFile input;
    if (!input.open(descriptor, QIODevice::ReadOnly, QFileDevice::AutoCloseHandle)) { ::close(descriptor); return false; }
    struct stat info {};
    if (::fstat(descriptor, &info) || !S_ISREG(info.st_mode) || info.st_size > limit) return false;
    auto bytes = input.read(limit + 1);
    if (input.error() != QFileDevice::NoError || bytes.isEmpty() || bytes.size() > limit) return false;
    // Reuse upstream parsing/decryption with an in-memory attachment, never a temporary key file.
    EntryAttachments attachment;
    const auto name = QFileInfo(path).fileName();
    attachment.set(name, bytes);
    settings.setSelectedType("attachment");
    settings.setAttachmentName(name);
    return settings.toOpenSSHKey(entry->username(), entry->password(), entry->database()->filePath(), &attachment, key, decrypt);
}
}

void KeyslotSSH::clearPending() {
    for (const auto& request : pending) request.key->clearPrivate();
    pending.clear();
    removals.clear();
}
void KeyslotSSH::prunePending() {
    for (auto it = pending.begin(); it != pending.end();) {
        if (it->expires <= clock.elapsed() || it->database.isNull()) { it->key->clearPrivate(); it = pending.erase(it); }
        else ++it;
    }
    for (auto it = removals.begin(); it != removals.end();) {
        if (it->expires <= clock.elapsed() || it->database.isNull()) it = removals.erase(it); else ++it;
    }
}

void KeyslotSSH::configure(const QJsonObject& args) {
    const auto path = text(args, "relay");
    if (!path.isEmpty() && (!QDir::isAbsolutePath(path) || path.toUtf8().size() > 100))
        fail("invalid_request", "Choose a valid native SSH relay path.");
    if (path != endpoint) relay.abort();
    clearPending();
    endpoint = path;
    agent = text(args, "socket");
    if (agent.isEmpty()) agent = QProcessEnvironment::systemEnvironment().value("SSH_AUTH_SOCK");
    provider = text(args, "provider");
    if (provider.isEmpty()) provider = QProcessEnvironment::systemEnvironment().value("SSH_SK_PROVIDER", "internal");
}

QJsonObject KeyslotSSH::request(QJsonObject value) {
    if (endpoint.isEmpty()) fail("disabled", "Enable SSH-agent integration before managing agent keys.");
    if (relay.state() != QLocalSocket::ConnectedState) {
        relay.abort();
        relay.connectToServer(endpoint);
        if (!relay.waitForConnected(1000)) fail("agent_error", "The native SSH relay is unavailable.");
    }
    value.insert("id", ++sequence);
    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    value.insert("deadline", double(now + 10000));
    auto encoded = QJsonDocument(value).toJson(QJsonDocument::Compact) + '\n';
    if (encoded.size() > 4 * 1024 * 1024 || relay.write(encoded) != encoded.size()) {
        encoded.fill('\0'); relay.abort();
        fail("agent_error", "The SSH request could not be sent.");
    }
    encoded.fill('\0');
    QElapsedTimer deadline;
    deadline.start();
    while (relay.bytesToWrite()) {
        if (deadline.elapsed() >= 10000 || !relay.waitForBytesWritten(10000 - deadline.elapsed())) {
            relay.abort(); fail("agent_error", "The SSH request could not be sent completely.");
        }
    }
    QByteArray input;
    while (!input.contains('\n')) {
        if (deadline.elapsed() >= 10000 || (!relay.bytesAvailable() && !relay.waitForReadyRead(10000 - deadline.elapsed()))) {
            relay.abort(); fail("agent_error", "The SSH relay did not respond. Review its cleanup status.");
        }
        input += relay.readAll();
        if (input.size() > 4 * 1024 * 1024) {
            relay.abort(); fail("agent_error", "The SSH relay returned invalid data.");
        }
    }
    QJsonParseError parse;
    const auto document = QJsonDocument::fromJson(input.trimmed(), &parse);
    if (parse.error != QJsonParseError::NoError || !document.isObject() || document.object().value("id").toInt(-1) != sequence) {
        relay.abort(); fail("agent_error", "The SSH relay returned invalid data.");
    }
    const auto response = document.object();
    if (response.contains("error")) throw SSHFailure{"agent_error", response.value("error").toString()};
    if (!response.value("result").isObject()) fail("agent_error", "The SSH relay returned invalid data.");
    return response.value("result").toObject();
}

QJsonObject KeyslotSSH::settings(const Entry* entry) const {
    const auto value = readSettings(entry);
    QJsonArray attachments;
    for (const auto& name : entry->attachments()->keys()) if (name != "KeeAgent.settings") attachments.append(name);
    return {{"enabled", value.allowUseOfSshKey()}, {"auto_add", value.addAtDatabaseOpen()},
        {"remove_on_lock", value.removeAtDatabaseClose()}, {"confirm", value.useConfirmConstraintWhenAdding()},
        {"lifetime", value.useLifetimeConstraintWhenAdding()}, {"seconds", value.lifetimeConstraintDuration()},
        {"source_type", value.selectedType()}, {"attachment", value.attachmentName()}, {"file", value.fileName()},
        {"configured", value.keyConfigured()}, {"attachments", attachments}};
}

QJsonObject KeyslotSSH::keyInfo(const Entry* entry, bool decrypt) const {
    const auto value = readSettings(entry);
    OpenSSHKey key;
    if (!value.keyConfigured() || !loadKey(value, entry, key, decrypt))
        fail("key_error", "The SSH key could not be opened. Check its source and the entry password.");
    const QJsonObject result{{"fingerprint", key.fingerprint()}, {"md5", key.fingerprint(QCryptographicHash::Md5)},
        {"public_key", key.publicKey()}, {"type", key.type()}, {"comment", key.comment()}, {"encrypted", key.encrypted()}};
    key.clearPrivate();
    return result;
}

void KeyslotSSH::saveSettings(Entry* entry, const QJsonObject& args) {
    if (entry->isRecycled()) fail("denied", "Restore this entry before configuring its SSH key.");
    auto value = readSettings(entry);
    const QStringList allowed{"entry", "enabled", "auto_add", "remove_on_lock", "confirm", "lifetime", "seconds",
                              "source_type", "attachment", "file"};
    for (auto it = args.begin(); it != args.end(); ++it)
        if (!allowed.contains(it.key())) fail("invalid_request", "Unknown SSH entry setting.");
    value.setAllowUseOfSshKey(flag(args, "enabled", value.allowUseOfSshKey()));
    value.setAddAtDatabaseOpen(flag(args, "auto_add", value.addAtDatabaseOpen()));
    value.setRemoveAtDatabaseClose(flag(args, "remove_on_lock", value.removeAtDatabaseClose()));
    value.setUseConfirmConstraintWhenAdding(flag(args, "confirm", value.useConfirmConstraintWhenAdding()));
    value.setUseLifetimeConstraintWhenAdding(flag(args, "lifetime", value.useLifetimeConstraintWhenAdding()));
    value.setSelectedType(text(args, "source_type", value.selectedType()));
    value.setAttachmentName(text(args, "attachment", value.attachmentName()));
    value.setFileName(text(args, "file", value.fileName()));
    if (args.contains("seconds")) {
        const auto seconds = args.value("seconds");
        if (!seconds.isDouble() || seconds.toDouble() != seconds.toInt() || seconds.toInt() < 1)
            fail("invalid_request", "Choose a positive SSH key lifetime in seconds.");
        value.setLifetimeConstraintDuration(seconds.toInt());
    }
    if (!args.contains("enabled") && (args.contains("auto_add") || args.contains("remove_on_lock")))
        value.setAllowUseOfSshKey(value.addAtDatabaseOpen() || value.removeAtDatabaseClose());
    if (value.selectedType() != "file" && value.selectedType() != "attachment")
        fail("invalid_request", "Choose an attached key or an external key file.");
    if (value.allowUseOfSshKey() && (!value.keyConfigured() || (value.selectedType() == "attachment"
        && !entry->attachments()->hasKey(value.attachmentName())))) fail("not_found", "Choose an available SSH key source.");
    entry->beginUpdate(); value.toEntry(entry); entry->endUpdate();
}

void KeyslotSSH::updatePolicy(const Entry* entry) {
    if (endpoint.isEmpty()) return;
    const auto value = readSettings(entry);
    request({{"method", "policy"}, {"entry", entry->uuidToHex()}, {"remove_on_lock", value.removeAtDatabaseClose()}});
}

QJsonObject KeyslotSSH::prepare(const QSharedPointer<Database>& db, Entry* entry, const QByteArray& fingerprint) {
    if (entry->isRecycled()) fail("denied", "Restore this entry before adding its SSH key.");
    const auto value = readSettings(entry);
    // AllowUseOfSshKey controls automatic loading; upstream manual Add also works when it is false.
    if (!value.keyConfigured()) fail("disabled", "Choose this entry's SSH key source first.");
    auto key = QSharedPointer<OpenSSHKey>::create();
    if (!loadKey(value, entry, *key)) fail("key_error", "The SSH key could not be opened. Check its source and the entry password.");
    const auto available = request({{"method", "list"}, {"socket", agent}, {"provider", provider}});
    bool loaded = false, owned = false, other = false;
    for (const auto& item : available.value("keys").toArray()) if (item.toObject().value("fingerprint").toString() == key->fingerprint()) {
        loaded = true; owned = item.toObject().value("owned").toBool(); other = item.toObject().value("other_vault").toBool();
    }
    prunePending();
    if (pending.size() + removals.size() >= 128) fail("busy", "Too many SSH key approvals are pending.");
    const auto token = QUuid::createUuid().toString(QUuid::WithoutBraces);
    pending.insert(token, {db, fingerprint, entry->uuidToHex(), key, value, clock.elapsed() + 30000});
    return {{"token", token}, {"fingerprint", key->fingerprint()}, {"type", key->type()}, {"comment", key->comment()},
        {"public_key", key->publicKey()}, {"title", entry->title()}, {"loaded", loaded}, {"owned", owned},
        {"other_vault", other}, {"socket", agent}, {"confirm", value.useConfirmConstraintWhenAdding()},
        {"lifetime", value.useLifetimeConstraintWhenAdding()}, {"seconds", value.lifetimeConstraintDuration()},
        {"remove_on_lock", value.removeAtDatabaseClose()}};
}

QJsonObject KeyslotSSH::add(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint) {
    const auto token = text(args, "token");
    if (!pending.contains(token)) fail("expired", "The SSH approval is no longer valid.");
    const auto value = pending.take(token);
    if (value.expires <= clock.elapsed() || value.database.toStrongRef() != db || value.fingerprint != fingerprint)
        fail("conflict", "The vault changed or the SSH approval expired. Review the key again.");
    if (!flag(args, "approved")) { value.key->clearPrivate(); return {{"added", false}, {"cancelled", true}}; }
    QByteArray privateData, publicData;
    BinaryStream privateStream(&privateData), publicStream(&publicData);
    if (!value.key->writePrivate(privateStream) || !value.key->writePublic(publicStream))
        fail("key_error", "The SSH key could not be encoded.");
    value.key->clearPrivate();
    auto result = request({{"method", "add"}, {"socket", agent}, {"provider", provider}, {"entry", value.entry},
        {"private", QString::fromLatin1(privateData.toBase64())}, {"public", QString::fromLatin1(publicData.toBase64())},
        {"confirm", value.settings.useConfirmConstraintWhenAdding()}, {"lifetime", value.settings.useLifetimeConstraintWhenAdding()},
        {"seconds", value.settings.lifetimeConstraintDuration()}, {"remove_on_lock", value.settings.removeAtDatabaseClose()}});
    privateData.fill('\0');
    return result;
}

QJsonObject KeyslotSSH::owned() { return request({{"method", "owned"}}); }
QJsonObject KeyslotSSH::remove(const QJsonObject& args) {
    return request({{"method", "remove"}, {"fingerprint", text(args, "fingerprint")}, {"socket", text(args, "socket")}});
}
QJsonObject KeyslotSSH::agentKeys() {
    return request({{"method", "list"}, {"socket", agent}, {"provider", provider}});
}
QJsonObject KeyslotSSH::reviewRemoval(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint) {
    prunePending();
    if (pending.size() + removals.size() >= 128) fail("busy", "Too many SSH key approvals are pending.");
    if (!args.value("fingerprints").isArray()) fail("invalid_request", "Choose SSH keys to remove.");
    auto result = request({{"method", "review-remove"}, {"socket", agent}, {"provider", provider},
        {"clear", flag(args, "clear")}, {"fingerprints", args.value("fingerprints")}});
    const auto token = QUuid::createUuid().toString(QUuid::WithoutBraces);
    removals.insert(token, {db, fingerprint, result.value("token").toString(), clock.elapsed() + 30000});
    result.insert("token", token);
    return result;
}
QJsonObject KeyslotSSH::finishRemoval(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint) {
    const auto token = text(args, "token");
    if (!removals.contains(token)) fail("expired", "The SSH removal approval is no longer valid.");
    const auto value = removals.take(token);
    if (value.expires <= clock.elapsed() || value.database.toStrongRef() != db || value.fingerprint != fingerprint)
        fail("conflict", "The vault changed or the SSH approval expired. Review the keys again.");
    return request({{"method", "finish-remove"}, {"token", value.relayToken}, {"approved", flag(args, "approved")}});
}
