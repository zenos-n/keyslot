// SPDX-License-Identifier: GPL-3.0-only
// Settings schema / two-way merge follow KeePassXC 2.8; see RemoteSynchronization.md.
#include "KeyslotRemote.h"
#include "core/CustomData.h"
#include "core/Database.h"
#include "core/Metadata.h"
#include "core/Merger.h"
#include "format/KeePass2Writer.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QProcess>
#include <QProcessEnvironment>
#include <QSaveFile>
#include <QSet>
#include <QTemporaryDir>
#include <QUuid>
#include <cmath>
#include <unistd.h>

namespace {
const QString Settings = QStringLiteral("KPXC_REMOTE_SYNC_SETTINGS");
[[noreturn]] void fail(const char* code, const char* message) { throw KeyslotRemote::Failure{code, message}; }
QString text(const QJsonObject& object, const QString& key, int bound = 32768) {
    const auto value = object.value(key);
    if ((!value.isUndefined() && !value.isString()) || value.toString().size() > bound || value.toString().contains(QChar(0)))
        fail("invalid_request", "Remote settings contain an invalid or oversized text field.");
    return value.toString();
}
int timeout(const QJsonObject& object, const QString& key) {
    const auto value = object.value(key);
    if (value.isUndefined()) return 10000;
    const double n = value.toDouble(-1);
    if (!value.isDouble() || !std::isfinite(n) || std::floor(n) != n || n < 100 || n > 3600000)
        fail("invalid_request", "Remote command timeouts must be between 0.1 seconds and one hour.");
    return int(n);
}
void validate(const QJsonObject& object) {
    if (text(object, "name", 256).trimmed().isEmpty()) fail("invalid_request", "Give this remote location a name.");
    for (const auto& prefix : {QStringLiteral("download"), QStringLiteral("upload")}) {
        const auto command = text(object, prefix + "Command");
        const auto input = text(object, prefix + "CommandInput");
        timeout(object, prefix + "TimeoutMsec");
        if (!command.trimmed().isEmpty() && ((!command.contains("{TEMP_DATABASE}") && !input.contains("{TEMP_DATABASE}"))
            || QProcess::splitCommand(command).isEmpty()))
            fail("invalid_request", "Each transfer must include {TEMP_DATABASE} in its command or standard input.");
    }
    if (text(object, "downloadCommand").trimmed().isEmpty() && text(object, "uploadCommand").trimmed().isEmpty())
        fail("invalid_request", "Provide a download command, an upload command, or both.");
}
QJsonArray read(const QSharedPointer<Database>& db) {
    const auto raw = db->metadata()->customData()->value(Settings);
    if (raw.isEmpty()) return {};
    if (raw.size() > 4 * 1024 * 1024) fail("invalid_request", "Remote settings are too large to edit safely.");
    QJsonParseError error;
    const auto doc = QJsonDocument::fromJson(raw.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError || !doc.isArray() || doc.array().size() > 256)
        fail("invalid_request", "Existing remote settings are invalid. They have been left unchanged.");
    QSet<QString> names;
    for (const auto& item : doc.array()) {
        if (!item.isObject()) fail("invalid_request", "Existing remote settings are invalid. They have been left unchanged.");
        const auto name = text(item.toObject(), "name", 256);
        if (name.isEmpty() || names.contains(name)) fail("invalid_request", "Existing remote location names are empty or duplicated. Settings were kept unchanged.");
        names.insert(name);
    }
    return doc.array();
}
QByteArray fingerprint(const QString& path) {
    QFileInfo info(path);
    if (info.isSymLink() || !info.isFile() || info.size() == 0)
        fail("remote_error", "The transfer did not produce a regular, nonempty database file.");
    QFile file(path);
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!file.open(QIODevice::ReadOnly) || !hash.addData(&file)) fail("remote_error", "The transferred database could not be read.");
    return hash.result();
}
void write(const QSharedPointer<Database>& db, const QString& path) {
    QSaveFile output(path);
    if (!output.open(QIODevice::WriteOnly) || !output.setPermissions(QFile::ReadOwner | QFile::WriteOwner))
        fail("save_error", "The encrypted upload file could not be created.");
    KeePass2Writer writer;
    if (!writer.writeDatabase(&output, db.data()) || !output.flush() || ::fsync(output.handle()) != 0 || !output.commit())
        fail("save_error", "The encrypted upload file could not be saved completely. Nothing was uploaded.");
}
}

struct KeyslotRemote::Pending {
    QWeakPointer<Database> database;
    QByteArray revision, downloadedHash, uploadHash;
    QJsonObject profile;
    QString token, phase = "review", download, upload, verify;
    QTemporaryDir directory;
    QProcess runner;
    QElapsedTimer age;
    Pending() : directory(qEnvironmentVariable("KEYSLOT_ENGINE_CONFIG_DIRECTORY") + "/remote-XXXXXX") { age.start(); }
    ~Pending() { stop(); }
    void stop() {
        if (runner.state() != QProcess::NotRunning) {
            runner.terminate();
            if (!runner.waitForFinished(1500)) { runner.kill(); runner.waitForFinished(1000); }
        }
    }
    QJsonObject state() const { return {{"token", token}, {"state", phase}}; }
    void start(const QString& prefix, const QString& path, const QString& next) {
        auto words = QProcess::splitCommand(text(profile, prefix + "Command"));
        // Parse before substitution so spaces in private runtime paths remain a single argument.
        for (auto& word : words) word.replace("{TEMP_DATABASE}", path);
        const auto program = words.takeFirst();
        auto input = text(profile, prefix + "CommandInput");
        input.replace("{TEMP_DATABASE}", path);
        QJsonArray arguments;
        for (const auto& word : words) arguments.append(word);
        const auto request = QJsonDocument(QJsonObject{{"program", program}, {"arguments", arguments},
            {"input", input}, {"timeout", timeout(profile, prefix + "TimeoutMsec")}}).toJson(QJsonDocument::Compact);
        runner.setProgram(QCoreApplication::applicationDirPath() + "/keyslot-remote-runner");
        runner.setArguments({QString::number(QCoreApplication::applicationPid())});
        runner.setStandardOutputFile(QProcess::nullDevice());
        runner.setStandardErrorFile(QProcess::nullDevice());
        auto environment = QProcessEnvironment::systemEnvironment();
        for (const auto& name : environment.keys()) if (name.startsWith("KEYSLOT_")) environment.remove(name);
        runner.setProcessEnvironment(environment);
        runner.start();
        if (!runner.waitForStarted(3000)) fail("remote_error", "The remote command supervisor could not start. No transfer was confirmed.");
        if (runner.write(request) != request.size()) { stop(); fail("remote_error", "The remote command could not be submitted."); }
        runner.closeWriteChannel();
        phase = next;
        age.restart();
    }
};

KeyslotRemote::KeyslotRemote() = default;
KeyslotRemote::~KeyslotRemote() = default;
void KeyslotRemote::clear() { pending.reset(); }
QJsonArray KeyslotRemote::locations(const QSharedPointer<Database>& db) {
    QJsonArray result;
    for (const auto& item : read(db)) {
        const auto object = item.toObject();
        result.append(QJsonObject{{"name", text(object, "name", 256)},
            {"download", !text(object, "downloadCommand").trimmed().isEmpty()},
            {"upload", !text(object, "uploadCommand").trimmed().isEmpty()}});
    }
    return result;
}
QJsonObject KeyslotRemote::location(const QSharedPointer<Database>& db, const QString& name) {
    for (const auto& item : read(db)) if (item.toObject().value("name").toString() == name) {
        const auto profile = item.toObject();
        for (const auto& prefix : {QStringLiteral("download"), QStringLiteral("upload")}) {
            text(profile, prefix + "Command"); text(profile, prefix + "CommandInput");
            timeout(profile, prefix + "TimeoutMsec");
        }
        return profile;
    }
    fail("not_found", "This remote location no longer exists. Open the location list again.");
}
void KeyslotRemote::edit(const QSharedPointer<Database>& db, const QJsonObject& args, bool remove) {
    const auto original = text(args, "original", 256);
    auto items = read(db);
    int index = -1;
    for (int i = 0; i < items.size(); ++i) if (items[i].toObject().value("name").toString() == original) index = i;
    if (!original.isEmpty() && index == -1) fail("conflict", "This location changed. Open its settings again.");
    if (remove) {
        if (index == -1) fail("invalid_request", "Choose a remote location to remove.");
        items.removeAt(index);
    } else {
        if (!args.value("profile").isObject()) fail("invalid_request", "Provide remote location settings.");
        auto profile = index < 0 ? QJsonObject{} : items[index].toObject();
        const auto changes = args.value("profile").toObject();
        // Retain extension fields written by other clients, but edit only the compatible schema.
        for (const auto& field : {"name", "downloadCommand", "downloadCommandInput", "downloadTimeoutMsec",
                                 "uploadCommand", "uploadCommandInput", "uploadTimeoutMsec"})
            if (changes.contains(field)) profile.insert(field, changes.value(field));
        validate(profile);
        for (int i = 0; i < items.size(); ++i) if (i != index && items[i].toObject().value("name") == profile.value("name"))
            fail("invalid_request", "A remote location already uses this name.");
        if (index < 0) { if (items.size() >= 256) fail("invalid_request", "Remove an unused location before adding another."); items.append(profile); }
        else items[index] = profile;
    }
    const auto encoded = QJsonDocument(items).toJson(QJsonDocument::Compact);
    if (encoded.size() > 4 * 1024 * 1024) fail("invalid_request", "Remote settings are too large.");
    db->metadata()->customData()->set(Settings, QString::fromUtf8(encoded));
}
QJsonObject KeyslotRemote::prepare(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision) {
    if (pending) fail("busy", "Finish or cancel the current synchronization first.");
    auto profile = location(db, text(args, "name", 256));
    validate(profile);
    auto plan = std::make_unique<Pending>();
    if (!plan->directory.isValid()) fail("file_error", "A private encrypted transfer directory could not be created.");
    plan->database = db; plan->revision = revision; plan->profile = profile;
    plan->token = QUuid::createUuid().toString(QUuid::WithoutBraces);
    plan->download = plan->directory.filePath("download.kdbx");
    plan->upload = plan->directory.filePath("upload.kdbx");
    plan->verify = plan->directory.filePath("verify.kdbx");
    auto result = plan->state(); result.insert("profile", profile);
    pending = std::move(plan);
    return result;
}
QJsonObject KeyslotRemote::call(const QString& method, const QSharedPointer<Database>& db, const QJsonObject& args,
    const QByteArray& revision, const QSharedPointer<const CompositeKey>& key, const Commit& commit) {
    if (!pending || pending->token != text(args, "token", 128)) fail("expired", "This synchronization is no longer active.");
    if (method == "remote.cancel") { clear(); return {{"state", "cancelled"}}; }
    auto& plan = *pending;
    if (plan.database.toStrongRef() != db || plan.revision != revision || plan.age.elapsed() > 3700000) {
        clear(); fail("conflict", "The vault changed or synchronization expired. Start again; nothing further was uploaded.");
    }
    if (method == "remote.start") {
        if (plan.phase != "review" || args.value("approved") != QJsonValue(true)) fail("invalid_request", "Review and approve the commands before running them.");
        if (text(plan.profile, "downloadCommand").trimmed().isEmpty()) plan.phase = "ready_merge";
        else plan.start("download", plan.download, "downloading");
    } else if (method == "remote.poll") {
        if (plan.phase == "downloading" || plan.phase == "verifying" || plan.phase == "uploading") {
            if (plan.runner.state() != QProcess::NotRunning) plan.runner.waitForFinished(25);
            if (plan.runner.state() == QProcess::NotRunning) {
                const auto phase = plan.phase;
                plan.phase = "failed";
                if (plan.runner.exitStatus() != QProcess::NormalExit || plan.runner.exitCode() != 0) {
                    if (phase == "uploading") fail("remote_error", "Upload did not finish successfully. The merged local vault was saved; the remote outcome is unknown. Inspect the remote file before retrying.");
                    if (phase == "verifying") fail("remote_error", "The pre-upload remote check failed. The merged local vault was saved; nothing was uploaded.");
                    fail("remote_error", "Download failed or timed out. No merge or upload was performed. Check the command and its timeout.");
                }
                if (phase == "downloading") {
                    plan.downloadedHash = fingerprint(plan.download); plan.phase = "ready_merge";
                } else if (phase == "verifying") {
                    if (fingerprint(plan.verify) != plan.downloadedHash)
                        fail("conflict", "The remote file changed during synchronization. The local merge was saved; upload was stopped. Start a fresh synchronization.");
                    plan.phase = "ready_upload";
                } else plan.phase = "done";
                plan.age.restart();
            }
        }
    } else if (method == "remote.merge") {
        if (plan.phase != "ready_merge" && plan.phase != "credentials_required") fail("invalid_request", "Download the remote file before merging.");
        QSharedPointer<Database> remote;
        if (!plan.downloadedHash.isEmpty()) {
            if (fingerprint(plan.download) != plan.downloadedHash) fail("conflict", "The downloaded file changed. Cancel and start again.");
            remote = QSharedPointer<Database>::create();
            if (!remote->open(plan.download, key ? key : db->key())) { plan.phase = "credentials_required"; return plan.state(); }
            if (fingerprint(plan.download) != plan.downloadedHash) fail("conflict", "The downloaded file changed while unlocking. Cancel and start again.");
        }
        const bool upload = !text(plan.profile, "uploadCommand").trimmed().isEmpty();
        // No upload can start until the local transaction is durable. The remote keeps its own key/KDF/cipher.
        plan.revision = commit([&] {
            if (remote) {
                Merger first(db.data(), remote.data()); first.merge();
                Merger second(remote.data(), db.data()); second.merge();
            }
            if (upload) { write(remote ? remote : db, plan.upload); plan.uploadHash = fingerprint(plan.upload); }
        });
        if (!upload) plan.phase = "done";
        else if (remote) plan.start("download", plan.verify, "verifying");
        else plan.phase = "ready_upload";
    } else if (method == "remote.upload") {
        if (plan.phase != "ready_upload") fail("invalid_request", "Complete the local merge and remote check before uploading.");
        if (fingerprint(plan.upload) != plan.uploadHash) fail("conflict", "The encrypted upload file changed. Nothing was uploaded.");
        plan.start("upload", plan.upload, "uploading");
    } else fail("invalid_request", "Unknown remote synchronization operation.");
    return plan.state();
}
