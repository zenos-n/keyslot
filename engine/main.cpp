// SPDX-License-Identifier: GPL-3.0-only
// Built inside the pinned KeePassXC source tree; no KDBX or crypto reimplementation.
#include "config-keepassx.h"
#include "CsvImport.h"
#include "BrowserDatabase.h"
#include "KeyslotSSH.h"
#include "KeyslotAutoType.h"
#include "KeyslotKeeShare.h"
#include "KeyslotSecrets.h"
#include "KeyslotTransfer.h"
#include "KeyslotLaunch.h"
#include "KeyslotConfig.h"
#include "KeyslotHistory.h"
#include "KeyslotTotp.h"
#include "KeyslotTrash.h"
#include "KeyslotEntryActions.h"
#include "KeyslotReports.h"
#include "KeyslotIcons.h"
#include "KeyslotNetwork.h"
#include <QKeySequence>
#include "fdosecrets/FdoSecretsSettings.h"
#include "core/Bootstrap.h"
#include "core/Database.h"
#include "core/CustomData.h"
#include "core/Clock.h"
#include "core/Config.h"
#include "core/DatabaseStats.h"
#include "core/Entry.h"
#include "core/EntrySearcher.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "core/Merger.h"
#include "core/PasswordHealth.h"
#include "core/PassphraseGenerator.h"
#include "core/PasswordGenerator.h"
#include "core/Resources.h"
#include "core/Totp.h"
#include "crypto/Crypto.h"
#include "crypto/kdf/Argon2Kdf.h"
#include "format/CsvExporter.h"
#include "format/BitwardenReader.h"
#include "format/HtmlExporter.h"
#include "format/KeePass1Reader.h"
#include "format/KeePass2Writer.h"
#include "format/KeePass2Reader.h"
#include "format/OPUXReader.h"
#include "format/OpVaultReader.h"
#include "format/ProtonPassReader.h"
#include "keys/FileKey.h"
#ifdef WITH_XC_YUBIKEY
#include "keys/ChallengeResponseKey.h"
#endif

#include <QCoreApplication>
#include <QColor>
#include <QImageReader>
#include <QBuffer>
#include <QCryptographicHash>
#include <QDir>
#include <QDirIterator>
#include <QCollator>
#include <QSet>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocale>
#include <QLockFile>
#include <QMap>
#include <QRegularExpression>
#include <QSaveFile>
#include <QTemporaryDir>
#include <exception>
#include <algorithm>
#include <functional>
#include <cstdio>
#include <cmath>
#include <memory>
#include <limits>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr qint64 MaxFrame = 64 * 1024 * 1024;
struct Failure { QString code; QString message; QJsonObject details {}; };
[[noreturn]] void fail(const char* code, const char* message) { throw Failure{code, message}; }
QString text(const QJsonObject& o, const char* key, const QString& fallback = {})
{
    if (!o.contains(key)) return fallback;
    if (!o.value(key).isString()) fail("invalid_request", "Expected a text field.");
    return o.value(key).toString();
}
bool boolean(const QJsonObject& o, const char* key, bool fallback = false)
{
    if (!o.contains(key)) return fallback;
    if (!o.value(key).isBool()) fail("invalid_request", "Expected a boolean field.");
    return o.value(key).toBool();
}
qint64 integer(const QJsonObject& o, const char* key, qint64 low, qint64 high)
{
    const auto value = o.value(key);
    const double number = value.toDouble(-1);
    if (!value.isDouble() || !std::isfinite(number) || std::floor(number) != number || number < low || number > high)
        fail("invalid_request", "A numeric setting is outside the supported range.");
    return static_cast<qint64>(number);
}
QString uid(const QUuid& value) { return value.toString(QUuid::WithoutBraces); }
QString requestedPath(const QJsonObject& args, const char* key = "path") {
    const auto value = text(args, key);
    if (value.isEmpty() || value.contains(QChar('\0'))) fail("invalid_request", "Choose a valid file path.");
    return value;
}
QByteArray digest(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) fail("file_error", "The database could not be read.");
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!hash.addData(&file)) fail("file_error", "The database could not be read completely.");
    return hash.result();
}
QByteArray importFingerprint(const QString& path, bool directory)
{
    if (!directory) {
        if (!QFileInfo(path).isFile()) fail("file_error", "Select an import source file.");
        return digest(path);
    }
    if (!QFileInfo(path).isDir()) fail("file_error", "Select an OPVault directory.");
    QStringList files;
    QDirIterator iterator(path, QDir::Files | QDir::Hidden | QDir::System,
                          QDirIterator::Subdirectories | QDirIterator::FollowSymlinks);
    while (iterator.hasNext()) files.append(iterator.next());
    files.sort();
    QCryptographicHash hash(QCryptographicHash::Sha256);
    const QDir root(path);
    for (const auto& file : files) {
        if (!QFileInfo(file).isFile()) fail("file_error", "The import directory contains an unreadable or unsupported file.");
        hash.addData(root.relativeFilePath(file).toUtf8());
        hash.addData("\0", 1);
        hash.addData(digest(file));
    }
    return hash.result();
}
void copyToSaveFile(const QString& source, const QString& target, QFile::Permissions permissions,
                    const std::function<void()>& beforeCommit = [] {})
{
    QFile input(source);
    QSaveFile output(target);
    output.setDirectWriteFallback(false);
    if (!input.open(QIODevice::ReadOnly) || !output.open(QIODevice::WriteOnly)
        || !output.setPermissions(permissions)) fail("file_error", "The encrypted file could not be staged.");
    while (!input.atEnd()) {
        const auto bytes = input.read(1024 * 1024);
        if (bytes.isEmpty() && input.error() != QFile::NoError)
            fail("file_error", "The encrypted file could not be read completely.");
        if (output.write(bytes) != bytes.size()) fail("file_error", "The encrypted file could not be written completely.");
    }
    beforeCommit();
    if (!output.commit()) fail("file_error", "The encrypted file could not be committed.");
}
QString keepRecoveryCopy(const QString& source, const QByteArray& expectedHash)
{
    const auto root = qEnvironmentVariable("KEYSLOT_RECOVERY_DIRECTORY");
    if (root.isEmpty() || !QFileInfo(root).isAbsolute() || !QDir().mkpath(root)) return source;
    struct stat info {};
    if (::lstat(QFile::encodeName(root).constData(), &info) || !S_ISDIR(info.st_mode)
        || info.st_uid != ::getuid() || !QFile::setPermissions(root, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner))
        return source;
    QTemporaryDir kept(root + "/recovery-XXXXXX");
    if (!kept.isValid()) return source;
    const auto target = kept.path() + "/database.kdbx";
    try {
        copyToSaveFile(source, target, QFile::ReadOwner | QFile::WriteOwner);
        if (digest(target) != expectedHash) return source;
    } catch (...) {
        return source;
    }
    kept.setAutoRemove(false);
    return target;
}
QString manualRoot(bool create = false)
{
    const auto root = qEnvironmentVariable("KEYSLOT_RECOVERY_DIRECTORY");
    if (root.isEmpty() || !QFileInfo(root).isAbsolute()) {
        if (!create) return {};
        fail("file_error", "A private recovery directory is required for manual saving.");
    }
    if (!QFileInfo::exists(root) && !create) return root;
    struct stat info {};
    if ((create && !QDir().mkpath(root)) || ::lstat(QFile::encodeName(root).constData(), &info)
        || !S_ISDIR(info.st_mode) || info.st_uid != ::getuid()
        || !QFile::setPermissions(root, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner))
        fail("file_error", "The private recovery directory could not be secured.");
    return QDir(root).canonicalPath();
}
bool recoveryLocation(const QString& path)
{
    const auto configured = qEnvironmentVariable("KEYSLOT_RECOVERY_DIRECTORY");
    if (configured.isEmpty() || !QFileInfo(configured).isAbsolute()) return false;
    const auto root = QDir(configured).canonicalPath();
    return !root.isEmpty() && path.startsWith(root + "/");
}
QJsonObject manualInfo(const QString& manifest, const QString& source = {})
{
    const QFileInfo file(manifest), directory(file.absolutePath());
    struct stat info {};
    if (file.fileName() != "manifest.json" || directory.absolutePath() != manualRoot()
        || !directory.fileName().startsWith("manual-")
        || ::lstat(QFile::encodeName(directory.absoluteFilePath()).constData(), &info)
        || !S_ISDIR(info.st_mode) || info.st_uid != ::getuid() || (info.st_mode & 0077)
        || ::lstat(QFile::encodeName(manifest).constData(), &info)
        || !S_ISREG(info.st_mode) || info.st_uid != ::getuid() || (info.st_mode & 0077))
        fail("file_error", "The unsaved-vault recovery record is not a private regular file.");
    QFile input(manifest);
    if (!input.open(QIODevice::ReadOnly) || input.size() > 16384) fail("file_error", "The recovery record could not be read.");
    const auto data = QJsonDocument::fromJson(input.readAll()).object();
    const auto original = data.value("source").toString(), name = data.value("snapshot").toString();
    const QRegularExpression sha("^[a-f0-9]{64}$"), snapshot("^snapshot-[a-f0-9-]{36}\\.kdbx$");
    if (data.value("version").toInt() != 1 || !QFileInfo(original).isAbsolute()
        || (!source.isEmpty() && original != source) || !snapshot.match(name).hasMatch()
        || !sha.match(data.value("base_hash").toString()).hasMatch()
        || !sha.match(data.value("snapshot_hash").toString()).hasMatch())
        fail("file_error", "The recovery record is invalid or belongs to another vault.");
    const auto saved = directory.absoluteFilePath() + "/" + name;
    if (::lstat(QFile::encodeName(saved).constData(), &info) || !S_ISREG(info.st_mode)
        || info.st_uid != ::getuid() || (info.st_mode & 0077))
        fail("file_error", "The encrypted recovery snapshot is not a private regular file.");
    auto result = data;
    result.insert("manifest", manifest); result.insert("path", saved);
    return result;
}
void discardManual(const QJsonObject& data, bool strict = true)
{
    const QFileInfo manifest(data.value("manifest").toString());
    if (!QFile::remove(manifest.absoluteFilePath())) {
        if (strict) fail("file_error", "The recovery record could not be removed.");
        return;
    }
    QDir directory(manifest.absolutePath());
    for (const auto& name : directory.entryList({"snapshot-*.kdbx"}, QDir::Files | QDir::NoSymLinks)) directory.remove(name);
}
QByteArray commitManual(const QString& manifest, const QString& source, bool ownsCheckpoint = false)
{
    manualInfo(manifest, source);
    QLockFile owner(manifest + ".owner");
    if (!ownsCheckpoint && !owner.tryLock()) fail("busy", "The vault owning this recovery copy is still open.");
    QLockFile lock(manifest + ".lock");
    if (!lock.tryLock()) fail("busy", "Another process is already saving this recovery snapshot.");
    const auto data = manualInfo(manifest, source);
    const auto snapshot = data.value("path").toString();
    const auto savedHash = QByteArray::fromHex(data.value("snapshot_hash").toString().toLatin1());
    const auto baseHash = QByteArray::fromHex(data.value("base_hash").toString().toLatin1());
    if (digest(snapshot) != savedHash) fail("file_error", "The encrypted recovery snapshot changed. It was not saved over the vault.");
    // A crash after the file commit but before journal removal is safe to retry.
    if (digest(source) != savedHash) {
        const auto verify = [&] {
            if (digest(source) != baseHash || digest(snapshot) != savedHash)
                fail("conflict", "The vault changed elsewhere. The unsaved encrypted copy was kept for recovery.");
        };
        verify();
        const QFileInfo destination(source);
        if (!destination.isWritable()) fail("read_only", "The vault is read-only. Its unsaved encrypted copy was kept.");
        copyToSaveFile(source, source + ".keyslot.bak", QFile::ReadOwner | QFile::WriteOwner, verify);
        copyToSaveFile(snapshot, source, destination.permissions(), verify);
        const int directory = ::open(QFile::encodeName(destination.absolutePath()).constData(), O_RDONLY | O_DIRECTORY);
        if (directory >= 0) { ::fsync(directory); ::close(directory); }
    }
    discardManual(data, false);
    return savedHash;
}
QJsonArray manualRecords(const QString& source)
{
    QList<QJsonObject> records;
    const auto location = manualRoot();
    if (location.isEmpty()) return {};
    const QDir root(location);
    for (const auto& item : root.entryInfoList({"manual-*"}, QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks)) {
        const auto manifest = item.absoluteFilePath() + "/manifest.json";
        if (!QFileInfo::exists(manifest)) continue;
        try {
            auto record = manualInfo(manifest);
            QLockFile owner(manifest + ".owner");
            if (!owner.tryLock()) continue;
            record = manualInfo(manifest);
            if (!source.isEmpty() && record.value("source").toString() != source) continue;
            record.insert("modified", double(QFileInfo(record.value("path").toString()).lastModified().toMSecsSinceEpoch()));
            records.append(record);
        } catch (const Failure&) {}
    }
    std::stable_sort(records.begin(), records.end(), [](const QJsonObject& left, const QJsonObject& right) {
        return left.value("modified").toDouble() > right.value("modified").toDouble();
    });
    QJsonArray result;
    for (const auto& item : records) result.append(item);
    return result;
}
QJsonObject summary(const Entry* e)
{
    auto visible = [e](const QString& key) {
        return e->attributes()->isProtected(key) ? QString() : e->attributes()->value(key);
    };
    QJsonArray attributes, attachments;
    for (const auto& name : e->attributes()->customKeys()) attributes.append(name);
    for (const auto& name : e->attachments()->keys()) attachments.append(name);
    return {{"uuid", uid(e->uuid())}, {"path", e->path()}, {"group", uid(e->group()->uuid())},
            {"group_path", e->group()->fullPath()}, {"title", e->title()},
            {"username", visible(EntryAttributes::UserNameKey)}, {"url", visible(EntryAttributes::URLKey)},
            {"notes", visible(EntryAttributes::NotesKey)}, {"tags", e->tags()},
            {"attributes", attributes}, {"attachments", attachments},
            {"history_count", e->historyItems().size()}, {"totp", e->hasTotp()}, {"passkey", e->hasPasskey()},
            {"recycled", e->isRecycled()}, {"addressable", true},
            {"expires", e->timeInfo().expires()}, {"expiry", e->timeInfo().expiryTime().toString(Qt::ISODate)},
            {"expired", e->isExpired()}, {"icon", e->iconNumber()},
            {"custom_icon", e->iconUuid().isNull() ? QString() : uid(e->iconUuid())},
            {"foreground", e->foregroundColor()}, {"background", e->backgroundColor()},
            {"override_url", e->overrideUrl()}, {"exclude_reports", e->excludeFromReports()},
            {"command_approved", KeyslotLaunch::approved(e)},
            {"created", e->timeInfo().creationTime().toString(Qt::ISODate)},
            {"modified", e->timeInfo().lastModificationTime().toString(Qt::ISODate)}};
}
QJsonObject csvOptions(const QJsonObject& args) {
    if (args.contains("csv_options") && !args.value("csv_options").isObject())
        fail("invalid_request", "CSV options must be an object.");
    return args.value("csv_options").toObject();
}
void checkImportReview(const QJsonObject& args, const QByteArray& fingerprint) {
    if (args.contains("source_fingerprint") && text(args, "source_fingerprint") != QString::fromLatin1(fingerprint.toHex()))
        fail("conflict", "The import source changed since review. Review it again before importing.");
}

class Engine {
    KeyslotBrowserDatabase browser;
    KeyslotSSH ssh;
    KeyslotAutoType autotype;
    KeyslotKeeShare keeshare;
    KeyslotSecrets secrets;
    KeyslotSecretSessions secretSessions;
    KeyslotTransfer transfer;
    KeyslotLaunch launch;
    KeyslotTrash trash;
    KeyslotEntryActions entryActions;
    KeyslotReports reports;
    KeyslotIcons iconTools;
    QSharedPointer<Database> db;
    QString path;
    QByteArray hash, diskHash;
    bool autoSave = true, modified = false;
    QString manualManifest, manualSnapshot;
    std::unique_ptr<QLockFile> manualOwner;

    void requireDatabase() const { if (!db) fail("locked", "Unlock a database first."); }
    void unchanged() const {
        requireDatabase();
        if (digest(path) != diskHash) fail("conflict", "Another application changed this database. Refresh before continuing.");
    }
    Entry* entry(const QJsonObject& args) const {
        requireDatabase();
        const QUuid id(text(args, "entry"));
        auto* result = id.isNull() ? nullptr : db->rootGroup()->findEntryByUuid(id);
        if (!result) fail("not_found", "The entry no longer exists. Refresh the database.");
        return result;
    }
    void historyRevision(const QJsonObject& args) const {
        unchanged();
        if (text(args, "revision") != QString::fromLatin1(hash.toHex()))
            fail("conflict", "The database changed since history was reviewed. Open history again.");
    }
    Entry* historyVersion(Entry* current, const QJsonObject& args, const char* field, bool allowCurrent = true) const {
        const int index = integer(args, field, allowCurrent ? -1 : 0, std::numeric_limits<int>::max());
        if (allowCurrent && index == -1) return current;
        if (index >= current->historyItems().size()) fail("invalid_request", "Select a valid history version.");
        return current->historyItems().at(index);
    }
    Group* group(const QString& id) const {
        requireDatabase();
        const QUuid uuid(id);
        auto* result = uuid.isNull() ? nullptr : db->rootGroup()->findGroupByUuid(uuid);
        if (!result) fail("not_found", "The group no longer exists. Refresh the database.");
        return result;
    }
    QSharedPointer<CompositeKey> makeKey(const QJsonObject& args, bool allowEmpty = false) {
        auto key = QSharedPointer<CompositeKey>::create();
        if (!boolean(args, "no_password")) key->addKey(QSharedPointer<PasswordKey>::create(text(args, "password")));
        const auto file = text(args, "keyfile");
        if (!file.isEmpty()) {
            auto fileKey = QSharedPointer<FileKey>::create();
            if (!fileKey->load(file)) fail("key_error", "The key file could not be loaded.");
            key->addKey(fileKey);
        }
        const auto hardware = text(args, "yubikey");
        if (!hardware.isEmpty()) {
#ifdef WITH_XC_YUBIKEY
            auto match = QRegularExpression("^([12])(?::([0-9]+))?$").match(hardware);
            if (!match.hasMatch()) fail("invalid_request", "Use hardware key slot 1 or 2, optionally followed by :serial.");
            bool valid = true;
            const auto serial = match.captured(2).isEmpty() ? 0u : match.captured(2).toUInt(&valid);
            if (!valid) fail("invalid_request", "The hardware key serial is invalid.");
            key->addChallengeResponseKey(QSharedPointer<ChallengeResponseKey>::create(YubiKeySlot{serial, match.captured(1).toInt()}));
            YubiKey::instance()->findValidKeys();
#else
            fail("unsupported", "This engine was built without hardware-key support.");
#endif
        }
        if (!allowEmpty && key->isEmpty()) fail("key_error", "Choose a password, a key file, or a hardware key.");
        return key;
    }
    void clearManual() {
        if (!manualManifest.isEmpty() && QFileInfo::exists(manualManifest)) {
            try { discardManual(manualInfo(manualManifest, path), false); } catch (const Failure&) {}
        }
        manualSnapshot.clear();
        modified = false;
        if (!manualManifest.isEmpty() && !QFileInfo::exists(manualManifest)) {
            const auto directory = QFileInfo(manualManifest).absolutePath();
            manualOwner.reset();
            QDir().rmdir(directory);
            manualManifest.clear();
            QFile::remove(qEnvironmentVariable("KEYSLOT_ENGINE_CONFIG_DIRECTORY") + "/manual.json");
        }
    }
    void writeState(const QString& target) {
        QFile output(target);
        if (!output.open(QIODevice::WriteOnly | QIODevice::NewOnly)
            || !output.setPermissions(QFile::ReadOwner | QFile::WriteOwner))
            fail("file_error", "An encrypted recovery snapshot could not be created.");
        KeePass2Writer writer;
        if (!writer.writeDatabase(&output, db.data()) || !output.flush() || ::fsync(output.handle()) != 0)
            fail("save_error", "The encrypted recovery snapshot could not be written completely.");
    }
    void checkpoint() {
        if (manualManifest.isEmpty()) {
            QTemporaryDir directory(manualRoot(true) + "/manual-XXXXXX");
            if (!directory.isValid()) fail("file_error", "A private unsaved-vault directory could not be created.");
            manualManifest = directory.path() + "/manifest.json";
            manualOwner = std::make_unique<QLockFile>(manualManifest + ".owner");
            if (!manualOwner->tryLock()) fail("busy", "The recovery checkpoint could not be reserved.");
            QSaveFile pointer(qEnvironmentVariable("KEYSLOT_ENGINE_CONFIG_DIRECTORY") + "/manual.json");
            const auto record = QJsonDocument(QJsonObject{{"manifest", manualManifest}}).toJson(QJsonDocument::Compact);
            if (!pointer.open(QIODevice::WriteOnly) || !pointer.setPermissions(QFile::ReadOwner | QFile::WriteOwner)
                || pointer.write(record) != record.size() || !pointer.commit()) {
                manualManifest.clear();
                fail("file_error", "The unsaved-vault journal could not be prepared.");
            }
            directory.setAutoRemove(false);
        }
        QLockFile lock(manualManifest + ".lock");
        if (!lock.tryLock()) fail("busy", "The recovery checkpoint is in use.");
        QTemporaryDir staging(qEnvironmentVariable("KEYSLOT_ENGINE_CONFIG_DIRECTORY") + "/checkpoint-XXXXXX");
        if (!staging.isValid()) fail("file_error", "The recovery snapshot could not be staged.");
        const auto stage = staging.path() + "/database.kdbx";
        writeState(stage);
        const auto revision = digest(stage);
        const auto directory = QFileInfo(manualManifest).absolutePath();
        const auto name = "snapshot-" + uid(QUuid::createUuid()) + ".kdbx";
        const auto target = directory + "/" + name;
        copyToSaveFile(stage, target, QFile::ReadOwner | QFile::WriteOwner);
        if (digest(target) != revision) fail("file_error", "The encrypted checkpoint could not be verified.");
        const auto data = QJsonDocument(QJsonObject{{"version", 1}, {"source", path}, {"snapshot", name},
            {"base_hash", QString::fromLatin1(diskHash.toHex())},
            {"snapshot_hash", QString::fromLatin1(revision.toHex())}}).toJson(QJsonDocument::Compact);
        QSaveFile journal(manualManifest);
        if (!journal.open(QIODevice::WriteOnly) || !journal.setPermissions(QFile::ReadOwner | QFile::WriteOwner)
            || journal.write(data) != data.size() || !journal.commit())
            fail("file_error", "The encrypted checkpoint could not be recorded. The previous state was kept.");
        const int dir = ::open(QFile::encodeName(directory).constData(), O_RDONLY | O_DIRECTORY);
        if (dir >= 0) { ::fsync(dir); ::close(dir); }
        const auto previous = manualSnapshot;
        manualSnapshot = target; hash = revision; modified = true;
        if (!previous.isEmpty() && previous != target) QFile::remove(previous);
        db->markAsModified();
    }
    void reload(QSharedPointer<const CompositeKey> key = {}, bool discard = false) {
        requireDatabase();
        if (modified && !discard) fail("unsaved_changes", "Save, merge or discard the unsaved changes before reloading.");
        if (!key) key = db->key();
        auto replacement = QSharedPointer<Database>::create();
        const auto before = digest(path);
        if (!replacement->open(path, key) || digest(path) != before) {
            fail("key_error", "The database could not be reopened. The currently open data is still available to save as a copy.");
        }
        db = std::move(replacement);
        clearManual();
        hash = diskHash = before;
    }
    void persist(bool creating = false, bool prepared = true) {
        if (!creating && prepared && modified && !manualSnapshot.isEmpty()) {
            hash = diskHash = commitManual(manualManifest, path, true);
            clearManual();
            db->markAsClean();
            return;
        }
        if (!creating) unchanged();
        QFileInfo info(path);
        if (!creating && !info.isWritable()) fail("read_only", "The database is read-only.");
        QTemporaryDir temporary(info.absolutePath() + "/.keyslot-XXXXXX");
        if (!temporary.isValid()) fail("file_error", "An encrypted staging directory could not be created.");
        const auto stage = temporary.path() + "/database.kdbx";
        if (!db->saveAs(stage, Database::Atomic)) fail("save_error", "KeePassXC could not save the encrypted database.");
        if (!QFile::setPermissions(stage, QFile::ReadOwner | QFile::WriteOwner))
            fail("file_error", "The encrypted staging file permissions could not be secured.");
        const auto persistedHash = digest(stage);
        if (creating) {
            // link() is atomic and refuses to replace an existing database.
            if (::link(QFile::encodeName(stage).constData(), QFile::encodeName(path).constData()) != 0)
                fail("file_error", "The database could not be created. A file may already exist there.");
        } else {
            unchanged();
            copyToSaveFile(path, path + ".keyslot.bak", QFile::ReadOwner | QFile::WriteOwner,
                           [this] { unchanged(); });
            copyToSaveFile(stage, path, info.permissions(), [this] { unchanged(); });
        }
        const int directory = ::open(QFile::encodeName(info.absolutePath()).constData(), O_RDONLY | O_DIRECTORY);
        if (directory >= 0) { ::fsync(directory); ::close(directory); }
        db->setFilePath(path);
        db->markAsClean();
        // Fingerprint our serialized output, never an external writer's later replacement.
        hash = diskHash = persistedHash;
        clearManual();
    }
    QJsonObject transaction(const std::function<void()>& change, bool forceSave = false,
                            const QByteArray& acceptedSource = {}) {
        if (acceptedSource.isEmpty()) unchanged();
        else if (digest(path) != acceptedSource) fail("conflict", "The merge source changed before the merge began.");
        const auto originalKey = db->key();
        const auto originalHash = hash;
        const auto originalDiskHash = diskHash;
        const auto originalModified = modified;
        QTemporaryDir recovery(qEnvironmentVariable("KEYSLOT_ENGINE_CONFIG_DIRECTORY") + "/recovery-XXXXXX");
        if (!recovery.isValid()) fail("file_error", "An encrypted recovery snapshot could not be created. The vault was not changed.");
        const auto recoveryPath = recovery.path() + "/database.kdbx";
        const auto pending = recovery.path() + "/pending.kdbx";
        if (!acceptedSource.isEmpty() && !modified) writeState(pending);
        else copyToSaveFile(modified ? manualSnapshot : path, pending, QFile::ReadOwner | QFile::WriteOwner);
        const auto recoveryHash = digest(pending);
        if (acceptedSource.isEmpty() && recoveryHash != originalHash)
            fail("conflict", "The database changed while preparing recovery. Refresh before continuing.");
        if (!QFile::rename(pending, recoveryPath))
            fail("file_error", "The encrypted recovery snapshot could not be prepared. The vault was not changed.");
        try {
            if (!acceptedSource.isEmpty()) diskHash = acceptedSource;
            change();
            // Transfers certify a saved destination before deleting the source.
            if (autoSave || forceSave) persist(false, false);
            else checkpoint();
        } catch (...) {
            const auto failure = std::current_exception();
            recovery.setAutoRemove(false);
            db.reset(); hash.clear();
            QSharedPointer<Database> restored;
            bool reopened = false;
            try {
                restored = QSharedPointer<Database>::create();
                reopened = restored->open(recoveryPath, originalKey);
            } catch (...) {}
            if (!reopened) {
                const auto kept = keepRecoveryCopy(recoveryPath, recoveryHash);
                if (kept != recoveryPath) recovery.setAutoRemove(true);
                throw Failure{"recovery_error", "The save failed and the vault could not be reopened. An encrypted copy of the last verified state was kept at:\n\n"
                    + kept + "\n\nOpen it with the original vault credentials. Keep a permanent copy if this path is temporary.",
                    {{"recovery_path", kept}, {"retain_runtime", kept == recoveryPath}}};
            }
            restored->setFilePath(path);
            if (originalModified) restored->markAsModified(); else restored->markAsClean();
            db = std::move(restored); hash = originalHash; diskHash = originalDiskHash; modified = originalModified;
            recovery.setAutoRemove(true);
            try { std::rethrow_exception(failure); }
            catch (const Failure& error) {
                if (error.code == "save_error" || error.code == "file_error" || error.code == "read_only")
                    throw Failure{error.code, error.message + "\n\nThe last verified vault state is still open. You can save an encrypted copy."};
                throw;
            }
        }
        return snapshot();
    }
    QSharedPointer<const Database> borrowedDatabase() const {
        return db;
    }
    QJsonObject settings() const {
        const auto* meta = db->metadata();
        QJsonArray ciphers, kdfs;
        for (const auto& id : KeePass2::CIPHERS)
            ciphers.append(QJsonObject{{"id", uid(id)}, {"name", KeePass2::cipherToString(id)}});
        const auto allowed = db->formatVersion() < KeePass2::FILE_VERSION_4 ? KeePass2::KDBX3_KDFS : KeePass2::KDBX4_KDFS;
        for (const auto& id : allowed) {
            const auto defaults = KeePass2::uuidToKdf(id);
            const auto argon = qSharedPointerDynamicCast<Argon2Kdf>(defaults);
            QJsonObject parameters{{"rounds", defaults->rounds()}};
            if (argon) {
                parameters.insert("memory_kib", static_cast<double>(argon->memory()));
                parameters.insert("parallelism", static_cast<double>(argon->parallelism()));
            }
            kdfs.append(QJsonObject{{"id", uid(id)}, {"name", KeePass2::kdfToString(id)},
                                   {"supports_memory", bool(argon)}, {"defaults", parameters}});
        }
        QJsonObject result{{"name", meta->name()}, {"description", meta->description()},
            {"default_username", meta->defaultUserName()}, {"recycle_bin", meta->recycleBinEnabled()},
            {"history_items", meta->historyMaxItems()}, {"history_size", meta->historyMaxSize()},
            {"cipher", uid(db->cipher())}, {"kdf", uid(db->kdf()->uuid())},
            {"rounds", db->kdf()->rounds()}, {"compression", db->compressionAlgorithm() == Database::CompressionGZip},
            {"format", static_cast<int>(db->formatVersion())}, {"ciphers", ciphers}, {"kdfs", kdfs},
            {"password_key", !db->key()->getKey(PasswordKey::UUID).isNull()},
            {"file_key", !db->key()->getKey(FileKey::UUID).isNull()},
            {"hardware_key", !db->key()->challengeResponseKeys().isEmpty()}};
        const auto argon = qSharedPointerDynamicCast<Argon2Kdf>(db->kdf());
        if (argon) {
            result.insert("memory_kib", static_cast<double>(argon->memory()));
            result.insert("parallelism", static_cast<double>(argon->parallelism()));
        }
        return result;
    }
    QSharedPointer<Kdf> configuredKdf(const QJsonObject& args) const {
        auto kdf = db->kdf()->clone();
        if (args.contains("kdf")) {
            const QUuid id(text(args, "kdf"));
            const auto available = db->formatVersion() < KeePass2::FILE_VERSION_4 ? KeePass2::KDBX3_KDFS : KeePass2::KDBX4_KDFS;
            if (!available.contains(id)) fail("invalid_request", "This KDF is not supported by the current database format.");
            if (id != kdf->uuid()) kdf = KeePass2::uuidToKdf(id);
        }
        if (!kdf) fail("invalid_request", "The selected KDF is unavailable.");
        if (args.contains("rounds") && !kdf->setRounds(integer(args, "rounds", 1, 2147483647)))
            fail("invalid_request", "The KDF iteration count is invalid.");
        auto argon = qSharedPointerDynamicCast<Argon2Kdf>(kdf);
        if (args.contains("memory_kib") && (!argon || !argon->setMemory(integer(args, "memory_kib", 1, 4294967295LL))))
            fail("invalid_request", "The KDF memory setting is invalid.");
        if (args.contains("parallelism") && (!argon || !argon->setParallelism(integer(args, "parallelism", 1, 16777215))))
            fail("invalid_request", "The KDF parallelism setting is invalid.");
        return kdf;
    }
    void walk(const Group* g, int depth, QJsonArray& groups, QJsonArray& entries) const {
        groups.append(QJsonObject{{"uuid", uid(g->uuid())}, {"parent", g->parentGroup() ? uid(g->parentGroup()->uuid()) : QString()},
                     {"path", g->fullPath()}, {"name", g->name()}, {"depth", depth}, {"recycled", g->isRecycled()},
                     {"notes", g->notes()}, {"addressable", true}, {"icon", g->iconNumber()},
                     {"custom_icon", g->iconUuid().isNull() ? QString() : uid(g->iconUuid())},
                     {"tags", g->tags()}, {"searching", static_cast<int>(g->searchingEnabled())},
                     {"expires", g->timeInfo().expires()},
                     {"expiry", g->timeInfo().expiryTime().toString(Qt::ISODate)}, {"expired", g->isExpired()}});
        for (const auto* e : g->entries()) entries.append(summary(e));
        for (const auto* child : g->children()) walk(child, depth + 1, groups, entries);
    }
    QJsonObject snapshot() const {
        requireDatabase();
        QJsonArray groups, entries;
        walk(db->rootGroup(), 0, groups, entries);
        auto secretGroup = FdoSecrets::settings()->exposedGroup(db);
        const auto* exposed = secretGroup.isNull() ? nullptr : db->rootGroup()->findGroupByUuid(secretGroup);
        if (!exposed || exposed->isRecycled()) secretGroup = {};
        return {{"name", db->metadata()->name()}, {"recycle_bin_enabled", db->metadata()->recycleBinEnabled()},
                {"recycle_bin", db->metadata()->recycleBin() ? uid(db->metadata()->recycleBin()->uuid()) : QString()},
                {"modified", modified}, {"recovery_path", modified ? manualSnapshot : QString()},
                {"recovery_copy", recoveryLocation(path)},
                {"secret_group", secretGroup.isNull() ? QString() : uid(secretGroup)},
                {"groups", groups}, {"entries", entries}, {"root", uid(db->rootGroup()->uuid())},
                {"default_username", db->metadata()->defaultUserName()}};
    }
    void editEntry(Entry* e, const QJsonObject& args) {
        const auto values = args.value("fields");
        if (!values.isObject()) fail("invalid_request", "Entry fields must be an object.");
        const auto fields = values.toObject();
        const QStringList allowed{"Title", "UserName", "Password", "URL", "Notes"};
        for (auto it = fields.begin(); it != fields.end(); ++it)
            if (!allowed.contains(it.key()) || !it.value().isString())
                fail("invalid_request", "An entry field is invalid.");
        const auto expiry = args.contains("expiry") ? QDateTime::fromString(text(args, "expiry"), Qt::ISODate).toUTC() : QDateTime();
        if (args.contains("expiry") && !expiry.isValid()) fail("invalid_request", "Enter a valid expiry timestamp.");
        auto otp = QSharedPointer<Totp::Settings>();
        if (args.contains("totp") && !text(args, "totp").isEmpty()) {
            otp = Totp::parseSettings(text(args, "totp"));
            if (!otp || !Totp::checkValidSettings(otp).isEmpty()) fail("invalid_request", "Enter a valid TOTP URI.");
        }
        e->beginUpdate();
        decorate(e, args);
        for (auto it = fields.begin(); it != fields.end(); ++it) {
            if (it.key() == EntryAttributes::URLKey) e->setUrl(it.value().toString());
            else e->setDefaultAttribute(it.key(), it.value().toString());
        }
        if (args.contains("tags")) e->setTags(text(args, "tags"));
        if (args.contains("expires")) e->setExpires(boolean(args, "expires"));
        if (expiry.isValid()) e->setExpiryTime(expiry);
        if (args.contains("foreground")) e->setForegroundColor(color(args, "foreground"));
        if (args.contains("background")) e->setBackgroundColor(color(args, "background"));
        if (args.contains("override_url")) e->setOverrideUrl(text(args, "override_url"));
        if (args.contains("exclude_reports")) e->setExcludeFromReports(boolean(args, "exclude_reports"));
        e->endUpdate();
        // setTotp owns its own history update and cannot be nested inside beginUpdate.
        if (args.contains("totp")) e->setTotp(otp);
    }
    QString color(const QJsonObject& args, const char* key) const {
        const auto value = text(args, key);
        if (value.isEmpty()) return {};
        const QColor result(value);
        if (!result.isValid()) fail("invalid_request", "Choose a valid entry color or leave it empty for the default.");
        return result.name(result.alpha() == 255 ? QColor::HexRgb : QColor::HexArgb);
    }
    template <typename T> void decorate(T* item, const QJsonObject& args) {
        const int standard = args.contains("icon") ? integer(args, "icon", 0, 68) : item->iconNumber();
        if (args.contains("custom_icon")) {
            const auto value = text(args, "custom_icon");
            const QUuid id(value);
            if (!value.isEmpty()) {
                if (id.isNull() || !db->metadata()->hasCustomIcon(id)) fail("not_found", "The selected custom icon is no longer available.");
                item->setIcon(id);
            } else item->setIcon(standard);
        } else if (args.contains("icon")) item->setIcon(standard);
    }
    QByteArray iconPng(const QByteArray& bytes) const {
        if (bytes.size() > 8 * 1024 * 1024) fail("invalid_request", "The icon is too large to preview.");
        QBuffer input;
        input.setData(bytes); input.open(QIODevice::ReadOnly);
        QImageReader reader(&input);
        const auto format = reader.format().toLower();
        if (!QList<QByteArray>{"png", "jpeg", "jpg", "gif", "bmp", "ico", "webp"}.contains(format))
            fail("invalid_request", "Convert this image to PNG before importing it.");
        if (format == "ico" && reader.imageCount() > 1) {
            int best = -1, area = 0;
            for (int index = 0; index < reader.imageCount(); ++index) {
                if (!reader.jumpToImage(index)) continue;
                const auto size = reader.size();
                if (size.isValid() && size.width() <= 4096 && size.height() <= 4096 && size.width() * size.height() > area) {
                    best = index; area = size.width() * size.height();
                }
            }
            if (best < 0 || !reader.jumpToImage(best)) fail("invalid_request", "This icon has no supported image size.");
        }
        const auto size = reader.size();
        if (!size.isValid() || size.width() > 4096 || size.height() > 4096)
            fail("invalid_request", "Choose an image with dimensions of at most 4096 by 4096 pixels.");
        if (size.width() > 128 || size.height() > 128) reader.setScaledSize(size.scaled(128, 128, Qt::KeepAspectRatio));
        const auto image = reader.read();
        if (image.isNull()) fail("invalid_request", "The icon image could not be decoded.");
        QByteArray result;
        QBuffer output(&result); output.open(QIODevice::WriteOnly);
        if (!image.save(&output, "PNG")) fail("file_error", "The icon image could not be converted.");
        return result;
    }
    QJsonObject icons(const QJsonObject& args) const {
        QJsonArray standard, custom;
        const QDir directory(QCoreApplication::applicationDirPath() + "/../share/keepassxc/database-icons");
        const auto files = directory.entryList({"*.png"}, QDir::Files, QDir::Name);
        for (int index = 0; index < files.size(); ++index) {
            auto name = QFileInfo(files[index]).completeBaseName().mid(4).replace('_', ' ');
            standard.append(QJsonObject{{"icon", index}, {"name", name}});
        }
        const auto order = db->metadata()->customIconsOrder();
        const int offset = args.contains("offset") ? integer(args, "offset", 0, std::numeric_limits<int>::max()) : 0;
        const int limit = args.contains("limit") ? integer(args, "limit", 1, 200) : 100;
        for (int index = offset; index < order.size() && index - offset < limit; ++index) {
            const auto id = order[index];
            const auto& data = db->metadata()->customIcon(id);
            int uses = 0;
            for (const auto* entry : db->rootGroup()->entriesRecursive(true)) if (entry->iconUuid() == id) ++uses;
            for (const auto* group : db->rootGroup()->groupsRecursive(true)) if (group->iconUuid() == id) ++uses;
            custom.append(QJsonObject{{"custom_icon", uid(id)}, {"name", data.name}, {"uses", uses},
                {"modified", data.lastModified.toString(Qt::ISODate)}});
        }
        return {{"standard", standard}, {"custom", custom}, {"total", order.size()}, {"offset", offset}};
    }
    QSharedPointer<Database> importSource(const QJsonObject& args) const {
        const auto source = requestedPath(args, "source");
        const auto format = text(args, "source_format");
        QSharedPointer<Database> imported;
        bool valid = false;
        if (format == "csv") {
            CsvImport csv;
            if (!csv.load(source, csvOptions(args))) throw Failure{"import_error", csv.error()};
            imported = csv.build();
            if (!imported) throw Failure{"import_error", csv.error()};
            valid = true;
        } else if (format == "xml") {
            imported = QSharedPointer<Database>::create(); valid = imported->import(source);
        } else if (format == "keepass1") {
            KeePass1Reader reader;
            imported = reader.readDatabase(source, text(args, "source_password"), text(args, "source_keyfile")); valid = !reader.hasError();
        } else if (format == "bitwarden") {
            BitwardenReader reader; imported = reader.convert(source, text(args, "source_password")); valid = !reader.hasError();
        } else if (format == "1pux") {
            OPUXReader reader; imported = reader.convert(source); valid = !reader.hasError();
        } else if (format == "opvault") {
            OpVaultReader reader; QDir directory(source);
            imported = reader.convert(directory, text(args, "source_password")); valid = !reader.hasError();
        } else if (format == "protonpass") {
            ProtonPassReader reader; imported = reader.convert(source); valid = !reader.hasError();
        } else fail("invalid_request", "Choose a supported import format.");
        if (!valid || !imported) fail("import_error", "KeePassXC could not import this source. Check the export format and source credentials.");
        return imported;
    }
public:
    bool unlocked() const { return bool(db); }
    QJsonValue call(const QString& method, const QJsonObject& args) {
        if (method == "hello") return QJsonObject{{"protocol", 1}, {"upstream", KEEPASSXC_VERSION},
            {"engine", "keepassxc-core"}, {"capabilities", QJsonArray{"uuid", "entry-edit", "groups", "attributes", "totp", "history", "attachments", "search", "settings", "key-change", "merge", "export", "reports", "encrypted-copy", "import", "csv-import", "import-review", "generator-options", "generator-details", "browser-associations", "browser-lookup", "autotype", "keeshare", "entry-urls", "history-preview", "totp-live", "transaction-recovery", "configuration", "file-watch", "manual-save", "trash-review", "report-details", "hibp", "search-options", "favicon", "unused-icons", "browser-save-result", "favicon-entry", "browser-icon-reservation", "wordlist-library", "browser-options", "entry-actions", "browser-entry-list", "shortcut-codec", "configuration-reset", "ssh-key-generation", "attribute-suggestions", "proton-record-types"}}};
        if (method == "save.policy") { autoSave = boolean(args, "auto_save"); return db ? QJsonValue(snapshot()) : QJsonValue(true); }
        if (method == "recovery.list") return manualRecords(boolean(args, "all") ? QString() : requestedPath(args, "source"));
        if (method == "recovery.commit" || method == "recovery.discard" || method == "recovery.clone") {
            const auto manifest = requestedPath(args, "manifest"), source = requestedPath(args, "source");
            if (method == "recovery.commit") return QString::fromLatin1(commitManual(manifest, source).toHex());
            manualInfo(manifest, source);
            QLockFile owner(manifest + ".owner");
            if (!owner.tryLock()) fail("busy", "The vault owning this recovery copy is still open.");
            QLockFile lock(manifest + ".lock");
            if (!lock.tryLock()) fail("busy", "This encrypted recovery copy is in use.");
            const auto data = manualInfo(manifest, source);
            if (args.contains("expected_hash") && (text(args, "expected_hash") != data.value("snapshot_hash").toString()
                || QString::fromLatin1(digest(data.value("path").toString()).toHex()) != text(args, "expected_hash")))
                fail("conflict", "The recovery copy changed after it was opened. It was kept for review.");
            if (method == "recovery.clone") {
                const auto saved = data.value("path").toString();
                const auto fingerprint = QByteArray::fromHex(data.value("snapshot_hash").toString().toLatin1());
                if (digest(saved) != fingerprint) fail("file_error", "The encrypted recovery snapshot changed. It was kept for manual recovery.");
                const auto copy = keepRecoveryCopy(saved, fingerprint);
                if (copy == saved) fail("file_error", "An independent encrypted working copy could not be created.");
                return copy;
            }
            discardManual(data);
            return true;
        }
        if (method == "lock") { iconTools.clear(); reports.clear(); trash.clear(); launch.clear(); transfer.clear(); secrets.clear(); autotype.clear(); db.reset(); path.clear(); hash.clear(); diskHash.clear(); manualOwner.reset(); manualManifest.clear(); manualSnapshot.clear(); modified = false; return true; }
        if (method == "url.offer" || method == "url.accept" || method == "url.cancel") {
            try {
                if (method == "url.cancel") { launch.cancel(args); return true; }
                if (db) fail("invalid_request", "Close the recipient vault before opening a linked vault.");
                if (method == "url.offer") return launch.offer(args);
                const auto opened = launch.accept(args);
                if (!manualRecords(opened.path).isEmpty())
                    fail("unsaved_recovery", "Open this linked vault manually to review its unsaved recovery copy first.");
                db = opened.database; path = opened.path; hash = diskHash = opened.hash;
                launch.clear();
                return snapshot();
            } catch (const LaunchFailure& error) { throw Failure{error.code, error.message}; }
        }
        if (method.startsWith("secret.session.")) {
            try { return secretSessions.call(method, args); }
            catch (const SecretFailure& error) { throw Failure{error.code, error.message}; }
        }
        if (method == "quick.seal") {
            call("database.key.verify", args);
            const auto pin = text(args, "short_password");
            if (pin.size() < 4 || pin.size() > 128)
                fail("invalid_request", "Choose a short password with 4 to 128 characters.");
            const QJsonObject credentials{{"path", path}, {"password", text(args, "password")},
                {"keyfile", text(args, "keyfile")}, {"yubikey", text(args, "yubikey")},
                {"no_password", boolean(args, "no_password")}};
            const auto payload = QJsonDocument(credentials).toJson(QJsonDocument::Compact);
            if (payload.size() > 65536) fail("invalid_request", "The unlock credential is too large for quick unlock.");
            Database sealed;
            sealed.setKdf(KeePass2::uuidToKdf(KeePass2::KDF_ARGON2ID));
            auto key = QSharedPointer<CompositeKey>::create();
            key->addKey(QSharedPointer<PasswordKey>::create(pin));
            if (!sealed.setKey(key)) fail("key_error", "The quick-unlock key could not be created.");
            auto* credential = new Entry();
            credential->setUuid(QUuid::createUuid());
            credential->setGroup(sealed.rootGroup());
            credential->setPassword(QString::fromUtf8(payload));
            QByteArray bytes;
            QBuffer output(&bytes);
            output.open(QIODevice::WriteOnly);
            KeePass2Writer writer;
            if (!writer.writeDatabase(&output, &sealed)) fail("key_error", "The quick-unlock credential could not be encrypted.");
            return QString::fromLatin1(bytes.toBase64());
        }
        if (method == "quick.unlock") {
            const auto encoded = text(args, "blob").toLatin1();
            if (encoded.size() > 262144) fail("invalid_request", "The quick-unlock credential is invalid.");
            auto bytes = QByteArray::fromBase64(encoded);
            if (bytes.toBase64() != encoded) fail("invalid_request", "The quick-unlock credential is invalid.");
            auto key = QSharedPointer<CompositeKey>::create();
            key->addKey(QSharedPointer<PasswordKey>::create(text(args, "short_password")));
            Database sealed;
            QBuffer input(&bytes);
            input.open(QIODevice::ReadOnly);
            KeePass2Reader reader;
            if (!reader.readDatabase(&input, key, &sealed))
                fail("quick_password", "The short password is incorrect.");
            const auto entries = sealed.rootGroup()->entries();
            if (entries.size() != 1) fail("invalid_request", "The quick-unlock credential is invalid.");
            auto payload = QJsonDocument::fromJson(entries.first()->password().toUtf8()).object();
            if (text(payload, "path") != requestedPath(args))
                fail("invalid_request", "This quick-unlock credential belongs to another vault.");
            payload.insert("allow_recovery", boolean(args, "allow_recovery"));
            return call("open", payload);
        }
        if (method == "import.csv.inspect") {
            const auto source = requestedPath(args, "source");
            const auto before = importFingerprint(source, false);
            checkImportReview(args, before);
            CsvImport csv;
            if (!csv.load(source, csvOptions(args))) throw Failure{"import_error", csv.error()};
            const auto row = args.contains("row_start") ? integer(args, "row_start", 0, 2147483647) : -1;
            const auto column = args.contains("column_start") ? integer(args, "column_start", 0, 2147483647) : 0;
            auto result = csv.inspect(row, column, boolean(args, "reveal"));
            if (importFingerprint(source, false) != before) fail("conflict", "The CSV source changed while being read.");
            result.insert("source_fingerprint", QString::fromLatin1(before.toHex()));
            return result;
        }
        if (method == "import.inspect") {
            const auto source = requestedPath(args, "source");
            const bool directory = text(args, "source_format") == "opvault";
            const auto before = importFingerprint(source, directory);
            checkImportReview(args, before);
            const auto imported = importSource(args);
            if (importFingerprint(source, directory) != before) fail("conflict", "The import source changed while being read.");
            QJsonArray preview;
            const auto entries = imported->rootGroup()->entriesRecursive();
            const int start = args.contains("row_start") ? integer(args, "row_start", 0, 2147483647) : 0;
            for (const auto* entry : entries.mid(start, 200)) preview.append(QJsonObject{
                {"title", entry->title().left(1024)}, {"group", entry->group()->fullPath().left(1024)},
                {"username", entry->attributes()->isProtected(EntryAttributes::UserNameKey) ? QString() : entry->username().left(1024)}});
            return QJsonObject{{"entries", entries.size()}, {"groups", imported->rootGroup()->groupsRecursive(true).size()},
                {"preview", preview}, {"row_start", start}, {"source_fingerprint", QString::fromLatin1(before.toHex())}};
        }
        if (method == "import.create") {
            if (modified) fail("unsaved_changes", "Save or discard the open vault before importing another database.");
            const QFileInfo destination(requestedPath(args));
            if (destination.exists() || destination.isSymLink()) fail("file_error", "A file already exists at that location.");
            const auto source = requestedPath(args, "source");
            const auto format = text(args, "source_format");
            const auto before = importFingerprint(source, format == "opvault");
            checkImportReview(args, before);
            Engine imported;
            imported.db = importSource(args);
            if (importFingerprint(source, format == "opvault") != before)
                fail("conflict", "The import source changed while being read.");
            imported.path = destination.absoluteFilePath();
            imported.db->setFormatVersion(KeePass2::FILE_VERSION_4);
            imported.db->setKdf(KeePass2::uuidToKdf(KeePass2::KDF_ARGON2ID));
            if (!imported.db->setKey(makeKey(args)))
                fail("key_error", "KeePassXC could not set the imported database's unlock key.");
            if (imported.db->metadata()->name().isEmpty()) imported.db->metadata()->setName(destination.completeBaseName());
            imported.persist(true);
            db = std::move(imported.db); path = imported.path; hash = diskHash = imported.hash;
            return snapshot();
        }
        if (method == "open" || method == "create") {
            if (modified) fail("unsaved_changes", "Save or discard the open vault before opening another database.");
            db.reset(); hash.clear(); diskHash.clear();
            manualOwner.reset(); manualManifest.clear(); manualSnapshot.clear();
            QFile::remove(qEnvironmentVariable("KEYSLOT_ENGINE_CONFIG_DIRECTORY") + "/manual.json");
            const auto requested = text(args, "path");
            if (requested.isEmpty() || requested.contains(QChar('\0'))) fail("invalid_request", "Select a database path.");
            auto key = makeKey(args, method == "open");
            auto opened = QSharedPointer<Database>::create();
            QFileInfo info(requested);
            path = method == "open" ? info.canonicalFilePath() : info.absoluteFilePath();
            if (method == "open") {
                if (recoveryLocation(path) && QFileInfo(path).dir().dirName().startsWith("manual-"))
                    fail("invalid_request", "Open the source vault to review an independent recovery copy. Recovery checkpoints cannot be edited directly.");
                if (!boolean(args, "allow_recovery") && !manualRecords(path).isEmpty())
                    fail("unsaved_recovery", "An unsaved encrypted recovery copy is available. Open this vault in Keyslot to review it first.");
                const auto before = digest(path);
                if (!opened->open(path, key)) fail("key_error", "KeePassXC could not unlock the database. Check your credentials and hardware key.");
                if (digest(path) != before) fail("conflict", "The database changed while being unlocked.");
                hash = diskHash = before;
                db = std::move(opened);
            } else {
                if (info.exists()) fail("file_error", "A file already exists at that location.");
                opened->setFormatVersion(KeePass2::FILE_VERSION_4);
                opened->setKdf(KeePass2::uuidToKdf(KeePass2::KDF_ARGON2ID));
                if (!opened->setKey(key)) fail("key_error", "KeePassXC could not set the database key.");
                opened->metadata()->setName(text(args, "name", info.completeBaseName()));
                opened->rootGroup()->setName("Passwords");
                db = std::move(opened);
                try { persist(true); } catch (...) { db.reset(); throw; }
            }
            return snapshot();
        }
        if (method == "configuration.read" || method == "configuration.write") {
            if (db) throw Failure{"invalid_request", "Use a separate helper for application configuration."};
            try {
                return method == "configuration.read" ? KeyslotConfig::read(args) : KeyslotConfig::write(args);
            } catch (const KeyslotConfig::Failure& error) {
                throw Failure{error.code, error.message, error.details};
            }
        }
        if (method == "shortcuts.decode") {
            const auto values = args.value("values");
            if (!values.isArray() || values.toArray().size() > 256)
                fail("invalid_request", "Specify supported keyboard shortcuts.");
            QJsonArray result;
            for (const auto& value : values.toArray()) {
                if (!value.isString() || value.toString().size() > 1024 || value.toString().contains(QChar('\0')))
                    fail("invalid_request", "A keyboard shortcut is invalid.");
                const auto source = value.toString();
                auto sequence = QKeySequence::fromString(source, QKeySequence::NativeText);
                if (!source.isEmpty() && (sequence.isEmpty() || sequence[0] == Qt::Key_unknown))
                    sequence = QKeySequence::fromString(source, QKeySequence::PortableText);
                const int stroke = sequence.isEmpty() ? 0 : sequence[0];
                const int key = stroke & ~int(Qt::KeyboardModifierMask);
                result.append(QJsonObject{{"text", sequence.toString(QKeySequence::PortableText)},
                    {"key", key ? QKeySequence(key).toString(QKeySequence::PortableText) : QString()},
                    {"ctrl", bool(stroke & Qt::CTRL)}, {"shift", bool(stroke & Qt::SHIFT)},
                    {"alt", bool(stroke & Qt::ALT)}, {"super", bool(stroke & Qt::META)},
                    {"keypad", bool(stroke & Qt::KeypadModifier)},
                    {"unsupported", sequence.count() > 1 || (!source.isEmpty() && (!key || key == Qt::Key_unknown))
                        || bool(stroke & Qt::GroupSwitchModifier)}});
            }
            return result;
        }
        if (method == "generator.info") {
            QJsonArray lists;
            for (const auto& name : QDir(resources()->wordlistPath("")).entryList(QDir::Files)) lists.append(name);
            return QJsonObject{{"wordlists", lists}, {"default_wordlist", PassphraseGenerator::DefaultWordList}};
        }
        if (method == "generator.wordlist.inspect") {
            const auto path = text(args, "path");
            if (path.contains(QChar('\0')) || !QFileInfo(path).isAbsolute() || !QFileInfo(path).isFile())
                fail("file_error", "Choose a regular word-list file.");
            PassphraseGenerator generator;
            generator.setWordCount(1);
            generator.setWordList(path);
            if (generator.generatePassphrase().isEmpty())
                fail("file_error", "This file contains no usable passphrase words.");
            return QJsonObject{{"wordlist_valid", generator.isWordListValid()},
                               {"entropy", generator.estimateEntropy(1)}};
        }
        if (method == "password.health") {
            const auto value = text(args, "value");
            const PasswordHealth health(value);
            return QJsonObject{{"entropy", health.entropy()}, {"quality", static_cast<int>(health.quality())},
                               {"length", value.size()}};
        }
        if (method == "generate") {
            const bool passphrase = boolean(args, "passphrase");
            const int length = args.contains("length") ? integer(args, "length", 1, passphrase ? 100 : 999) : passphrase ? 6 : 24;
            const auto result = [&](const QString& value, double entropy = -1, bool wordlistValid = true) -> QJsonValue {
                if (!boolean(args, "details")) return value;
                const auto health = entropy < 0 ? PasswordHealth(value) : PasswordHealth(entropy);
                return QJsonObject{{"value", value}, {"entropy", health.entropy()},
                                   {"quality", static_cast<int>(health.quality())}, {"length", value.size()},
                                   {"wordlist_valid", wordlistValid}};
            };
            if (passphrase) {
                PassphraseGenerator generator;
                generator.setWordCount(length);
                const auto list = text(args, "wordlist", PassphraseGenerator::DefaultWordList);
                if (list.contains(QChar('\0'))) fail("invalid_request", "Choose a readable word list.");
                if (QFileInfo(list).isAbsolute()) {
                    if (!QFileInfo(list).isFile()) fail("file_error", "Choose a regular word-list file.");
                    generator.setWordList(list);
                } else {
                    if (!QDir(resources()->wordlistPath("")).entryList(QDir::Files).contains(list))
                        fail("invalid_request", "Choose an installed word list or an absolute custom word-list path.");
                    generator.setWordList(resources()->wordlistPath(list));
                }
                const auto wordCase = text(args, "word_case", "lowercase");
                const QMap<QString, PassphraseGenerator::PassphraseWordCase> cases{
                    {"lowercase", PassphraseGenerator::LOWERCASE}, {"uppercase", PassphraseGenerator::UPPERCASE},
                    {"titlecase", PassphraseGenerator::TITLECASE}, {"mixedcase", PassphraseGenerator::MIXEDCASE}};
                if (!cases.contains(wordCase)) fail("invalid_request", "Choose a supported word case.");
                generator.setWordCase(cases.value(wordCase));
                generator.setWordSeparator(text(args, "separator", PassphraseGenerator::DefaultSeparator));
                const auto value = generator.generatePassphrase();
                if (value.isEmpty()) fail("file_error", "Choose a readable word list containing at least one word.");
                return result(value, generator.estimateEntropy(), generator.isWordListValid());
            }
            PasswordGenerator generator;
            generator.setLength(length);
            PasswordGenerator::CharClasses classes;
            if (boolean(args, "lowercase", true)) classes |= PasswordGenerator::LowerLetters;
            if (boolean(args, "uppercase", true)) classes |= PasswordGenerator::UpperLetters;
            if (boolean(args, "numbers", true)) classes |= PasswordGenerator::Numbers;
            if (boolean(args, "symbols", true)) {
                if (boolean(args, "braces", true)) classes |= PasswordGenerator::Braces;
                if (boolean(args, "punctuation", true)) classes |= PasswordGenerator::Punctuation;
                if (boolean(args, "quotes", true)) classes |= PasswordGenerator::Quotes;
                if (boolean(args, "dashes", true)) classes |= PasswordGenerator::Dashes;
                if (boolean(args, "math", true)) classes |= PasswordGenerator::Math;
                if (boolean(args, "logograms", true)) classes |= PasswordGenerator::Logograms;
            }
            if (boolean(args, "extended_ascii")) classes |= PasswordGenerator::EASCII;
            generator.setCharClasses(classes);
            PasswordGenerator::GeneratorFlags flags;
            if (boolean(args, "every_group", true)) flags |= PasswordGenerator::CharFromEveryGroup;
            if (boolean(args, "exclude_lookalike")) flags |= PasswordGenerator::ExcludeLookAlike;
            generator.setFlags(flags);
            generator.setCustomCharacterSet(text(args, "additional"));
            generator.setExcludedCharacterSet(text(args, "excluded"));
            if (!generator.isValid()) fail("invalid_request", "The password generator settings are invalid.");
            const auto value = generator.generatePassword();
            return result(value);
        }
        if (method == "keyfile.generate") {
            const QFileInfo target(requestedPath(args));
            QTemporaryDir temporary(target.absolutePath() + "/.keyslot-key-XXXXXX");
            if (!temporary.isValid()) fail("file_error", "A key-file staging directory could not be created.");
            const auto stage = temporary.path() + "/keyfile";
            if (!FileKey::create(stage) || !QFile::setPermissions(stage, QFile::ReadOwner | QFile::WriteOwner))
                fail("file_error", "The key file could not be generated.");
            QFile file(stage);
            if (!file.open(QIODevice::ReadOnly) || ::fsync(file.handle()) != 0)
                fail("file_error", "The key file could not be synchronized to disk.");
            if (::link(QFile::encodeName(stage).constData(), QFile::encodeName(target.absoluteFilePath()).constData()) != 0)
                fail("file_error", "The key file could not be created. A file may already exist there.");
            return true;
        }
        if (method == "network.icon") {
            const auto url = QUrl(text(args, "url"));
            if (!url.isValid() || url.host().isEmpty()) fail("invalid_request", "The icon download address is invalid.");
            const auto result = KeyslotNetwork::get(url, 8 * 1024 * 1024, integer(args, "timeout", 1, 15000));
            return QJsonObject{{"data", QString::fromLatin1(result.bytes.toBase64())}, {"status", result.status},
                {"redirect", result.redirect.toString(QUrl::FullyEncoded)}, {"failed", !result.error.isEmpty()}};
        }
        requireDatabase();
        if (method.startsWith("entries.actions.")) {
            try {
                if (method == "entries.actions.cancel") { entryActions.cancel(text(args, "token")); return true; }
                unchanged();
                if (method == "entries.actions.info") return QJsonObject{{"tags", QJsonArray::fromStringList(db->tagList())}};
                if (method == "entries.actions.review") return entryActions.review(db, args, hash);
                if (method == "entries.actions.apply") {
                    const auto created = entryActions.apply(db, args, hash,
                        [this](const std::function<void()>& change) { transaction(change); });
                    return QJsonObject{{"created", created}, {"snapshot", snapshot()}};
                }
            } catch (const KeyslotEntryActions::Failure& error) { throw Failure{error.code, error.message}; }
            fail("unsupported", "This entry action is not supported.");
        }
        if (method.startsWith("icons.favicon.") || method.startsWith("icons.unused.")) {
            try {
                if (method == "icons.favicon.cancel" || method == "icons.unused.cancel") { iconTools.cancel(text(args, "token")); return true; }
                unchanged();
                if (method == "icons.unused.review") return iconTools.reviewUnused(db, args, hash);
                if (method == "icons.unused.remove") {
                    iconTools.removeUnused(db, args, hash, [this](const std::function<void()>& change) { transaction(change); });
                    return snapshot();
                }
                if (method == "icons.favicon.prepare") return iconTools.prepare(db, args, hash);
                if (method == "icons.favicon.step") return iconTools.step(db, args, hash);
                if (method == "icons.favicon.accept") return iconTools.accept(db, args, hash, [this](const QByteArray& raw) {
                    try { return iconPng(raw); } catch (const Failure&) { return QByteArray(); }
                });
                if (method == "icons.favicon.finish") {
                    const auto id = iconTools.finish(db, args, hash, [this](const std::function<void()>& change) { transaction(change); });
                    return QJsonObject{{"icon", id}, {"snapshot", snapshot()}};
                }
            } catch (const KeyslotIcons::Failure& error) { throw Failure{error.code, error.message}; }
            fail("unsupported", "This icon operation is not supported.");
        }
        if (method == "report.hibp.prepare" || method == "report.hibp.step" || method == "report.hibp.cancel"
            || method == "database.report.edit") {
            try {
                if (method == "report.hibp.cancel") { reports.cancel(text(args, "token")); return true; }
                unchanged();
                if (method == "report.hibp.prepare") return reports.prepare(db, args, hash);
                if (method == "report.hibp.step") return reports.step(db, args, hash);
                KeyslotReports::edit(db, args, hash, [this](const std::function<void()>& change) { transaction(change); });
                return snapshot();
            } catch (const KeyslotReports::Failure& error) { throw Failure{error.code, error.message}; }
        }
        if (method == "trash.review" || method == "trash.apply" || method == "trash.cancel") {
            try {
                if (method == "trash.cancel") { trash.cancel(text(args, "token")); return true; }
                unchanged();
                if (method == "trash.review") return trash.review(db, args, hash);
                trash.apply(db, args, hash, [this](const std::function<void()>& change) { transaction(change); });
                return snapshot();
            } catch (const KeyslotTrash::Failure& error) { throw Failure{error.code, error.message}; }
        }
        if (method == "url.prepare" || method == "url.finish" || method == "url.forget") {
            unchanged();
            try {
                if (method == "url.prepare") return launch.prepare(db, entry(args), args, hash);
                if (method == "url.forget") return transaction([&] { KeyslotLaunch::forget(entry(args)); });
                auto result = launch.finish(db, args, hash, [this](const std::function<void()>& change) { transaction(change); });
                result.insert("snapshot", snapshot());
                return result;
            } catch (const LaunchFailure& error) { throw Failure{error.code, error.message}; }
        }
        if (method == "database.watch") {
            const QFileInfo info(path);
            if (!info.exists() || !info.isFile() || !info.isReadable()) return QJsonObject{{"state", "unavailable"}};
            const auto observed = digest(path);
            if (observed == diskHash) return QJsonObject{{"state", "unchanged"}};
            if (modified) return QJsonObject{{"state", "conflict"}, {"revision", QString::fromLatin1(hash.toHex())},
                {"source_revision", QString::fromLatin1(observed.toHex())}};
            if (!boolean(args, "reload")) return QJsonObject{{"state", "changed"}};
            reload();
            return QJsonObject{{"state", "reloaded"}, {"snapshot", snapshot()}};
        }
        if (method == "output.inspect") {
            const QFileInfo requested(requestedPath(args));
            const auto parent = QDir(requested.absolutePath()).canonicalPath();
            if (parent.isEmpty()) fail("file_error", "Choose an existing destination folder.");
            const QFileInfo destination(parent + "/" + requested.fileName());
            if (recoveryLocation(destination.absoluteFilePath()))
                fail("invalid_request", "Choose a destination outside Keyslot’s private recovery storage.");
            if (destination.isSymLink() || (destination.exists() && !destination.isFile()))
                fail("file_error", "Choose a regular file, not a link or a folder.");
            return QJsonObject{{"path", destination.absoluteFilePath()}, {"exists", destination.exists()},
                {"hash", destination.exists() ? QString::fromLatin1(digest(destination.absoluteFilePath()).toHex()) : QString()},
                {"revision", QString::fromLatin1(hash.toHex())}};
        }
        if (method == "database.save_as") {
            if (text(args, "revision") != QString::fromLatin1(hash.toHex()))
                fail("conflict", "The working vault changed while choosing its destination. Save it again.");
            const QFileInfo requested(requestedPath(args));
            const auto parent = QDir(requested.absolutePath()).canonicalPath();
            if (parent.isEmpty()) fail("file_error", "The destination folder is unavailable.");
            const auto target = parent + "/" + requested.fileName();
            if (recoveryLocation(target)) fail("invalid_request", "Choose a destination outside Keyslot’s private recovery storage.");
            const auto expected = text(args, "expected_hash");
            const bool overwrite = boolean(args, "overwrite");
            if (overwrite && !QRegularExpression("^[a-f0-9]{64}$").match(expected).hasMatch())
                fail("invalid_request", "Review the existing destination before replacing it.");
            const auto verify = [&] {
                const QFileInfo current(target);
                if (current.isSymLink() || (current.exists() && !current.isFile()))
                    fail("conflict", "The destination changed into a link or a folder.");
                if (overwrite) {
                    if (!current.exists() || QString::fromLatin1(digest(target).toHex()) != expected)
                        fail("conflict", "The destination changed after review. Choose it again before replacing it.");
                    if (!current.isWritable()) fail("read_only", "The destination is read-only.");
                } else if (current.exists()) fail("file_error", "A file appeared at the destination. It was not replaced.");
            };
            verify();
            if (target == path) {
                transaction([] {}, true, QByteArray::fromHex(expected.toLatin1()));
                return QJsonObject{{"path", path}, {"snapshot", snapshot()}};
            }
            QTemporaryDir staging(parent + "/.keyslot-save-as-XXXXXX");
            if (!staging.isValid()) fail("file_error", "The destination could not be staged.");
            const auto stage = staging.path() + "/database.kdbx";
            writeState(stage);
            const auto saved = digest(stage);
            verify();
            if (overwrite) {
                copyToSaveFile(target, target + ".keyslot.bak", QFile::ReadOwner | QFile::WriteOwner, verify);
                copyToSaveFile(stage, target, QFileInfo(target).permissions(), verify);
            } else if (::link(QFile::encodeName(stage).constData(), QFile::encodeName(target).constData()) != 0)
                fail("file_error", "The destination could not be created. A file may already exist there.");
            const int directory = ::open(QFile::encodeName(parent).constData(), O_RDONLY | O_DIRECTORY);
            if (directory >= 0) { ::fsync(directory); ::close(directory); }
            clearManual();
            path = target; hash = diskHash = saved;
            db->setFilePath(path); db->markAsClean();
            return QJsonObject{{"path", path}, {"snapshot", snapshot()}};
        }
        if (method == "database.save") { if (modified) persist(); return snapshot(); }
        if (method == "refresh") { reload(); return snapshot(); }
        if (method == "database.reopen" || method == "database.reconcile") {
            if (args.contains("revision") && text(args, "revision") != QString::fromLatin1(hash.toHex()))
                fail("conflict", "The unsaved vault changed after review. Review it again before continuing.");
            const auto reviewed = text(args, "source_revision");
            if (!reviewed.isEmpty() && (reviewed.size() != 64 || QString::fromLatin1(digest(path).toHex()) != reviewed))
                fail("conflict", "The file changed again after review. Review the new changes before continuing.");
            if (boolean(args, "overwrite")) {
                if (reviewed.isEmpty() || !args.contains("revision")) fail("invalid_request", "Review both versions before overwriting disk changes.");
                return transaction([] {}, true, QByteArray::fromHex(reviewed.toLatin1()));
            }
            const auto key = boolean(args, "same_credentials") ? db->key() : QSharedPointer<const CompositeKey>(makeKey(args, true));
            if (!boolean(args, "merge")) { reload(key, boolean(args, "discard")); return snapshot(); }
            auto replacement = QSharedPointer<Database>::create();
            const auto before = digest(path);
            if (!replacement->open(path, key)) fail("key_error", "The changed vault requires its current credential before merging.");
            if (digest(path) != before) fail("conflict", "The changed vault changed again while being opened.");
            return transaction([&] {
                Merger merger(db.data(), replacement.data());
                merger.merge();
                if (digest(path) != before) fail("conflict", "The vault changed again during the merge.");
                db = replacement;
            }, false, before);
        }
        if (method == "database.key.verify") {
            unchanged();
            Database candidate;
            if (!candidate.open(modified ? manualSnapshot : path, makeKey(args, true)))
                fail("key_error", "The vault credential could not be verified. Check the password and key file.");
            unchanged();
            return true;
        }
        // Reads and recovery copies use the open state; transactions still verify the file before writing.
        if (method == "snapshot") return snapshot();
        if (method == "database.settings") return settings();
        if (method.startsWith("transfer.")) {
            try {
                if (method == "transfer.cancel") { transfer.cancel(args); return true; }
                unchanged();
                if (method == "transfer.prepare") return transfer.prepare(db, args, hash);
                if (method == "transfer.listen") return transfer.listen(db, args, hash);
                if (method == "transfer.send") return transfer.send(db, args, hash);
                QJsonObject result;
                const auto commit = [this](const std::function<void()>& change) { transaction(change, true); };
                if (method == "transfer.receive") result = transfer.receive(db, args, hash, commit);
                else if (method == "transfer.finish") result = transfer.finish(db, args, hash, commit);
                else if (method == "transfer.local") result = transfer.local(db, args, hash, commit);
                else fail("unknown_method", "This entry transfer operation is unavailable.");
                result.insert("snapshot", snapshot());
                return result;
            } catch (const TransferFailure& error) { throw Failure{error.code, error.message}; }
        }
        if (method == "icons.list") return icons(args);
        if (method == "icons.get" || method == "icons.export") {
            QByteArray bytes;
            const auto custom = text(args, "custom_icon");
            if (!custom.isEmpty()) {
                const QUuid id(custom);
                if (id.isNull() || !db->metadata()->hasCustomIcon(id)) fail("not_found", "This custom icon is unavailable.");
                bytes = db->metadata()->customIcon(id).data;
            } else {
                const int index = integer(args, "icon", 0, 68);
                const QDir directory(QCoreApplication::applicationDirPath() + "/../share/keepassxc/database-icons");
                const auto files = directory.entryList({"*.png"}, QDir::Files, QDir::Name);
                if (index >= files.size()) fail("not_found", "The standard icon assets are unavailable.");
                QFile image(directory.filePath(files[index]));
                if (!image.open(QIODevice::ReadOnly)) fail("file_error", "The standard icon could not be read.");
                bytes = image.readAll();
            }
            if (method == "icons.export") {
                // Preserve the original custom image bytes, including formats from existing vaults.
                QSaveFile file(requestedPath(args)); file.setDirectWriteFallback(false);
                if (!file.open(QIODevice::WriteOnly) || !file.setPermissions(QFile::ReadOwner | QFile::WriteOwner)
                    || file.write(bytes) != bytes.size() || !file.commit()) fail("file_error", "The icon could not be exported.");
                return true;
            }
            return QString::fromLatin1(iconPng(bytes).toBase64());
        }
        if (method == "icons.import") {
            const auto value = text(args, "data").toLatin1();
            if (value.size() > 12 * 1024 * 1024) fail("invalid_request", "The icon is too large.");
            const auto raw = QByteArray::fromBase64(value, QByteArray::AbortOnBase64DecodingErrors);
            if (raw.toBase64() != value) fail("invalid_request", "The icon encoding is invalid.");
            const auto png = iconPng(raw);
            auto id = db->metadata()->findCustomIcon(png);
            if (id.isNull()) {
                id = QUuid::createUuid();
                const auto name = text(args, "name").left(1024);
                transaction([&] { db->metadata()->addCustomIcon(id, png, name, Clock::currentDateTimeUtc()); });
            }
            return QJsonObject{{"icon", uid(id)}, {"snapshot", snapshot()}};
        }
        if (method == "icons.remove") {
            const QUuid id(text(args, "custom_icon"));
            if (id.isNull() || !db->metadata()->hasCustomIcon(id)) fail("not_found", "This custom icon is unavailable.");
            return transaction([&] {
                for (auto* e : db->rootGroup()->entriesRecursive(true)) if (e->iconUuid() == id) {
                    if (e->group()) { e->beginUpdate(); e->setIcon(Entry::DefaultIconNumber); e->endUpdate(); }
                    else { e->setUpdateTimeinfo(false); e->setIcon(0); e->setUpdateTimeinfo(true); }
                }
                for (auto* g : db->rootGroup()->groupsRecursive(true)) if (g->iconUuid() == id) g->setIcon(Group::DefaultIconNumber);
                for (auto* e : db->rootGroup()->entriesRecursive(true)) if (!e->group() && e->iconUuid() == id) {
                    e->setUpdateTimeinfo(false); e->setIcon(0); e->setUpdateTimeinfo(true);
                }
                db->metadata()->removeCustomIcon(id);
            });
        }
        if (method.startsWith("secret.")) {
            try {
                if (method == "secret.settings") return secrets.settings(db);
                if (method == "secret.settings.save")
                    return transaction([&] { secrets.saveSettings(db, args); });
                if (method == "secret.configure") { secrets.configure(args); return true; }
                if (method == "secret.drop-peer") { secrets.dropPeer(text(args, "peer")); return true; }
                // Public clients must not read a stale copy after another app revokes exposure.
                unchanged();
                if (method == "secret.info") return secrets.info(db, args);
                if (method == "secret.search") return secrets.search(db, args);
                if (method == "secret.get") return secrets.get(db, args);
                if (method == "secret.prepare") return secrets.prepare(db, args, hash);
                if (method == "secret.finish") {
                    auto result = secrets.finish(db, args, hash, [this](const std::function<void()>& change) { transaction(change); });
                    result.insert("snapshot", snapshot());
                    return result;
                }
                if (method == "secret.mutate") {
                    auto result = secrets.mutate(db, args, [this](const std::function<void()>& change) { transaction(change); });
                    result.insert("snapshot", snapshot());
                    return result;
                }
            } catch (const SecretFailure& error) { throw Failure{error.code, error.message}; }
        }
        if (method.startsWith("keeshare.")) {
            try {
                if (method == "keeshare.configure") { keeshare.configure(args); return true; }
                if (method == "keeshare.sync") {
                    unchanged();
                    auto result = keeshare.sync(db, hash, [this](const std::function<void()>& change) { transaction(change); },
                        [this] { unchanged(); return hash; }, boolean(args, "force"));
                    result.insert("snapshot", snapshot());
                    return result;
                }
                auto* target = group(text(args, "group"));
                if (method == "keeshare.settings") return keeshare.settings(target);
                if (method == "keeshare.settings.save")
                    return transaction([&] { keeshare.saveSettings(target, args); });
            } catch (const KeeShareFailure& error) { throw Failure{error.code, error.message}; }
        }
        if (method.startsWith("autotype.")) {
            try {
                if (method == "autotype.targets") return autotype.targets();
                if (method == "autotype.matches") return autotype.matches(db, args);
                if (method == "autotype.finish") { unchanged(); return autotype.finish(db, args, hash); }
                if (method == "autotype.group.settings") return autotype.settings(group(text(args, "group")));
                if (method == "autotype.group.save") {
                    auto* target = group(text(args, "group"));
                    return transaction([&] { autotype.saveSettings(target, args); });
                }
                auto* item = entry(args);
                if (method == "autotype.settings") return autotype.settings(item);
                if (method == "autotype.settings.save")
                    return transaction([&] { autotype.saveSettings(item, args); });
                if (method == "autotype.prepare") { unchanged(); return autotype.prepare(db, item, args, hash); }
            } catch (const AutoTypeFailure& error) { throw Failure{error.code, error.message}; }
        }
        if (method.startsWith("ssh.")) {
            try {
                if (method == "ssh.generate.cancel") { ssh.cancelGenerated(text(args, "token")); return true; }
                if (method == "ssh.configure") { ssh.configure(args); return true; }
                if (method == "ssh.owned") return ssh.owned();
                if (method == "ssh.remove") return ssh.remove(args);
                if (method == "ssh.agent.list") return ssh.agentKeys();
                if (method == "ssh.removal.prepare") { unchanged(); return ssh.reviewRemoval(db, args, hash); }
                if (method == "ssh.removal.finish") { unchanged(); return ssh.finishRemoval(db, args, hash); }
                if (method == "ssh.add") { unchanged(); return ssh.add(db, args, hash); }
                auto* item = entry(args);
                if (method == "ssh.generate.info") return ssh.generationInfo(item);
                if (method == "ssh.generate.prepare") { unchanged(); return ssh.generate(db, item, args, hash); }
                if (method == "ssh.generate.save") {
                    unchanged();
                    return transaction([&] { ssh.saveGenerated(db, item, args, hash); });
                }
                if (method == "ssh.settings") return ssh.settings(item);
                if (method == "ssh.key_info") return ssh.keyInfo(item, boolean(args, "decrypt"));
                if (method == "ssh.prepare") { unchanged(); return ssh.prepare(db, item, hash); }
                if (method == "ssh.settings.save") {
                    auto result = transaction([&] { ssh.saveSettings(item, args); });
                    try { ssh.updatePolicy(item); }
                    catch (const SSHFailure& error) { result.insert("ssh_warning", error.message); }
                    return result;
                }
            } catch (const SSHFailure& error) { throw Failure{error.code, error.message}; }
        }
        if (method.startsWith("passkey.")) {
            try {
                if (method == "passkey.inspect") return browser.inspectPasskeyImport(args);
                if (method == "passkey.import") {
                    browser.importPasskey(db, args, [this](const std::function<void()>& change) { transaction(change); });
                    return snapshot();
                }
                auto* item = entry(args);
                if (!item->hasPasskey()) fail("not_found", "This entry has no passkey.");
                if (method == "passkey.info") return browser.passkeyInfo(item);
                if (method == "passkey.export") {
                    if (QFileInfo(requestedPath(args)).absoluteFilePath() == QFileInfo(path).absoluteFilePath())
                        fail("invalid_request", "An unencrypted passkey cannot replace the database.");
                    browser.exportPasskey(item, args);
                    return true;
                }
                if (method == "passkey.remove") {
                    if (item->isRecycled()) fail("denied", "Restore this entry before removing its passkey.");
                    return transaction([&] { item->beginUpdate(); item->removePasskey(); item->endUpdate(); });
                }
            } catch (const BrowserFailure& error) { throw Failure{error.code, error.message}; }
        }
        if (method.startsWith("browser.")) {
            // Browser authorization must not use a stale copy after another client revokes access.
            unchanged();
            try {
                if (method == "browser.options") return browser.options(db, args, hash);
                if (method == "browser.options.save") {
                    browser.saveOptions(db, args, hash, [this](const std::function<void()>& change) { transaction(change); });
                    return snapshot();
                }
                if (method == "browser.lookup") return browser.lookup(db, args, hash);
                if (method == "browser.passkey.prepare") return browser.preparePasskey(db, args, hash);
                if (method == "browser.passkey.finish") return browser.finishPasskey(db, args, hash,
                    [this](const std::function<void()>& change) { transaction(change); });
                if (method == "browser.prepare_delete") return browser.prepareDelete(db, args, hash);
                if (method == "browser.delete") return browser.remove(db, args, hash,
                    [this](const std::function<void()>& change) { transaction(change); });
                if (method == "browser.totp") return browser.totp(db, args);
                if (method == "browser.groups") return browser.databaseGroups(db, args);
                if (method == "browser.entries") return browser.databaseEntries(db, args);
                if (method == "browser.prepare_group") return browser.prepareGroup(db, args, hash);
                if (method == "browser.create_group") return browser.createGroup(db, args, hash,
                    [this](const std::function<void()>& change) { transaction(change); });
                if (method == "browser.release") return browser.release(db, args, hash,
                    [this](const std::function<void()>& change) { transaction(change); });
                if (method == "browser.prepare_save") return browser.prepareSave(db, args, hash);
                if (method == "browser.save") return browser.save(db, args, hash,
                    [this](const std::function<void()>& change) { transaction(change); });
                if (method == "browser.save.details") {
                    QString entry;
                    const bool changed = browser.save(db, args, hash,
                        [this](const std::function<void()>& change) { transaction(change); }, &entry);
                    QString reservation;
                    if (changed) {
                        try { reservation = iconTools.reserve(db, entry); } catch (const KeyslotIcons::Failure&) {}
                    }
                    return QJsonObject{{"changed", changed}, {"entry", entry}, {"icon_request", reservation}};
                }
            } catch (const BrowserFailure& error) { throw Failure{error.code, error.message}; }
            auto* data = db->metadata()->customData();
            const auto root = db->rootGroup()->uuidToHex();
            const auto databaseHash = QString::fromLatin1(QCryptographicHash::hash(root.toUtf8(), QCryptographicHash::Sha256).toHex());
            if (method == "browser.info") {
                const auto* bin = db->metadata()->recycleBin();
                const auto legacy = root + (bin ? bin->uuidToHex() : QString());
                return QJsonObject{{"hash", databaseHash}, {"legacy_hash", QString::fromLatin1(
                    QCryptographicHash::hash(legacy.toUtf8(), QCryptographicHash::Sha256).toHex())},
                    {"name", db->metadata()->name()}};
            }
            if (method == "browser.associations") {
                QJsonArray connections;
                for (const auto& key : data->keys()) {
                    if (!key.startsWith(CustomData::BrowserKeyPrefix)) continue;
                    const auto id = key.mid(CustomData::BrowserKeyPrefix.size());
                    connections.append(QJsonObject{{"id", id}, {"created", data->value(CustomData::Created + id)}});
                }
                return connections;
            }
            const auto id = text(args, "id");
            if (id.isEmpty() || id.size() > 1024 || id.contains(QChar('\0')))
                fail("invalid_request", "Choose a nonempty browser connection name.");
            const auto name = CustomData::BrowserKeyPrefix + id;
            if (method == "browser.revoke") {
                if (!data->contains(name)) fail("not_found", "The browser connection no longer exists.");
                return transaction([&] { data->remove(name); data->remove(CustomData::Created + id); });
            }
            const auto key = text(args, "key");
            const auto decoded = QByteArray::fromBase64(key.toLatin1());
            if (decoded.size() != 32 || QString::fromLatin1(decoded.toBase64()) != key)
                fail("invalid_request", "The browser identification key is invalid.");
            if (method == "browser.authenticate")
                return QJsonObject{{"authenticated", data->contains(name) && data->value(name) == key}, {"hash", databaseHash}};
            if (method == "browser.associate") {
                if (data->contains(name) && !boolean(args, "replace"))
                    fail("already_exists", "That browser connection name is already in use.");
                return transaction([&] {
                    data->set(name, key);
                    data->set(CustomData::Created + id, QLocale::system().toString(Clock::currentDateTime(), QLocale::ShortFormat));
                });
            }
            fail("invalid_request", "Unknown browser operation.");
        }
        if (method == "database.kdf.benchmark") {
            const QStringList allowed{"kdf", "memory_kib", "parallelism", "milliseconds"};
            for (auto it = args.begin(); it != args.end(); ++it)
                if (!allowed.contains(it.key())) fail("invalid_request", "An unknown KDF benchmark option was supplied.");
            const auto milliseconds = integer(args, "milliseconds", Kdf::MIN_ENCRYPTION_TIME, Kdf::MAX_ENCRYPTION_TIME);
            const auto kdf = configuredKdf(args);
            const int rounds = kdf->benchmark(milliseconds);
            if (rounds < 1) fail("key_error", "KeePassXC could not calibrate these KDF settings.");
            return QJsonObject{{"rounds", rounds}};
        }
        if (method == "database.settings.save") {
            const QStringList allowed{"name", "description", "default_username", "recycle_bin", "history_items",
                                      "history_size", "cipher", "kdf", "rounds", "memory_kib", "parallelism", "compression"};
            for (auto it = args.begin(); it != args.end(); ++it)
                if (!allowed.contains(it.key())) fail("invalid_request", "An unknown database setting was supplied.");
            auto kdf = configuredKdf(args);
            const QUuid cipher = args.contains("cipher") ? QUuid(text(args, "cipher")) : db->cipher();
            if (!KeePass2::CIPHERS.contains(cipher)) fail("invalid_request", "The selected cipher is unavailable.");
            if (args.contains("history_items")) integer(args, "history_items", -1, 2147483647);
            if (args.contains("history_size")) integer(args, "history_size", -1, 2147483647);
            for (const auto* name : {"name", "description", "default_username"}) if (args.contains(name)) text(args, name);
            for (const auto* name : {"recycle_bin", "compression"}) if (args.contains(name)) boolean(args, name);
            const bool changeKdf = args.contains("kdf") || args.contains("rounds") || args.contains("memory_kib") || args.contains("parallelism");
            const bool truncate = (args.contains("history_items") && args.value("history_items").toInt() != db->metadata()->historyMaxItems())
                || (args.contains("history_size") && args.value("history_size").toInt() != db->metadata()->historyMaxSize());
            return transaction([&] {
                auto* meta = db->metadata();
                if (args.contains("name")) meta->setName(text(args, "name"));
                if (args.contains("description")) meta->setDescription(text(args, "description"));
                if (args.contains("default_username")) meta->setDefaultUserName(text(args, "default_username"));
                if (args.contains("recycle_bin")) meta->setRecycleBinEnabled(boolean(args, "recycle_bin"));
                if (args.contains("history_items")) meta->setHistoryMaxItems(args.value("history_items").toInt());
                if (args.contains("history_size")) meta->setHistoryMaxSize(args.value("history_size").toInt());
                if (truncate) for (auto* e : db->rootGroup()->entriesRecursive()) e->truncateHistory();
                if (args.contains("compression")) db->setCompressionAlgorithm(boolean(args, "compression") ? Database::CompressionGZip : Database::CompressionNone);
                db->setCipher(cipher);
                if (changeKdf && !db->changeKdf(kdf)) fail("key_error", "KeePassXC could not apply the KDF settings.");
            });
        }
        if (method == "database.key.change") {
            const QStringList allowed{"password", "keyfile", "yubikey", "remove_password", "remove_keyfile", "remove_hardware"};
            for (auto it = args.begin(); it != args.end(); ++it)
                if (!allowed.contains(it.key())) fail("invalid_request", "An unknown unlock-key option was supplied.");
            for (const auto* name : {"remove_password", "remove_keyfile", "remove_hardware"})
                if (args.contains(name)) boolean(args, name);
            if (args.contains("password") && boolean(args, "remove_password")) fail("invalid_request", "Choose replacement or removal of the password.");
            if (args.contains("keyfile") && boolean(args, "remove_keyfile")) fail("invalid_request", "Choose replacement or removal of the key file.");
            if (args.contains("yubikey") && boolean(args, "remove_hardware")) fail("invalid_request", "Choose replacement or removal of the hardware key.");
            auto parts = args;
            parts.insert("no_password", !args.contains("password"));
            auto key = makeKey(parts, true);
            for (const auto& current : db->key()->keys()) {
                if (current->uuid() == PasswordKey::UUID && (args.contains("password") || boolean(args, "remove_password"))) continue;
                if (current->uuid() == FileKey::UUID && (args.contains("keyfile") || boolean(args, "remove_keyfile"))) continue;
                key->addKey(current);
            }
            if (!args.contains("yubikey") && !boolean(args, "remove_hardware"))
                for (const auto& current : db->key()->challengeResponseKeys()) key->addChallengeResponseKey(current);
            if (key->isEmpty()) fail("key_error", "At least one unlock component must remain.");
            return transaction([&] {
                if (!db->setKey(key)) fail("key_error", "KeePassXC could not change the database key.");
            });
        }
        if (method == "database.merge") {
            const auto sourcePath = QFileInfo(requestedPath(args)).canonicalFilePath();
            if (sourcePath.isEmpty() || sourcePath == path) fail("invalid_request", "Choose another database to merge.");
            const auto before = digest(sourcePath);
            auto source = std::make_unique<Database>();
            const auto key = boolean(args, "same_credentials") ? db->key() : QSharedPointer<const CompositeKey>(makeKey(args));
            if (!source->open(sourcePath, key)) fail("key_error", "The merge database could not be unlocked.");
            if (digest(sourcePath) != before) fail("conflict", "The merge source changed while being read.");
            Merger preview(source.get(), db.data());
            if (preview.merge(true).isEmpty()) return snapshot();
            return transaction([&] {
                Merger merger(source.get(), db.data());
                merger.merge();
                if (digest(sourcePath) != before) fail("conflict", "The merge source changed during the operation.");
            });
        }
        if (method == "database.copy") {
            const QFileInfo destination(requestedPath(args));
            if (destination.absoluteFilePath() == path || destination.canonicalFilePath() == path)
                fail("invalid_request", "Choose a different destination for the database copy.");
            QFile output(destination.absoluteFilePath());
            if (!output.open(QIODevice::WriteOnly | QIODevice::NewOnly)
                || !output.setPermissions(QFile::ReadOwner | QFile::WriteOwner))
                fail("file_error", "The encrypted database copy could not be created.");
            // Serialize the open database without requiring the original file to remain available.
            KeePass2Writer writer;
            if (!writer.writeDatabase(&output, db.data()) || !output.flush() || ::fsync(output.handle()) != 0)
                fail("save_error", "The encrypted database copy could not be written completely.");
            return true;
        }
        if (method == "database.export") {
            const auto format = text(args, "format");
            const QFileInfo destination(requestedPath(args));
            if (destination.absoluteFilePath() == path || destination.canonicalFilePath() == path)
                fail("invalid_request", "An unencrypted export cannot replace the database.");
            QTemporaryDir temporary(destination.absolutePath() + "/.keyslot-export-XXXXXX");
            if (!temporary.isValid()) fail("file_error", "The export staging directory could not be created.");
            const auto stage = temporary.path() + "/export";
            QFile output(stage);
            if (!output.open(QIODevice::WriteOnly | QIODevice::NewOnly) || !output.setPermissions(QFile::ReadOwner | QFile::WriteOwner))
                fail("file_error", "The export file could not be created.");
            bool ok = false;
            if (format == "xml") {
                QByteArray xml;
                ok = db->extract(xml) && output.write(xml) == xml.size();
                xml.fill('\0');
            } else if (format == "csv") {
                CsvExporter exporter;
                ok = exporter.exportDatabase(&output, borrowedDatabase());
            } else if (format == "html") {
                HtmlExporter exporter;
                ok = exporter.exportDatabase(&output, borrowedDatabase());
            } else fail("invalid_request", "Choose XML, CSV, or HTML export.");
            if (!ok || !output.flush() || ::fsync(output.handle()) != 0)
                fail("file_error", "The export could not be written completely.");
            output.close();
            if (boolean(args, "overwrite"))
                copyToSaveFile(stage, destination.absoluteFilePath(), QFile::ReadOwner | QFile::WriteOwner);
            else if (::link(QFile::encodeName(stage).constData(), QFile::encodeName(destination.absoluteFilePath()).constData()) != 0)
                fail("file_error", "The export destination already exists or cannot be written.");
            return true;
        }
        if (method == "database.report") return KeyslotReports::inventory(db, boolean(args, "excluded"), hash);
        if (method == "search") {
            auto* base = args.contains("group") ? group(text(args, "group")) : db->rootGroup();
            if (args.contains("group")) {
                int matches = 0;
                for (const auto* item : db->rootGroup()->groupsRecursive(true)) if (item->uuid() == base->uuid()) ++matches;
                if (matches != 1) fail("invalid_request", "Choose a group with an unambiguous identifier.");
            }
            const bool recursive = boolean(args, "recursive", true), recycled = boolean(args, "recycled");
            const bool force = boolean(args, "force");
            QList<Entry*> candidates;
            const auto groups = recursive ? base->groupsRecursive(true) : QList<Group*>{base};
            for (const auto* item : groups) {
                if (item->isRecycled() ? !recycled : (!force && !item->resolveSearchingEnabled())) continue;
                for (auto* entry : item->entries()) if (recycled || !entry->isRecycled()) candidates.append(entry);
            }
            EntrySearcher searcher(boolean(args, "case_sensitive"), !boolean(args, "protected"));
            QJsonArray result;
            for (const auto* e : searcher.searchEntries(text(args, "query"), candidates)) result.append(uid(e->uuid()));
            return result;
        }
        if (method == "attribute") {
            auto* e = entry(args);
            if (boolean(args, "totp")) {
                bool valid = false;
                const auto value = e->totp(&valid);
                if (!valid) fail("invalid_request", "This entry has no valid TOTP settings.");
                return value;
            }
            const auto name = text(args, "name", "Password");
            if (!e->attributes()->hasKey(name)) fail("not_found", "This attribute does not exist.");
            return boolean(args, "resolve", true) ? e->resolveMultiplePlaceholders(e->attribute(name)) : e->attribute(name);
        }
        if (method == "attribute.suggestions") {
            auto* current = entry(args);
            const auto query = text(args, "query");
            if (query.size() > 1024) fail("invalid_request", "Use a shorter attribute-name search.");
            const int offset = integer(args, "offset", 0, std::numeric_limits<int>::max());
            QSet<QString> names;
            int omitted = 0;
            for (const auto* item : db->rootGroup()->entriesRecursive()) {
                if (item->isRecycled()) continue;
                for (const auto& name : item->attributes()->customKeys()) {
                    if (current->attributes()->hasKey(name) || EntryAttributes::isPasskeyAttribute(name)
                        || !name.contains(query, Qt::CaseInsensitive)) continue;
                    if (name.size() > 1024 || name.contains(QChar('\0'))) { ++omitted; continue; }
                    names.insert(name);
                }
            }
            auto sorted = names.values();
            QCollator collator; collator.setNumericMode(true); collator.setCaseSensitivity(Qt::CaseInsensitive);
            std::sort(sorted.begin(), sorted.end(), [&](const QString& left, const QString& right) {
                const auto compared = collator.compare(left, right);
                return compared ? compared < 0 : left < right;
            });
            QJsonArray page;
            const auto count = std::min(100, std::max(0, sorted.size() - offset));
            for (int i = 0; i < count; ++i) page.append(sorted[offset + i]);
            return QJsonObject{{"names", page}, {"total", sorted.size()}, {"offset", offset}, {"omitted", omitted}};
        }
        if (method == "attribute.info") {
            auto* e = entry(args);
            const auto name = text(args, "name");
            if (!e->attributes()->hasKey(name)) fail("not_found", "This attribute does not exist.");
            QJsonObject result{{"value", e->attribute(name)}, {"protected", e->attributes()->isProtected(name)}};
            if (boolean(args, "review")) {
                unchanged();
                result.insert("revision", QString::fromLatin1(hash.toHex()));
            }
            return result;
        }
        if (method == "totp.sample" || method == "totp.copy") {
            auto* e = entry(args);
            try {
                const auto sample = KeyslotTotp::sample(e, method == "totp.sample" ? args : QJsonObject());
                if (method == "totp.sample") return sample;
                const auto code = sample.value("code").toString();
                return boolean(args, "combined") ? e->resolveMultiplePlaceholders(e->password()) + code : code;
            } catch (const KeyslotTotp::Failure& error) { throw Failure{error.code, error.message}; }
        }
        if (method == "totp.settings" || method == "totp.config" || method == "totp.save"
            || method == "totp.remove" || method == "totp.qr") {
            auto* e = entry(args);
            unchanged();
            const auto revision = QString::fromLatin1(hash.toHex());
            if ((method == "totp.save" || method == "totp.remove" || args.contains("revision"))
                && text(args, "revision") != revision)
                fail("conflict", "The database changed since setup was opened. Open it again before continuing.");
            try {
                if (method == "totp.settings") return e->hasTotp() ? Totp::writeSettings(e->totpSettings(), e->title(), e->username(), true) : QString();
                if (method == "totp.config") {
                    auto data = KeyslotTotp::config(e); data.insert("revision", revision); return data;
                }
                if (method == "totp.qr") {
                    const auto bytes = KeyslotTotp::qr(e, !args.contains("path"));
                    if (!args.contains("path")) return QJsonObject{{"png", QString::fromLatin1(bytes.toBase64())},
                        {"custom", Totp::hasCustomSettings(e->totpSettings()) || !e->totpSettings()->encoder.shortName.isEmpty()}, {"revision", revision}};
                    QFile output(requestedPath(args));
                    if (!output.open(QIODevice::WriteOnly | QIODevice::NewOnly)
                        || !output.setPermissions(QFile::ReadOwner | QFile::WriteOwner)
                        || output.write(bytes) != bytes.size() || !output.flush() || ::fsync(output.handle()) != 0)
                        fail("file_error", "The QR code output could not be created completely.");
                    return true;
                }
                if (e->isRecycled()) fail("invalid_request", "Restore this entry before changing its one-time password.");
                auto settings = method == "totp.remove" ? QSharedPointer<Totp::Settings>() : KeyslotTotp::settings(e, args);
                return transaction([&] { e->setTotp(settings); });
            } catch (const KeyslotTotp::Failure& error) { throw Failure{error.code, error.message}; }
        }
        if (method == "entry.save") {
            auto* parent = group(text(args, "group"));
            if (parent->isRecycled()) fail("invalid_request", "Restore this group before editing it.");
            Entry* existing = args.contains("entry") ? entry(args) : nullptr;
            return transaction([&] {
                auto* e = existing;
                if (!e) { e = new Entry(); e->setUuid(QUuid::createUuid()); e->setGroup(parent); parent->applyGroupIconOnCreateTo(e); }
                editEntry(e, args);
                if (!existing) {
                    const auto initialHistory = e->historyItems();
                    e->removeHistoryItems(initialHistory);
                }
                if (e->group() != parent) e->setGroup(parent);
            });
        }
        if (method == "entry.move" || method == "entry.restore") {
            auto* e = entry(args);
            auto* destination = group(text(args, "group"));
            if (destination->isRecycled()) fail("invalid_request", "Choose a destination outside the recycle bin.");
            return transaction([&] { e->setGroup(destination); });
        }
        if (method == "entry.recycle") {
            auto* e = entry(args);
            if (e->isRecycled() || !db->metadata()->recycleBinEnabled())
                fail("invalid_request", "The recycle bin is disabled or this entry is already recycled.");
            return transaction([&] { db->recycleEntry(e); });
        }
        if (method == "entries.recycle") {
            const auto values = args.value("entries");
            if (!values.isArray() || values.toArray().isEmpty() || !db->metadata()->recycleBinEnabled())
                fail("invalid_request", "Select entries and enable the recycle bin first.");
            QList<Entry*> chosen;
            QSet<QUuid> seen;
            for (const auto& value : values.toArray()) {
                auto* e = entry(QJsonObject{{"entry", value}});
                if (e->isRecycled() || seen.contains(e->uuid()))
                    fail("invalid_request", "Choose each entry once, outside the recycle bin.");
                chosen.append(e); seen.insert(e->uuid());
            }
            return transaction([&] { for (auto* e : chosen) db->recycleEntry(e); });
        }
        if (method == "group.save") {
            Group* existing = args.contains("group") ? group(text(args, "group")) : nullptr;
            Group* parent = args.contains("parent") ? group(text(args, "parent")) : nullptr;
            const auto name = text(args, "name");
            if (!existing && !parent) fail("invalid_request", "Choose a parent group.");
            if (existing && existing->isRecycled() && parent)
                fail("invalid_request", "Use Restore to move a recycled group.");
            if (parent && parent->isRecycled()) fail("invalid_request", "Choose a parent outside the recycle bin.");
            if (existing == db->rootGroup() && parent) fail("invalid_request", "The root group cannot be moved.");
            for (auto* p = parent; p; p = p->parentGroup())
                if (p == existing) fail("invalid_request", "A group cannot be moved inside itself.");
            return transaction([&] {
                auto* g = existing;
                if (!g) { g = new Group(); g->setUuid(QUuid::createUuid()); }
                g->setName(name);
                if (args.contains("notes")) g->setNotes(text(args, "notes"));
                decorate(g, args);
                if (args.contains("tags")) g->setTags(text(args, "tags"));
                if (args.contains("searching")) g->setSearchingEnabled(static_cast<Group::TriState>(integer(args, "searching", 0, 2)));
                if (args.contains("expires")) g->setExpires(boolean(args, "expires"));
                if (args.contains("expiry")) {
                    const auto expiry = QDateTime::fromString(text(args, "expiry"), Qt::ISODate).toUTC();
                    if (!expiry.isValid()) fail("invalid_request", "Enter a valid group expiry timestamp.");
                    g->setExpiryTime(expiry);
                }
                if (parent) g->setParent(parent);
            });
        }
        if (method == "group.recycle") {
            auto* g = group(text(args, "group"));
            if (g == db->rootGroup() || g->isRecycled() || !db->metadata()->recycleBinEnabled())
                fail("invalid_request", "This group cannot be recycled.");
            return transaction([&] { db->recycleGroup(g); });
        }
        if (method == "attribute.save" || method == "attribute.remove") {
            auto* e = entry(args);
            const auto name = text(args, "name");
            if (name.isEmpty() || EntryAttributes::isDefaultAttribute(name))
                fail("invalid_request", "Choose a nonempty custom attribute name.");
            if (args.contains("revision")) {
                unchanged();
                if (text(args, "revision") != QString::fromLatin1(hash.toHex()))
                    fail("conflict", "The database changed since this attribute was opened. Open it again before continuing.");
            }
            const auto original = text(args, "original_name");
            const auto rename = method == "attribute.save" && args.contains("original_name");
            if (rename) {
                if (EntryAttributes::isPasskeyAttribute(name) || EntryAttributes::isDefaultAttribute(original)
                    || EntryAttributes::isPasskeyAttribute(original))
                    fail("invalid_request", "Choose a custom attribute name that is not reserved.");
                if (!original.isEmpty() && !e->attributes()->hasKey(original))
                    fail("not_found", "This attribute no longer exists. Open it again before continuing.");
                if (original != name && e->attributes()->hasKey(name))
                    fail("conflict", "An attribute with this name already exists. Choose another name.");
            }
            const auto value = text(args, "value");
            const auto protect = boolean(args, "protected", true);
            return transaction([&] {
                e->beginUpdate();
                if (method == "attribute.remove") e->attributes()->remove(name);
                else {
                    if (rename && !original.isEmpty() && original != name)
                        e->attributes()->rename(original, name);
                    e->attributes()->set(name, value, protect);
                }
                e->endUpdate();
            });
        }
        if (method == "history") {
            unchanged();
            auto* e = entry(args);
            QJsonArray items;
            int index = 0;
            for (const auto* old : e->historyItems()) items.append(QJsonObject{
                {"index", index++}, {"modified", old->timeInfo().lastModificationTime().toString(Qt::ISODate)},
                {"title", old->attributes()->isProtected(EntryAttributes::TitleKey) ? QString() : old->title()},
                {"username", old->attributes()->isProtected(EntryAttributes::UserNameKey) ? QString() : old->username()},
                {"revision", QString::fromLatin1(hash.toHex())}});
            return items;
        }
        if (method == "history.compare" || method == "history.value") {
            historyRevision(args);
            auto* e = entry(args);
            if (method == "history.value") {
                auto* version = historyVersion(e, args, "index");
                const auto section = text(args, "section"), key = text(args, "key");
                const auto comparison = KeyslotHistory::compare(version, version);
                bool exists = false;
                for (const auto& value : comparison.value("sections").toArray()) {
                    const auto item = value.toObject();
                    if (item.value("section").toString() != section) continue;
                    for (const auto& row : item.value("rows").toArray())
                        if (row.toObject().value("key").toString() == key) exists = true;
                }
                if (!exists) fail("not_found", "This history field does not exist.");
                return KeyslotHistory::value(version, section, key);
            }
            return KeyslotHistory::compare(historyVersion(e, args, "left"), historyVersion(e, args, "right"));
        }
        if (method == "history.restore" || method == "history.remove" || method == "history.clear") {
            historyRevision(args);
            auto* e = entry(args);
            auto* old = method == "history.clear" ? nullptr : historyVersion(e, args, "index", false);
            return transaction([&] {
                if (method == "history.clear") { const auto items = e->historyItems(); e->removeHistoryItems(items); }
                else if (method == "history.remove") e->removeHistoryItems({old});
                else {
                    std::unique_ptr<Entry> copy(old->clone(Entry::CloneNoFlags));
                    e->beginUpdate(); e->copyDataFrom(copy.get()); e->endUpdate();
                }
            });
        }
        if (method == "attachment.export" || method == "history.attachment") {
            auto* e = entry(args);
            if (method == "history.attachment") {
                historyRevision(args);
                e = historyVersion(e, args, "index");
                if (!args.contains("path")) fail("invalid_request", "Choose an attachment output file.");
            }
            const auto name = text(args, "name");
            if (!e->attachments()->hasKey(name)) fail("not_found", "This attachment does not exist.");
            if (args.contains("path")) {
                QFile output(requestedPath(args));
                if (!output.open(QIODevice::WriteOnly | QIODevice::NewOnly)
                    || !output.setPermissions(QFile::ReadOwner | QFile::WriteOwner))
                    fail("file_error", "The attachment output could not be created.");
                const auto bytes = e->attachments()->value(name);
                if (output.write(bytes) != bytes.size() || !output.flush() || ::fsync(output.handle()) != 0)
                    fail("file_error", "The attachment could not be written completely.");
                return true;
            }
            return QString::fromLatin1(e->attachments()->value(name).toBase64());
        }
        if (method == "attachment.import" || method == "attachment.remove") {
            auto* e = entry(args);
            const auto name = text(args, "name");
            if (name.isEmpty()) fail("invalid_request", "Choose an attachment name.");
            QByteArray bytes;
            if (method == "attachment.import") {
                if (args.contains("source")) {
                    if (args.contains("data")) fail("invalid_request", "Choose one attachment input source.");
                    const auto source = requestedPath(args, "source");
                    QFile input(source);
                    if (!QFileInfo(source).isFile() || !input.open(QIODevice::ReadOnly))
                        fail("file_error", "The attachment source could not be opened.");
                    const auto size = input.size();
                    if (size > std::numeric_limits<int>::max())
                        fail("invalid_request", "The attachment exceeds the upstream engine's size limit.");
                    bytes = input.readAll();
                    if (input.error() != QFile::NoError || bytes.size() != size)
                        fail("file_error", "The attachment source changed or could not be read completely.");
                } else {
                    const auto encoded = text(args, "data").toLatin1();
                    bytes = QByteArray::fromBase64(encoded);
                    if (bytes.toBase64() != encoded) fail("invalid_request", "The attachment encoding is invalid.");
                }
            }
            const bool replace = boolean(args, "replace");
            if (method == "attachment.import" && e->attachments()->hasKey(name) && !replace)
                fail("exists", "An attachment with this name already exists.");
            return transaction([&] {
                e->beginUpdate();
                if (method == "attachment.remove") e->attachments()->remove(name);
                else e->attachments()->set(name, bytes);
                e->endUpdate();
            });
        }
        fail("unknown_method", "This engine operation is unavailable.");
    }
};
} // namespace

int main(int argc, char** argv)
{
    // Destroy standalone settings after Qt has destroyed its QSettings objects.
    std::unique_ptr<QTemporaryDir> standaloneSettings;
    QCoreApplication app(argc, argv);
    app.setApplicationName("keyslot-engine");
    // Browser options are supplied by the GTK parent; never read/write stock KeePassXC settings.
    auto settingsDirectory = qEnvironmentVariable("KEYSLOT_ENGINE_CONFIG_DIRECTORY");
    if (settingsDirectory.isEmpty()) {
        standaloneSettings = std::make_unique<QTemporaryDir>(QDir::tempPath() + "/keyslot-settings-XXXXXX");
        if (!standaloneSettings->isValid()) return 1;
        settingsDirectory = standaloneSettings->path();
    }
    struct stat settingsInfo {};
    if (::lstat(QFile::encodeName(settingsDirectory).constData(), &settingsInfo)
        || !S_ISDIR(settingsInfo.st_mode) || settingsInfo.st_uid != ::getuid() || (settingsInfo.st_mode & 0077)) return 1;
    qputenv("KEYSLOT_ENGINE_CONFIG_DIRECTORY", QFile::encodeName(settingsDirectory));
    Config::createConfigFromFile(settingsDirectory + "/settings.ini", settingsDirectory + "/settings-local.ini");
    Bootstrap::disableCoreDumps();
    if (!Crypto::init()) return 1;
    Bootstrap::bootstrap();
    Engine engine;
    QFile input, output;
    if (!input.open(stdin, QIODevice::ReadOnly) || !output.open(stdout, QIODevice::WriteOnly)) return 1;
    while (true) {
        QByteArray frame = input.readLine(MaxFrame + 1);
        if (frame.isEmpty()) return 0;
        if (frame.size() > MaxFrame || !frame.endsWith('\n')) return 2;
        QJsonObject response;
        QJsonParseError parseError;
        auto doc = QJsonDocument::fromJson(frame, &parseError);
        frame.fill('\0');
        try {
            if (parseError.error != QJsonParseError::NoError || !doc.isObject())
                fail("invalid_request", "Expected one JSON request per line.");
            auto request = doc.object();
            const auto id = request.value("id");
            if (!id.isDouble() || id.toDouble() < 0 || id.toDouble() > 9007199254740991.0 || std::floor(id.toDouble()) != id.toDouble())
                fail("invalid_request", "The request ID is invalid.");
            response.insert("id", id);
            if (!request.value("params").isObject()) fail("invalid_request", "Expected request parameters.");
            response.insert("result", engine.call(text(request, "method"), request.value("params").toObject()));
        } catch (const Failure& error) {
            auto details = error.details;
            details.insert("code", error.code); details.insert("message", error.message);
            response.insert("error", details);
        } catch (...) {
            response.insert("error", QJsonObject{{"code", "internal_error"}, {"message", "The engine could not complete this operation."}});
        }
        response.insert("unlocked", engine.unlocked());
        auto bytes = QJsonDocument(response).toJson(QJsonDocument::Compact) + '\n';
        if (bytes.size() > MaxFrame || output.write(bytes) != bytes.size() || !output.flush()) return 2;
        bytes.fill('\0');
    }
}
