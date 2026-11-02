// SPDX-License-Identifier: GPL-3.0-only
// Reuse upstream KeeShare containers, group cloning and synchronization merge rules.
#include "KeyslotKeeShare.h"
#include "core/Config.h"
#include "core/Database.h"
#include "core/Group.h"
#include "keeshare/KeeShare.h"
#include "keeshare/ShareImport.h"
#include "keeshare/ShareExport.h"
#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QLockFile>
#include <QSaveFile>
#include <QTemporaryDir>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <fcntl.h>

namespace {
constexpr qint64 MaxShareBytes = 256 * 1024 * 1024;
[[noreturn]] void reject(const char* code, const char* message) { throw KeeShareFailure{code, message}; }
QString text(const QJsonObject& o, const char* name, int maximum = 4096) {
    if (!o.value(name).isString() || o.value(name).toString().size() > maximum || o.value(name).toString().contains(QChar('\0')))
        reject("invalid_request", "A KeeShare text setting is invalid.");
    return o.value(name).toString();
}
bool flag(const QJsonObject& o, const char* name) {
    if (!o.value(name).isBool()) reject("invalid_request", "A KeeShare switch is invalid.");
    return o.value(name).toBool();
}
QByteArray digest(const QString& path) {
    QFileInfo info(path);
    if (!info.exists() && !info.isSymLink()) return {};
    if (!info.isFile() || info.size() > MaxShareBytes) reject("file_error", "A KeeShare file is unreadable or exceeds 256 MiB.");
    QFile file(path);
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!file.open(QIODevice::ReadOnly) || !hash.addData(&file)) reject("file_error", "A KeeShare file could not be read completely.");
    return hash.result();
}
QString resolved(const Database* db, const KeeShareSettings::Reference& reference) {
    QFileInfo info(QFileInfo(db->filePath()).absoluteDir().absoluteFilePath(reference.path));
    const auto path = info.exists() || info.isSymLink() ? info.canonicalFilePath() : info.absoluteFilePath();
    if (path.isEmpty()) reject("file_error", "A KeeShare path cannot be resolved.");
    struct stat source {}, target {};
    if (path == QFileInfo(db->filePath()).canonicalFilePath()
        || (::stat(QFile::encodeName(db->filePath()), &source) == 0 && ::stat(QFile::encodeName(path), &target) == 0
            && source.st_dev == target.st_dev && source.st_ino == target.st_ino))
        reject("invalid_request", "A share cannot replace the open database.");
    return path;
}
QString key(const Group* group, const KeeShareSettings::Reference& reference) {
    return group->uuid().toString() + QCryptographicHash::hash(KeeShareSettings::Reference::serialize(reference).toUtf8(),
        QCryptographicHash::Sha256).toHex();
}
void secureDirectory(const QString& path) {
    if (!QDir().mkpath(QFileInfo(path).absolutePath()) || (::mkdir(QFile::encodeName(path), 0700) && errno != EEXIST))
        reject("file_error", "The KeeShare identity directory could not be created.");
    struct stat info {};
    if (::lstat(QFile::encodeName(path), &info) || !S_ISDIR(info.st_mode) || info.st_uid != ::getuid() || (info.st_mode & 0077))
        reject("file_error", "The KeeShare identity directory must be private and owned by your user.");
}
}
void KeyslotKeeShare::configure(const QJsonObject& args) {
    const auto incoming = flag(args, "import"), outgoing = flag(args, "export");
    const auto path = text(args, "identity");
    if (!QFileInfo(path).isAbsolute()) reject("invalid_request", "The KeeShare identity path must be absolute.");
    if (allowImport != incoming || allowExport != outgoing || identityPath != path) {
        imported.clear();
        exported.clear();
    }
    allowImport = incoming;
    allowExport = outgoing;
    identityPath = path;
}
namespace {
struct IdentityFile { bool exists = false; QByteArray bytes; };
IdentityFile readIdentity(const QString& path) {
    const int descriptor = ::open(QFile::encodeName(path), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        if (errno == ENOENT) return {};
        reject("file_error", "The KeeShare identity file could not be read safely.");
    }
    struct stat info {};
    if (::fstat(descriptor, &info) || !S_ISREG(info.st_mode) || info.st_uid != ::getuid()
        || (info.st_mode & 0077) || info.st_size > 65536) {
        ::close(descriptor);
        reject("file_error", "The KeeShare identity file must be private and owned by your user.");
    }
    QFile input;
    if (!input.open(descriptor, QIODevice::ReadOnly, QFileDevice::AutoCloseHandle)) {
        ::close(descriptor);
        reject("file_error", "The KeeShare identity file could not be read.");
    }
    const auto bytes = input.read(65537);
    if (input.error() != QFileDevice::NoError || !input.atEnd() || bytes.size() != info.st_size)
        reject("file_error", "The KeeShare identity changed while it was being read.");
    return {true, bytes};
}
QString identityRevision(const IdentityFile& file) {
    return file.exists ? QString::fromLatin1(QCryptographicHash::hash(file.bytes, QCryptographicHash::Sha256).toHex())
                       : QStringLiteral("missing");
}
KeeShareSettings::Own parseIdentity(const IdentityFile& file) {
    if (!file.exists) return {};
    const auto own = KeeShareSettings::Own::deserialize(QString::fromUtf8(file.bytes));
    if (own.isNull() || own.key.isNull() || own.certificate.isNull())
        reject("file_error", "The KeeShare identity is invalid. Restore its backup before continuing.");
    return own;
}
QByteArray writeIdentity(const QString& path, const KeeShareSettings::Own& own) {
    const auto bytes = KeeShareSettings::Own::serialize(own).toUtf8();
    if (bytes.isEmpty() || bytes.size() > 65536)
        reject("key_error", "The KeeShare identity could not be serialized.");
    QSaveFile output(path);
    output.setDirectWriteFallback(false);
    if (!output.open(QIODevice::WriteOnly) || !output.setPermissions(QFile::ReadOwner | QFile::WriteOwner)
        || output.write(bytes) != bytes.size() || !output.flush() || ::fsync(output.handle()) || !output.commit())
        reject("file_error", "The KeeShare identity could not be saved.");
    return bytes;
}
}
QJsonObject KeyslotKeeShare::identitySettings(const QJsonObject& args) {
    const auto path = text(args, "identity"), operation = text(args, "operation");
    if (!QFileInfo(path).isAbsolute()) reject("invalid_request", "Choose an absolute KeeShare identity path.");
    if (operation != "read" && operation != "rename" && operation != "regenerate")
        reject("invalid_request", "Choose a supported KeeShare identity action.");
    secureDirectory(QFileInfo(path).absolutePath());
    QLockFile lock(path + ".lock");
    if (!lock.tryLock(5000)) reject("busy", "Another Keyslot window is updating the KeeShare identity. Try again.");
    auto file = readIdentity(path);
    auto own = parseIdentity(file);
    if (operation != "read") {
        if (text(args, "revision", 128) != identityRevision(file))
            reject("conflict", "The KeeShare identity changed elsewhere. Reload it before updating.");
        const auto signer = text(args, "signer");
        if (operation == "rename" && !file.exists) reject("not_found", "Generate a KeeShare identity first.");
        if (operation == "regenerate") own = KeeShareSettings::Own::generate();
        if (own.key.isNull() || own.certificate.isNull()) reject("key_error", "KeePassXC could not generate a signing identity.");
        own.certificate.signer = signer;
        if (identityRevision(readIdentity(path)) != identityRevision(file))
            reject("conflict", "The KeeShare identity changed elsewhere. Reload it before updating.");
        file = {true, writeIdentity(path, own)};
    }
    return {{"exists", file.exists}, {"signer", file.exists ? own.certificate.signer : QString()},
            {"fingerprint", file.exists ? own.certificate.fingerprint() : QString()}, {"revision", identityRevision(file)}};
}
void KeyslotKeeShare::identity() {
    if (identityPath.isEmpty()) reject("disabled", "Configure KeeShare before exporting signed containers.");
    secureDirectory(QFileInfo(identityPath).absolutePath());
    QLockFile lock(identityPath + ".lock");
    if (!lock.tryLock(5000)) reject("busy", "Another Keyslot window is updating the KeeShare identity. Try again.");
    auto file = readIdentity(identityPath);
    if (file.exists && QCryptographicHash::hash(file.bytes, QCryptographicHash::Sha256) == signedIdentity) return;
    auto own = parseIdentity(file);
    if (!file.exists) {
        own = KeeShareSettings::Own::generate();
        if (own.certificate.signer.isEmpty()) own.certificate.signer = "Keyslot";
        if (own.key.isNull() || own.certificate.isNull()) reject("key_error", "KeePassXC could not generate a KeeShare signing identity.");
        file = {true, writeIdentity(identityPath, own)};
    }
    const auto revision = QCryptographicHash::hash(file.bytes, QCryptographicHash::Sha256);
    if (revision != signedIdentity) {
        exported.clear();
        signedIdentity = revision;
    }
    KeeShare::setOwn(own);
}
QJsonObject KeyslotKeeShare::settings(const Group* group) const {
    const auto reference = KeeShare::referenceOf(group);
    return {{"mode", int(reference.type)}, {"path", reference.path}, {"has_password", !reference.password.isEmpty()},
            {"keep_groups", reference.keepGroups}, {"import_enabled", allowImport}, {"export_enabled", allowExport}};
}
void KeyslotKeeShare::saveSettings(Group* group, const QJsonObject& args) {
    if (group->isRecycled()) reject("invalid_request", "Restore this group before configuring KeeShare.");
    auto reference = KeeShare::referenceOf(group);
    const auto mode = args.value("mode");
    if (!mode.isDouble() || mode.toDouble() != mode.toInt(-1) || mode.toInt() < 0 || mode.toInt() > 3)
        reject("invalid_request", "Choose a supported KeeShare mode.");
    reference.type = static_cast<KeeShareSettings::TypeFlag>(mode.toInt());
    reference.path = text(args, "path");
    reference.keepGroups = flag(args, "keep_groups");
    if (args.contains("password")) reference.password = text(args, "password", 65536);
    if (reference.type != KeeShareSettings::Inactive && (reference.path.isEmpty() || reference.password.isEmpty()))
        reject("invalid_request", "Choose a share file and a share password.");
    if (!reference.path.isEmpty()) {
        const auto path = resolved(group->database(), reference);
        for (const auto* other : group->database()->rootGroup()->groupsRecursive(true)) {
            if (other == group || other->isRecycled()) continue;
            const auto current = KeeShare::referenceOf(other);
            if (reference.isExporting() && current.isExporting() && resolved(group->database(), current) == path)
                reject("conflict", "Two groups cannot export to the same KeeShare file.");
        }
    }
    KeeShare::setReferenceTo(group, reference);
    imported.clear();
    exported.clear();
}
QJsonObject KeyslotKeeShare::sync(const QSharedPointer<Database>& db, const QByteArray& fingerprint,
    const std::function<void(const std::function<void()>&)>& transaction,
    const std::function<QByteArray()>& currentFingerprint, bool force) {
    Q_UNUSED(fingerprint);
    struct Incoming { QUuid group; KeeShareSettings::Reference reference; QString path, stage, key; QByteArray hash; };
    QList<Incoming> incoming;
    QJsonArray warnings;
    int imports = 0, exports = 0;
    QTemporaryDir stages;
    if (!stages.isValid()) reject("file_error", "KeeShare encrypted input staging is unavailable.");
    for (const auto* group : db->rootGroup()->groupsRecursive(true)) {
        if (group->isRecycled()) continue;
        const auto reference = KeeShare::referenceOf(group);
        if (!allowImport || !reference.isImporting()) continue;
        try {
            const auto path = resolved(db.data(), reference);
            const auto hash = digest(path);
            if (hash.isEmpty()) {
                if (!reference.isExporting()) warnings.append("A KeeShare import source is missing.");
                continue;
            }
            const auto id = key(group, reference);
            if (!force && imported.value(id) == hash) continue;
            const auto stage = stages.path() + "/" + QString::number(incoming.size()) + ".kdbx.share";
            if (!QFile::copy(path, stage) || digest(stage) != hash || digest(path) != hash)
                reject("conflict", "A KeeShare source changed while it was being read.");
            incoming.append({group->uuid(), reference, path, stage, id, hash});
        } catch (const KeeShareFailure& error) { warnings.append(error.message); }
    }
    bool importFailed = false;
    if (!incoming.isEmpty()) {
        try {
            transaction([&] {
                for (const auto& source : incoming) {
                    auto* group = db->rootGroup()->findGroupByUuid(source.group);
                    if (!group || digest(source.path) != source.hash)
                        reject("conflict", "A KeeShare source changed during synchronization.");
                    const auto result = ShareImport::containerInto(source.stage, source.reference, group);
                    if (result.isError() || result.isWarning())
                        reject("import_error", "KeePassXC could not import a share. Check its password and file format.");
                    if (digest(source.path) != source.hash)
                        reject("conflict", "A KeeShare source changed during synchronization.");
                }
            });
            for (const auto& source : incoming) imported[source.key] = source.hash;
            imports = incoming.size();
        } catch (const KeeShareFailure& error) {
            warnings.append(error.message);
            importFailed = true;
        }
    }
    // Never overwrite a bidirectional source after an unsuccessful import.
    if (importFailed) return {{"imports", imports}, {"exports", exports}, {"warnings", warnings}};
    QHash<QString, int> destinations;
    for (const auto* group : db->rootGroup()->groupsRecursive(true)) {
        const auto reference = KeeShare::referenceOf(group);
        if (group->isRecycled() || !allowExport || !reference.isExporting()) continue;
        try { ++destinations[resolved(db.data(), reference)]; }
        catch (const KeeShareFailure& error) { warnings.append(error.message); }
    }
    const auto databaseHash = currentFingerprint();
    for (const auto* group : db->rootGroup()->groupsRecursive(true)) {
        const auto reference = KeeShare::referenceOf(group);
        if (group->isRecycled() || !allowExport || !reference.isExporting()) continue;
        try {
            const auto path = resolved(db.data(), reference), id = key(group, reference);
            if (destinations.value(path) != 1) reject("conflict", "Conflicting KeeShare export destinations were skipped.");
            if (reference.isImporting() && !allowImport)
                reject("disabled", "Enable imports before exporting a bidirectional KeeShare group.");
            if (path.endsWith(".kdbx.share")) identity();
            if (!force && exported.value(id) == databaseHash) continue;
            const auto before = digest(path);
            if (reference.isImporting() && !before.isEmpty() && imported.value(id) != before)
                reject("conflict", "The shared file changed before export. Import it successfully before trying again.");
            const QFileInfo target(path);
            QTemporaryDir staging(target.absolutePath() + "/.keyslot-share-XXXXXX");
            if (!staging.isValid()) reject("file_error", "The KeeShare export folder is not writable.");
            const auto stage = staging.path() + (path.endsWith(".kdbx.share") ? "/share.kdbx.share" : "/share.kdbx");
            const auto result = ShareExport::intoContainer(stage, reference, group);
            if (result.isError()) reject("export_error", "KeePassXC could not serialize a KeeShare export.");
            const auto written = digest(stage);
            if (written.isEmpty()) reject("export_error", "The KeeShare export is empty.");
            QFile input(stage);
            QSaveFile output(path);
            output.setDirectWriteFallback(false);
            if (!input.open(QIODevice::ReadOnly) || !output.open(QIODevice::WriteOnly)
                || !output.setPermissions(target.exists() ? target.permissions() : QFile::ReadOwner | QFile::WriteOwner))
                reject("file_error", "The KeeShare export could not be staged.");
            while (!input.atEnd()) {
                const auto bytes = input.read(1024 * 1024);
                if ((bytes.isEmpty() && input.error() != QFile::NoError) || output.write(bytes) != bytes.size())
                    reject("file_error", "The KeeShare export could not be written completely.");
            }
            if (currentFingerprint() != databaseHash || resolved(db.data(), reference) != path || digest(path) != before || !output.flush()
                || ::fsync(output.handle()) || !output.commit())
                reject("conflict", "The share changed or could not be committed. Its previous file was preserved.");
            if (reference.isImporting()) imported[id] = written;
            exported[id] = databaseHash;
            ++exports;
        } catch (const KeeShareFailure& error) { warnings.append(error.message); }
    }
    return {{"imports", imports}, {"exports", exports}, {"warnings", warnings}};
}
