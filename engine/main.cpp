// SPDX-License-Identifier: GPL-3.0-only
// Built inside the pinned KeePassXC source tree; no KDBX or crypto reimplementation.
#include "config-keepassx.h"
#include "CsvImport.h"
#include "BrowserDatabase.h"
#include "KeyslotSSH.h"
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
#include <QBuffer>
#include <QCryptographicHash>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocale>
#include <QRegularExpression>
#include <QSaveFile>
#include <QTemporaryDir>
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
struct Failure { QString code; QString message; };
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
    QSharedPointer<Database> db;
    QString path;
    QByteArray hash;

    void requireDatabase() const { if (!db) fail("locked", "Unlock a database first."); }
    void unchanged() const {
        requireDatabase();
        if (digest(path) != hash) fail("conflict", "Another application changed this database. Refresh before continuing.");
    }
    Entry* entry(const QJsonObject& args) const {
        requireDatabase();
        const QUuid id(text(args, "entry"));
        auto* result = id.isNull() ? nullptr : db->rootGroup()->findEntryByUuid(id);
        if (!result) fail("not_found", "The entry no longer exists. Refresh the database.");
        return result;
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
    void reload(QSharedPointer<const CompositeKey> key = {}) {
        requireDatabase();
        if (!key) key = db->key();
        auto replacement = QSharedPointer<Database>::create();
        const auto before = digest(path);
        if (!replacement->open(path, key) || digest(path) != before) {
            fail("key_error", "The database could not be reopened. The currently open data is still available to save as a copy.");
        }
        db = std::move(replacement);
        hash = before;
    }
    void persist(bool creating = false) {
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
        hash = persistedHash;
    }
    QJsonObject transaction(const std::function<void()>& change) {
        unchanged();
        const auto originalKey = db->key();
        try {
            change();
            persist();
        } catch (...) {
            // A failed edit must never leave uncommitted changes in the live engine.
            try { reload(originalKey); } catch (...) { db.reset(); hash.clear(); }
            throw;
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
                     {"notes", g->notes()}, {"addressable", true}});
        for (const auto* e : g->entries()) entries.append(summary(e));
        for (const auto* child : g->children()) walk(child, depth + 1, groups, entries);
    }
    QJsonObject snapshot() const {
        requireDatabase();
        QJsonArray groups, entries;
        walk(db->rootGroup(), 0, groups, entries);
        return {{"name", db->metadata()->name()}, {"recycle_bin_enabled", db->metadata()->recycleBinEnabled()},
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
        for (auto it = fields.begin(); it != fields.end(); ++it) e->setDefaultAttribute(it.key(), it.value().toString());
        if (args.contains("tags")) e->setTags(text(args, "tags"));
        if (args.contains("expires")) e->setExpires(boolean(args, "expires"));
        if (expiry.isValid()) e->setExpiryTime(expiry);
        e->endUpdate();
        // setTotp owns its own history update and cannot be nested inside beginUpdate.
        if (args.contains("totp")) e->setTotp(otp);
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
            {"engine", "keepassxc-core"}, {"capabilities", QJsonArray{"uuid", "entry-edit", "groups", "attributes", "totp", "history", "attachments", "search", "settings", "key-change", "merge", "export", "reports", "encrypted-copy", "import", "csv-import", "import-review", "generator-options", "browser-associations", "browser-lookup"}}};
        if (method == "lock") { db.reset(); path.clear(); hash.clear(); return true; }
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
            const auto payload = QJsonDocument::fromJson(entries.first()->password().toUtf8()).object();
            if (text(payload, "path") != requestedPath(args))
                fail("invalid_request", "This quick-unlock credential belongs to another vault.");
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
            db = std::move(imported.db); path = imported.path; hash = imported.hash;
            return snapshot();
        }
        if (method == "open" || method == "create") {
            db.reset(); hash.clear();
            const auto requested = text(args, "path");
            if (requested.isEmpty() || requested.contains(QChar('\0'))) fail("invalid_request", "Select a database path.");
            auto key = makeKey(args, method == "open");
            auto opened = QSharedPointer<Database>::create();
            QFileInfo info(requested);
            path = method == "open" ? info.canonicalFilePath() : info.absoluteFilePath();
            if (method == "open") {
                const auto before = digest(path);
                if (!opened->open(path, key)) fail("key_error", "KeePassXC could not unlock the database. Check your credentials and hardware key.");
                if (digest(path) != before) fail("conflict", "The database changed while being unlocked.");
                hash = before;
                db = std::move(opened);
            } else {
                if (info.exists()) fail("file_error", "A file already exists at that location.");
                if (!opened->setKey(key)) fail("key_error", "KeePassXC could not set the database key.");
                opened->metadata()->setName(text(args, "name", info.completeBaseName()));
                opened->rootGroup()->setName("Passwords");
                db = std::move(opened);
                try { persist(true); } catch (...) { db.reset(); throw; }
            }
            return snapshot();
        }
        if (method == "generate") {
            const int length = args.contains("length") ? integer(args, "length", 1, 128) : 24;
            if (boolean(args, "passphrase")) {
                if (length < 4 || length > 20) fail("invalid_request", "Choose 4 to 20 words.");
                PassphraseGenerator generator;
                generator.setDefaultWordList(); generator.setWordCount(length);
                if (!generator.isWordListValid()) fail("file_error", "The upstream passphrase word list is unavailable.");
                return generator.generatePassphrase();
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
            return generator.generatePassword();
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
        requireDatabase();
        if (method == "refresh") { reload(); return snapshot(); }
        if (method == "database.key.verify") {
            unchanged();
            Database candidate;
            if (!candidate.open(path, makeKey(args, true)))
                fail("key_error", "The vault credential could not be verified. Check the password and key file.");
            unchanged();
            return true;
        }
        // Reads and recovery copies use the open state; transactions still verify the file before writing.
        if (method == "snapshot") return snapshot();
        if (method == "database.settings") return settings();
        if (method.startsWith("ssh.")) {
            try {
                if (method == "ssh.configure") { ssh.configure(args); return true; }
                if (method == "ssh.owned") return ssh.owned();
                if (method == "ssh.remove") return ssh.remove(args);
                if (method == "ssh.agent.list") return ssh.agentKeys();
                if (method == "ssh.removal.prepare") { unchanged(); return ssh.reviewRemoval(db, args, hash); }
                if (method == "ssh.removal.finish") { unchanged(); return ssh.finishRemoval(db, args, hash); }
                if (method == "ssh.add") { unchanged(); return ssh.add(db, args, hash); }
                auto* item = entry(args);
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
                if (method == "browser.lookup") return browser.lookup(db, args, hash);
                if (method == "browser.passkey.prepare") return browser.preparePasskey(db, args, hash);
                if (method == "browser.passkey.finish") return browser.finishPasskey(db, args, hash,
                    [this](const std::function<void()>& change) { transaction(change); });
                if (method == "browser.prepare_delete") return browser.prepareDelete(db, args, hash);
                if (method == "browser.delete") return browser.remove(db, args, hash,
                    [this](const std::function<void()>& change) { transaction(change); });
                if (method == "browser.totp") return browser.totp(db, args);
                if (method == "browser.groups") return browser.databaseGroups(db, args);
                if (method == "browser.prepare_group") return browser.prepareGroup(db, args, hash);
                if (method == "browser.create_group") return browser.createGroup(db, args, hash,
                    [this](const std::function<void()>& change) { transaction(change); });
                if (method == "browser.release") return browser.release(db, args, hash,
                    [this](const std::function<void()>& change) { transaction(change); });
                if (method == "browser.prepare_save") return browser.prepareSave(db, args, hash);
                if (method == "browser.save") return browser.save(db, args, hash,
                    [this](const std::function<void()>& change) { transaction(change); });
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
        if (method == "database.report") {
            auto borrowed = db;
            DatabaseStats stats(borrowed);
            HealthChecker checker(borrowed);
            QJsonArray entries;
            for (const auto* e : db->rootGroup()->entriesRecursive()) {
                if (e->isRecycled() || e->excludeFromReports()) continue;
                const auto health = checker.evaluate(e);
                if (health) entries.append(QJsonObject{{"uuid", uid(e->uuid())}, {"title", e->title()},
                    {"group", e->group()->fullPath()}, {"score", health->score()},
                    {"quality", static_cast<int>(health->quality())}, {"entropy", health->entropy()},
                    {"reason", health->scoreReason()}, {"details", health->scoreDetails()}, {"expired", e->isExpired()}});
            }
            return QJsonObject{{"groups", stats.groupCount}, {"entries", stats.entryCount},
                {"expired", stats.expiredEntries}, {"weak", stats.weakPasswords}, {"reused", stats.reusedPasswords},
                {"unique", stats.uniquePasswords}, {"average_length", stats.averagePwdLength()}, {"health", entries}};
        }
        if (method == "search") {
            EntrySearcher searcher(false, true);
            QJsonArray result;
            for (const auto* e : searcher.search(text(args, "query"), db->rootGroup())) result.append(uid(e->uuid()));
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
        if (method == "attribute.info") {
            auto* e = entry(args);
            const auto name = text(args, "name");
            if (!e->attributes()->hasKey(name)) fail("not_found", "This attribute does not exist.");
            return QJsonObject{{"value", e->attribute(name)}, {"protected", e->attributes()->isProtected(name)}};
        }
        if (method == "totp.settings") {
            auto* e = entry(args);
            return e->hasTotp() ? Totp::writeSettings(e->totpSettings(), e->title(), e->username(), true) : QString();
        }
        if (method == "entry.save") {
            auto* parent = group(text(args, "group"));
            if (parent->isRecycled()) fail("invalid_request", "Restore this group before editing it.");
            Entry* existing = args.contains("entry") ? entry(args) : nullptr;
            return transaction([&] {
                auto* e = existing;
                if (!e) { e = new Entry(); e->setUuid(QUuid::createUuid()); e->setGroup(parent); }
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
        if (method == "group.save") {
            Group* existing = args.contains("group") ? group(text(args, "group")) : nullptr;
            Group* parent = args.contains("parent") ? group(text(args, "parent")) : nullptr;
            const auto name = text(args, "name");
            if (!existing && !parent) fail("invalid_request", "Choose a parent group.");
            if (parent && parent->isRecycled()) fail("invalid_request", "Choose a parent outside the recycle bin.");
            if (existing == db->rootGroup() && parent) fail("invalid_request", "The root group cannot be moved.");
            for (auto* p = parent; p; p = p->parentGroup())
                if (p == existing) fail("invalid_request", "A group cannot be moved inside itself.");
            return transaction([&] {
                auto* g = existing;
                if (!g) { g = new Group(); g->setUuid(QUuid::createUuid()); }
                g->setName(name);
                if (args.contains("notes")) g->setNotes(text(args, "notes"));
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
            const auto value = text(args, "value");
            const auto protect = boolean(args, "protected", true);
            return transaction([&] {
                e->beginUpdate();
                if (method == "attribute.remove") e->attributes()->remove(name);
                else e->attributes()->set(name, value, protect);
                e->endUpdate();
            });
        }
        if (method == "history") {
            auto* e = entry(args);
            QJsonArray items;
            int index = 0;
            for (const auto* old : e->historyItems()) items.append(QJsonObject{
                {"index", index++}, {"modified", old->timeInfo().lastModificationTime().toString(Qt::ISODate)},
                {"title", old->title()}, {"username", old->attributes()->isProtected(EntryAttributes::UserNameKey) ? QString() : old->username()}});
            return items;
        }
        if (method == "history.restore" || method == "history.remove") {
            auto* e = entry(args);
            const auto indexValue = args.value("index");
            const int index = indexValue.toInt(-1);
            if (!indexValue.isDouble() || indexValue.toDouble() != index || index < 0 || index >= e->historyItems().size())
                fail("invalid_request", "Select a valid history version.");
            auto* old = e->historyItems().at(index);
            return transaction([&] {
                if (method == "history.remove") e->removeHistoryItems({old});
                else {
                    std::unique_ptr<Entry> copy(old->clone(Entry::CloneNoFlags));
                    e->beginUpdate(); e->copyDataFrom(copy.get()); e->endUpdate();
                }
            });
        }
        if (method == "attachment.export") {
            auto* e = entry(args);
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
            response.insert("error", QJsonObject{{"code", error.code}, {"message", error.message}});
        } catch (...) {
            response.insert("error", QJsonObject{{"code", "internal_error"}, {"message", "The engine could not complete this operation."}});
        }
        response.insert("unlocked", engine.unlocked());
        auto bytes = QJsonDocument(response).toJson(QJsonDocument::Compact) + '\n';
        if (bytes.size() > MaxFrame || output.write(bytes) != bytes.size() || !output.flush()) return 2;
        bytes.fill('\0');
    }
}
