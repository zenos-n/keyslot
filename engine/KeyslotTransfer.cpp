// SPDX-License-Identifier: GPL-3.0-only
// Entries are cloned and streamed through the pinned upstream KDBX implementation.
#include "KeyslotTransfer.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/EntryAttributes.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "crypto/Random.h"
#include "crypto/kdf/AesKdf.h"
#include "format/Kdbx4Reader.h"
#include "format/KeePass2Writer.h"
#include "keys/CompositeKey.h"
#include "keys/PasswordKey.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLocalServer>
#include <QLocalSocket>
#include <QSet>
#include <QTemporaryDir>
#include <QtEndian>
#include <cmath>
#include <limits>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
[[noreturn]] void reject(const char* code, const char* message) { throw TransferFailure{code, message}; }
QString text(const QJsonObject& args, const char* key, int limit = 4096) {
    const auto value = args.value(key);
    if (!value.isString() || value.toString().size() > limit || value.toString().contains(QChar('\0')))
        reject("invalid_request", "A transfer text field is invalid.");
    return value.toString();
}
QString token() { return QString::fromLatin1(randomGen()->randomArray(32).toHex()); }
QString uid(const QUuid& id) { return id.toString(QUuid::WithoutBraces); }
int pid(const QJsonObject& args, const char* key) {
    const auto value = args.value(key);
    const auto number = value.toDouble(-1);
    if (!value.isDouble() || !std::isfinite(number) || number != std::floor(number) || number <= 0 || number > std::numeric_limits<int>::max())
        reject("invalid_request", "The transfer peer is invalid.");
    return int(number);
}
int position(const QJsonObject& args, const Group* target, bool group) {
    if (!args.contains("position")) return -1;
    const auto value = args.value("position"); const auto n = value.toDouble(-2);
    if (!value.isDouble() || !std::isfinite(n) || std::floor(n) != n || n < -1 || n > target->children().size() || (!group && n != -1))
        reject("invalid_request", "The reviewed group insertion position is invalid.");
    return int(n);
}
QStringList identifiers(const QJsonObject& args, const char* field = "entries", bool allowEmpty = false) {
    if (!args.value(field).isArray() || (!allowEmpty && args.value(field).toArray().isEmpty()))
        reject("invalid_request", "Choose items to transfer.");
    QStringList result;
    QSet<QString> seen;
    for (const auto& value : args.value(field).toArray()) {
        if (!value.isString() || QUuid(value.toString()).isNull()) reject("invalid_request", "A transfer entry is invalid.");
        const auto id = uid(QUuid(value.toString()));
        if (seen.contains(id)) reject("invalid_request", "Choose each transfer item once.");
        seen.insert(id);
        result.append(id);
    }
    return result;
}
Group* findGroup(Database* db, const QString& id) {
    const QUuid uuid(id);
    Group* found = nullptr;
    for (auto* group : db->rootGroup()->groupsRecursive(true)) if (!uuid.isNull() && group->uuid() == uuid) {
        if (found) reject("invalid_request", "The transfer group identifier is ambiguous.");
        found = group;
    }
    if (!found) reject("not_found", "The transfer group is no longer available.");
    return found;
}
Group* transferGroup(Database* db, const QString& id) {
    auto* group = findGroup(db, id);
    if (group == db->rootGroup()) reject("invalid_request", "The database root cannot be transferred as a group.");
    return group;
}
void remapIcons(Group* tree, const QHash<QUuid, QUuid>& icons) {
    for (auto* group : tree->groupsRecursive(true)) if (icons.contains(group->iconUuid())) {
        group->setUpdateTimeinfo(false); group->setIcon(icons.value(group->iconUuid())); group->setUpdateTimeinfo(true);
    }
    for (auto* entry : tree->entriesRecursive(true)) if (icons.contains(entry->iconUuid())) {
        entry->setUpdateTimeinfo(false); entry->setIcon(icons.value(entry->iconUuid())); entry->setUpdateTimeinfo(true);
    }
}
void freshIds(Group* tree, const Database* db) {
    QSet<QUuid> reserved;
    for (const auto* group : db->rootGroup()->groupsRecursive(true)) reserved.insert(group->uuid());
    for (const auto* entry : db->rootGroup()->entriesRecursive()) reserved.insert(entry->uuid());
    const auto fresh = [&](QUuid value) {
        while (reserved.contains(value)) value = QUuid::createUuid();
        reserved.insert(value); return value;
    };
    for (auto* group : tree->groupsRecursive(true)) group->setUuid(fresh(group->uuid()));
    for (auto* entry : tree->entriesRecursive()) {
        const auto value = fresh(entry->uuid()); entry->setUuid(value);
        for (auto* version : entry->historyItems()) version->setUuid(value);
    }
}
QList<Entry*> entries(const Database* db, const QStringList& ids) {
    QList<Entry*> result;
    QHash<QUuid, Entry*> available;
    QSet<QUuid> ambiguous;
    for (auto* item : db->rootGroup()->entriesRecursive()) {
        if (available.contains(item->uuid())) ambiguous.insert(item->uuid());
        available.insert(item->uuid(), item);
    }
    for (const auto& id : ids) {
        auto* entry = available.value(QUuid(id));
        if (!entry || ambiguous.contains(entry->uuid())) reject("not_found", "A transfer entry is unavailable or its identifier is ambiguous.");
        result.append(entry);
    }
    return result;
}
QByteArray digest(const QString& path) {
    QFile file(path);
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!QFileInfo(path).isFile() || !file.open(QIODevice::ReadOnly) || !hash.addData(&file))
        reject("file_error", "The saved transfer database could not be verified.");
    return hash.result();
}
void distinct(const QString& source, const QString& destination) {
    struct stat a {}, b {};
    if (::stat(QFile::encodeName(source), &a) || ::stat(QFile::encodeName(destination), &b)
        || !S_ISREG(a.st_mode) || !S_ISREG(b.st_mode)) reject("file_error", "Both transfer vaults must be available regular files.");
    if (a.st_dev == b.st_dev && a.st_ino == b.st_ino)
        reject("invalid_request", "These windows refer to the same database file.");
}
bool peer(QLocalSocket& socket, int expected) {
    struct ucred credentials {};
    socklen_t length = sizeof(credentials);
    if (::getsockopt(socket.socketDescriptor(), SOL_SOCKET, SO_PEERCRED, &credentials, &length)
        || credentials.uid != ::getuid() || credentials.pid != expected) return false;
    // Upstream hardening makes /proc/<pid>/exe unreadable. Authenticate the parent's exact child PID instead.
    return true;
}

// Blocking, bounded chunks keep credentials out of Python and avoid an attachment-sized JSON/frame buffer.
class Channel {
    QLocalSocket& socket;
    QElapsedTimer clock;
    int timeout;
public:
    explicit Channel(QLocalSocket& socket, int timeout = 300000) : socket(socket), timeout(timeout) { clock.start(); }
    void alive() {
        if (clock.elapsed() > timeout || socket.state() != QLocalSocket::ConnectedState)
            reject("transfer_error", "The native transfer disconnected or timed out. The source entries were kept.");
    }
    QByteArray read(qint64 size) {
        QByteArray result;
        while (result.size() < size) {
            const auto part = socket.read(size - result.size());
            if (!part.isEmpty()) result.append(part);
            else { alive(); socket.waitForReadyRead(200); }
        }
        return result;
    }
    void write(const char* data, qint64 size) {
        while (size) {
            alive();
            const auto written = socket.write(data, qMin<qint64>(size, 65536));
            if (written <= 0) reject("transfer_error", "The native transfer could not be sent.");
            data += written; size -= written;
            while (socket.bytesToWrite()) { alive(); socket.waitForBytesWritten(200); }
        }
    }
    void write(const QByteArray& bytes) { write(bytes.constData(), bytes.size()); }
    quint32 number() { return qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(read(4).constData())); }
    void number(quint32 number) { const auto bytes = qToBigEndian(number); write(reinterpret_cast<const char*>(&bytes), 4); }
};
class Chunks : public QIODevice {
    Channel& channel;
    quint32 remaining = 0;
    bool ended = false, failed = false, started = false;
public:
    explicit Chunks(Channel& channel, OpenMode mode) : channel(channel) { open(mode); }
    bool isSequential() const override { return true; }
    bool seek(qint64 position) override { return position == 0 && !started; }
    bool atEnd() const override { return failed || (ended && !remaining && !QIODevice::bytesAvailable()); }
    qint64 bytesAvailable() const override { return failed ? 0 : QIODevice::bytesAvailable() + remaining + (ended ? 0 : 65536); }
    void finish() { channel.number(0); }
protected:
    qint64 readData(char* data, qint64 maximum) override {
        if (failed) return -1;
        started = true;
        try {
        qint64 offset = 0;
        while (!ended && offset < maximum) {
            if (!remaining) {
                remaining = channel.number();
                if (!remaining) { ended = true; break; }
                if (remaining > 65536) reject("invalid_request", "A native transfer chunk is invalid.");
            }
            const auto count = qMin<qint64>(maximum - offset, remaining);
            const auto bytes = channel.read(count);
            memcpy(data + offset, bytes.constData(), count); remaining -= count; offset += count;
        }
        return offset;
        } catch (const TransferFailure& error) { failed = true; setErrorString(error.message); return -1; }
    }
    qint64 writeData(const char* data, qint64 size) override {
        if (failed) return -1;
        try {
        const auto total = size;
        while (size) {
            const auto count = qMin<qint64>(size, 65536);
            channel.number(count); channel.write(data, count);
            data += count; size -= count;
        }
        return total;
        } catch (const TransferFailure& error) { failed = true; setErrorString(error.message); return -1; }
    }
};
QSharedPointer<CompositeKey> key(const QByteArray& bytes) {
    auto result = QSharedPointer<CompositeKey>::create();
    result->addKey(QSharedPointer<PasswordKey>::create(QString::fromLatin1(bytes.toHex())));
    return result;
}
}

void KeyslotTransfer::clear() { sources.clear(); destinations.clear(); }
void KeyslotTransfer::prune() {
    for (auto it = sources.begin(); it != sources.end();) {
        if (it->expires < clock.elapsed()) it = sources.erase(it); else ++it;
    }
    for (auto it = destinations.begin(); it != destinations.end();) {
        if (it->expires < clock.elapsed()) it = destinations.erase(it); else ++it;
    }
    if (sources.size() + destinations.size() >= 8) reject("busy", "Finish or cancel the pending entry transfers first.");
}
QJsonObject KeyslotTransfer::prepare(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint) {
    prune();
    Source pending;
    pending.database = db; pending.fingerprint = fingerprint;
    pending.sourceGroup = args.value("source_group").toString();
    Group* sourceGroup = nullptr;
    if (!pending.sourceGroup.isEmpty()) {
        if (args.contains("entries")) reject("invalid_request", "Choose entries or a group, not both.");
        sourceGroup = transferGroup(db.data(), pending.sourceGroup);
        pending.sourceGroup = uid(sourceGroup->uuid());
        for (const auto* group : sourceGroup->groupsRecursive(true)) pending.groups.append(uid(group->uuid()));
        for (const auto* entry : sourceGroup->entriesRecursive()) pending.entries.append(uid(entry->uuid()));
    } else pending.entries = identifiers(args);
    if (!args.value("move").isBool()) reject("invalid_request", "Choose copy or move.");
    pending.move = args.value("move").toBool();
    pending.expires = clock.elapsed() + 120000;
    pending.key = randomGen()->randomArray(32);
    pending.capsule = QSharedPointer<Database>::create();
    auto kdf = QSharedPointer<AesKdf>::create(false); kdf->setRounds(10000);
    pending.capsule->setKdf(kdf);
    if (!pending.capsule->setKey(key(pending.key))) reject("key_error", "The native transfer key could not be prepared.");
    QSet<QUuid> icons;
    QJsonArray review;
    bool hasReferences = false;
    int recycled = 0;
    if (sourceGroup) {
        auto* copy = sourceGroup->clone(Entry::CloneIncludeHistory, Group::CloneIncludeEntries);
        copy->setUpdateTimeinfo(false); copy->setParent(pending.capsule->rootGroup(), -1, false); copy->setUpdateTimeinfo(true);
        for (const auto* group : sourceGroup->groupsRecursive(true)) if (!group->iconUuid().isNull()) icons.insert(group->iconUuid());
    }
    for (auto* entry : entries(db.data(), pending.entries)) {
        if (entry->isRecycled()) ++recycled;
        if (!sourceGroup) {
            auto* copy = entry->clone(Entry::CloneIncludeHistory);
            copy->setUpdateTimeinfo(false); copy->setGroup(pending.capsule->rootGroup(), false); copy->setUpdateTimeinfo(true);
        }
        bool references = false;
        for (const auto& name : entry->attributes()->keys()) references |= entry->attributes()->isReference(name);
        hasReferences |= references;
        if (review.size() < 10) review.append(QJsonObject{{"entry", uid(entry->uuid())}, {"title", entry->title()}, {"references", references}});
        if (!entry->iconUuid().isNull()) icons.insert(entry->iconUuid());
        for (const auto* history : entry->historyItems()) if (!history->iconUuid().isNull()) icons.insert(history->iconUuid());
    }
    pending.capsule->metadata()->copyCustomIcons(icons, db->metadata());
    const auto id = token(); sources.insert(id, pending);
    return {{"token", id}, {"entries", review}, {"ids", QJsonArray::fromStringList(pending.entries)},
        {"groups", QJsonArray::fromStringList(pending.groups)}, {"source_group", pending.sourceGroup},
        {"group_name", sourceGroup ? sourceGroup->name() : QString()}, {"count", pending.entries.size()},
        {"contains_recycle_bin", sourceGroup && db->metadata()->recycleBin()
            && sourceGroup->groupsRecursive(true).contains(db->metadata()->recycleBin())},
        {"recycled_entries", recycled}, {"recycled_group", sourceGroup && sourceGroup->isRecycled()},
        {"references", hasReferences}, {"move", pending.move}, {"pid", int(::getpid())}, {"path", db->filePath()}};
}
QJsonObject KeyslotTransfer::listen(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint) {
    prune();
    Destination pending;
    pending.database = db; pending.fingerprint = fingerprint;
    pending.sourcePid = pid(args, "source_pid");
    pending.sourceToken = text(args, "source_token", 64);
    if (QByteArray::fromHex(pending.sourceToken.toLatin1()).toHex() != pending.sourceToken.toLatin1() || pending.sourceToken.size() != 64)
        reject("invalid_request", "The transfer token is invalid.");
    pending.sourcePath = text(args, "source_path");
    distinct(pending.sourcePath, db->filePath());
    pending.sourceGroup = args.value("source_group").toString();
    pending.entries = identifiers(args, "entries", !pending.sourceGroup.isEmpty());
    pending.groups = identifiers(args, "groups", pending.sourceGroup.isEmpty());
    if ((!pending.sourceGroup.isEmpty() && (!pending.groups.contains(pending.sourceGroup) || QUuid(pending.sourceGroup).isNull()))
        || (pending.sourceGroup.isEmpty() && !pending.groups.isEmpty()))
        reject("invalid_request", "The reviewed group manifest is invalid.");
    pending.group = text(args, "group", 64);
    const auto* group = findGroup(db.data(), pending.group);
    pending.position = position(args, group, !pending.sourceGroup.isEmpty());
    const auto runtime = qEnvironmentVariable("KEYSLOT_ENGINE_CONFIG_DIRECTORY", QDir::tempPath());
    pending.directory = QSharedPointer<QTemporaryDir>::create(runtime + "/transfer-XXXXXX");
    if (!pending.directory->isValid()) reject("file_error", "The private transfer directory could not be created.");
    pending.server = QSharedPointer<QLocalServer>::create();
    pending.server->setSocketOptions(QLocalServer::UserAccessOption);
    const auto socket = pending.directory->path() + "/socket";
    if (QFile::encodeName(socket).size() >= 104 || !pending.server->listen(socket))
        reject("file_error", "The private native transfer socket could not be opened.");
    pending.expires = clock.elapsed() + 120000;
    const auto id = token(); destinations.insert(id, pending);
    return {{"token", id}, {"socket", socket}, {"pid", int(::getpid())}, {"path", db->filePath()},
            {"group", uid(group->uuid())}, {"group_name", group->fullPath()}, {"name", db->metadata()->name()},
            {"position", pending.position}, {"recycled", group->isRecycled()}};
}
QJsonObject KeyslotTransfer::send(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint) {
    const auto id = text(args, "token", 64);
    auto found = sources.find(id);
    if (found == sources.end() || found->database.toStrongRef() != db || found->fingerprint != fingerprint
        || found->expires < clock.elapsed() || found->started)
        reject("expired", "The source transfer approval expired or the vault changed.");
    const auto ticket = args.value("destination").toObject();
    const auto destinationPath = text(ticket, "path");
    distinct(db->filePath(), destinationPath);
    const auto endpoint = text(ticket, "socket", 103);
    struct stat info {}, parent {};
    if (::lstat(QFile::encodeName(endpoint), &info) || !S_ISSOCK(info.st_mode) || info.st_uid != ::getuid() || (info.st_mode & 0077)
        || ::lstat(QFile::encodeName(QFileInfo(endpoint).absolutePath()), &parent) || !S_ISDIR(parent.st_mode)
        || parent.st_uid != ::getuid() || (parent.st_mode & 0077)) reject("denied", "The native transfer socket is not private.");
    QLocalSocket socket;
    socket.setReadBufferSize(1024 * 1024);
    socket.connectToServer(endpoint);
    if (!socket.waitForConnected(5000) || !peer(socket, pid(ticket, "pid"))) reject("denied", "The destination helper could not be authenticated.");
    Channel channel(socket);
    const auto destinationToken = text(ticket, "token", 64);
    if (destinationToken.size() != 64) reject("invalid_request", "The destination token is invalid.");
    found->started = true;
    channel.write("KSXFER01", 8); channel.write(destinationToken.toLatin1()); channel.write(found->key);
    Chunks stream(channel, QIODevice::WriteOnly);
    KeePass2Writer writer;
    if (!writer.writeDatabase(&stream, found->capsule.data())) reject("transfer_error", "The encrypted entry transfer could not be written.");
    stream.finish();
    const auto length = channel.number();
    if (!length || length > 1024 * 1024) reject("transfer_error", "The destination receipt is invalid.");
    const auto document = QJsonDocument::fromJson(channel.read(length));
    const auto receipt = document.object();
    if (receipt.value("token").toString() != destinationToken || receipt.value("source_token").toString() != id
        || receipt.value("path").toString() != destinationPath || receipt.value("count").toInt(-1) != found->entries.size()
        || receipt.value("groups").toInt(-1) != found->groups.size())
        reject("transfer_error", "The saved destination receipt does not match this transfer.");
    const auto saved = QByteArray::fromHex(receipt.value("hash").toString().toLatin1());
    if (saved.size() != 32 || digest(destinationPath) != saved) reject("conflict", "The destination changed before its saved copy could be verified.");
    found->delivered = true; found->destination = destinationPath; found->destinationHash = saved;
    found->expires = clock.elapsed() + 120000;
    return {{"delivered", true}, {"count", found->entries.size()}};
}
QJsonObject KeyslotTransfer::receive(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint, const Commit& commit) {
    const auto id = text(args, "token", 64);
    if (!destinations.contains(id)) reject("expired", "The destination transfer approval is unavailable.");
    const auto pending = destinations.take(id);
    if (pending.database.toStrongRef() != db || pending.fingerprint != fingerprint || pending.expires < clock.elapsed())
        reject("expired", "The destination transfer approval expired or the vault changed.");
    QElapsedTimer waiting; waiting.start();
    QSharedPointer<QLocalSocket> socket;
    while (waiting.elapsed() < 10000 && !socket) {
        if (::kill(pending.sourcePid, 0)) reject("transfer_error", "The source vault closed before the transfer.");
        if (!pending.server->hasPendingConnections()) pending.server->waitForNewConnection(200);
        while (pending.server->hasPendingConnections()) {
            QSharedPointer<QLocalSocket> incoming(pending.server->nextPendingConnection());
            if (!peer(*incoming, pending.sourcePid) && !peer(*incoming, int(::getppid()))) { incoming->abort(); continue; }
            incoming->setReadBufferSize(1024 * 1024);
            Channel hello(*incoming, 5000);
            const auto magic = hello.read(8);
            const auto offered = hello.read(64);
            if (offered != id.toLatin1()) { incoming->abort(); continue; }
            if (magic == "KSXCAN01" && peer(*incoming, int(::getppid()))) reject("cancelled", "The transfer was cancelled.");
            if (magic == "KSXFER01" && peer(*incoming, pending.sourcePid)) socket = incoming;
            else incoming->abort();
        }
    }
    if (!socket) reject("transfer_error", "The source did not connect. The source entries were kept.");
    Channel channel(*socket);
    const auto password = channel.read(32);
    Chunks stream(channel, QIODevice::ReadOnly);
    auto capsule = QSharedPointer<Database>::create();
    // The capsule writer always uses KDBX4. The generic detector consumes magic bytes then seeks backwards.
    Kdbx4Reader reader;
    if (!reader.readDatabase(&stream, key(password), capsule.data())) reject("transfer_error", "The encrypted entry transfer could not be read.");
    // Consume the bounded chunk terminator before sending the saved receipt.
    char extra;
    if (stream.read(&extra, 1) != 0) reject("invalid_request", "The native transfer contains trailing data.");
    QStringList received;
    for (const auto* entry : capsule->rootGroup()->entriesRecursive()) received.append(uid(entry->uuid()));
    auto expected = pending.entries; received.sort(); expected.sort();
    QStringList receivedGroups;
    for (const auto* child : capsule->rootGroup()->groupsRecursive(false)) receivedGroups.append(uid(child->uuid()));
    auto expectedGroups = pending.groups; receivedGroups.sort(); expectedGroups.sort();
    auto children = capsule->rootGroup()->children();
    if (received != expected || receivedGroups != expectedGroups
        || (!pending.sourceGroup.isEmpty() && (children.size() != 1 || uid(children.first()->uuid()) != pending.sourceGroup
            || !capsule->rootGroup()->entries().isEmpty())))
        reject("invalid_request", "The transfer does not contain the reviewed entries and groups.");
    auto* group = findGroup(db.data(), pending.group);
    if (pending.position > group->children().size()) reject("conflict", "The reviewed group position changed before saving.");
    QJsonArray imported, importedGroups;
    QString importedRoot;
    commit([&] {
        QHash<QUuid, QUuid> icons;
        for (const auto& original : capsule->metadata()->customIconsOrder()) {
            const auto data = capsule->metadata()->customIcon(original);
            auto mapped = original;
            if (db->metadata()->hasCustomIcon(mapped) && !(db->metadata()->customIcon(mapped) == data)) {
                mapped = db->metadata()->findCustomIcon(data.data);
                if (mapped.isNull()) mapped = QUuid::createUuid();
            }
            if (!db->metadata()->hasCustomIcon(mapped)) db->metadata()->addCustomIcon(mapped, data);
            icons.insert(original, mapped);
        }
        if (!pending.sourceGroup.isEmpty()) {
            auto* copy = children.first()->clone(Entry::CloneCopy);
            freshIds(copy, db.data()); remapIcons(copy, icons);
            copy->setParent(group, pending.position); importedRoot = uid(copy->uuid());
            for (const auto* item : copy->entriesRecursive()) imported.append(uid(item->uuid()));
            for (const auto* item : copy->groupsRecursive(true)) importedGroups.append(uid(item->uuid()));
        } else for (const auto* original : capsule->rootGroup()->entries()) {
            auto* copy = original->clone(Entry::CloneCopy);
            while (db->rootGroup()->findEntryByUuid(copy->uuid())) {
                delete copy; copy = original->clone(Entry::CloneCopy);
            }
            QList<Entry*> versions = copy->historyItems(); versions.append(copy);
            for (auto* version : versions) if (icons.contains(version->iconUuid())) {
                version->setUpdateTimeinfo(false); version->setIcon(icons.value(version->iconUuid())); version->setUpdateTimeinfo(true);
            }
            copy->setGroup(group); imported.append(uid(copy->uuid()));
        }
    });
    // fingerprint refers to Engine's staged-output hash, updated by commit; never certify an external writer's replacement.
    if (digest(db->filePath()) != fingerprint) reject("conflict", "The destination changed immediately after saving. Source entries were kept.");
    const auto receipt = QJsonDocument(QJsonObject{{"token", id}, {"source_token", pending.sourceToken},
        {"path", db->filePath()}, {"hash", QString::fromLatin1(fingerprint.toHex())}, {"count", imported.size()},
        {"groups", importedGroups.size()}}).toJson(QJsonDocument::Compact);
    // Once saved, a lost acknowledgement must not be reported as an unsaved destination.
    bool acknowledged = true;
    try { channel.number(receipt.size()); channel.write(receipt); } catch (const TransferFailure&) { acknowledged = false; }
    return {{"saved", true}, {"entries", imported}, {"groups", importedGroups}, {"root_group", importedRoot}, {"acknowledged", acknowledged}};
}
QJsonObject KeyslotTransfer::finish(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint, const Commit& commit) {
    const auto id = text(args, "token", 64);
    if (!sources.contains(id)) reject("expired", "The source transfer approval is unavailable.");
    const auto pending = sources.take(id);
    if (pending.database.toStrongRef() != db || pending.fingerprint != fingerprint || pending.expires < clock.elapsed() || !pending.delivered)
        reject("expired", "The source changed or its saved destination was not acknowledged. Source entries were kept.");
    if (digest(pending.destination) != pending.destinationHash)
        reject("conflict", "The saved destination changed. Source entries were kept.");
    if (pending.move) commit([&] {
        if (!pending.sourceGroup.isEmpty()) {
            auto* group = transferGroup(db.data(), pending.sourceGroup);
            if (db->metadata()->recycleBin() && group->groupsRecursive(true).contains(db->metadata()->recycleBin()))
                db->metadata()->setRecycleBin(nullptr);
            delete group;
        }
        else for (auto* entry : entries(db.data(), pending.entries)) delete entry;
    });
    return {{"moved", pending.move}, {"copied", true}, {"count", pending.entries.size()}};
}
QJsonObject KeyslotTransfer::local(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint, const Commit& commit) {
    const auto id = text(args, "token", 64);
    if (!sources.contains(id)) reject("expired", "The entry transfer approval is unavailable.");
    const auto pending = sources.take(id);
    if (pending.database.toStrongRef() != db || pending.fingerprint != fingerprint || pending.expires < clock.elapsed() || pending.started)
        reject("expired", "The entry transfer approval expired or the vault changed.");
    auto* target = findGroup(db.data(), text(args, "group", 64));
    Group* sourceGroup = pending.sourceGroup.isEmpty() ? nullptr : transferGroup(db.data(), pending.sourceGroup);
    if (sourceGroup && sourceGroup->findGroupByUuid(target->uuid()))
        reject("invalid_request", "A group cannot be copied or moved inside itself.");
    auto insertion = position(args, target, sourceGroup != nullptr);
    if (sourceGroup && pending.move && sourceGroup->parentGroup() == target && insertion >= 0
        && insertion > target->children().indexOf(sourceGroup)) --insertion;
    QJsonArray result, resultGroups;
    QString root;
    commit([&] {
      if (sourceGroup) {
        auto* copy = pending.move ? sourceGroup : sourceGroup->clone(Entry::CloneCopy);
        if (!pending.move) freshIds(copy, db.data());
        copy->setParent(target, insertion); root = uid(copy->uuid());
        for (const auto* item : copy->entriesRecursive()) result.append(uid(item->uuid()));
        for (const auto* item : copy->groupsRecursive(true)) resultGroups.append(uid(item->uuid()));
      } else for (auto* original : entries(db.data(), pending.entries)) {
        auto* entry = pending.move ? original : original->clone(Entry::CloneCopy);
        entry->setGroup(target); result.append(uid(entry->uuid()));
    }});
    return {{"moved", pending.move}, {"copied", true}, {"entries", result}, {"groups", resultGroups}, {"root_group", root}, {"count", result.size()}};
}
void KeyslotTransfer::cancel(const QJsonObject& args) {
    const auto id = text(args, "token", 64);
    sources.remove(id); destinations.remove(id);
}
