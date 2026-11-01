// SPDX-License-Identifier: GPL-3.0-only
#include "KeyslotProperties.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "core/CustomData.h"
#include <QCryptographicHash>
#include <QFile>
#include <QJsonArray>
#include <cmath>
#include <fcntl.h>
#include <unistd.h>

namespace {
[[noreturn]] void fail(const char* code, const char* message) { throw KeyslotProperties::Failure{code, message}; }
QString text(const QJsonObject& args, const char* key, int limit = 32768) {
    const auto value = args.value(key);
    if (!value.isString() || value.toString().size() > limit) fail("invalid_request", "A property request contains an invalid text field.");
    return value.toString();
}
int offset(const QJsonObject& args) {
    if (!args.contains("offset")) return 0;
    const auto value = args.value("offset"); const auto n = value.toDouble(-1);
    if (!value.isDouble() || !std::isfinite(n) || std::floor(n) != n || n < 0 || n > 1000000000)
        fail("invalid_request", "Choose a valid plugin-data page.");
    return int(n);
}
QString date(const QDateTime& time) { return time.isValid() ? time.toUTC().toString(Qt::ISODateWithMs) : QString(); }
QString id(const QUuid& value) { return value.isNull() ? QString() : value.toString(QUuid::WithoutBraces); }
struct Target {
    Entry* entry = nullptr;
    Group* group = nullptr;
    CustomData* data() const { return entry ? entry->customData() : group->customData(); }
    const TimeInfo& time() const { return entry ? entry->timeInfo() : group->timeInfo(); }
    QString name() const {
        return entry ? (entry->attributes()->isProtected(EntryAttributes::TitleKey) ? QStringLiteral("Protected Entry") : entry->title()) : group->name();
    }
};
Target find(const QSharedPointer<Database>& db, const QJsonObject& args) {
    if (args.contains("entry") == args.contains("group")) fail("invalid_request", "Choose exactly one entry or group.");
    const bool isEntry = args.contains("entry");
    const QUuid uuid(text(args, isEntry ? "entry" : "group", 128));
    if (uuid.isNull()) fail("invalid_request", "Choose a valid entry or group.");
    Target result;
    int matches = 0;
    if (isEntry) {
        for (auto* entry : db->rootGroup()->entriesRecursive())
            if (entry->uuid() == uuid) { result.entry = entry; ++matches; }
    } else {
        for (auto* group : db->rootGroup()->groupsRecursive(true))
            if (group->uuid() == uuid) { result.group = group; ++matches; }
    }
    if (matches != 1) fail("not_found", "The entry or group is missing or its identifier is ambiguous. Refresh before continuing.");
    return result;
}
QByteArray fingerprint(const CustomData* data, const QString& name) {
    if (!data->contains(name)) fail("conflict", "Selected plugin data no longer exists. Review it again.");
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(data->value(name).toUtf8()); hash.addData("\0", 1); hash.addData(date(data->lastModified(name)).toUtf8());
    return hash.result();
}
void revision(const QJsonObject& args, const QByteArray& current) {
    if (text(args, "revision", 128) != QString::fromLatin1(current.toHex()))
        fail("conflict", "The vault changed after properties were opened. Refresh the properties first.");
}
}

QJsonObject KeyslotProperties::info(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& current) {
    const auto item = find(db, args);
    const auto& time = item.time();
    QJsonObject result{{"revision", QString::fromLatin1(current.toHex())}, {"name", item.name()},
        {"uuid", id(item.entry ? item.entry->uuid() : item.group->uuid())},
        {"uuid_hex", QString::fromLatin1((item.entry ? item.entry->uuid() : item.group->uuid()).toRfc4122().toHex())},
        {"created", date(time.creationTime())}, {"modified", date(time.lastModificationTime())},
        {"accessed", date(time.lastAccessTime())}, {"location_changed", date(time.locationChanged())},
        {"expiry", date(time.expiryTime())}, {"expires", time.expires()}, {"usage_count", time.usageCount()},
        {"recycled", item.entry ? item.entry->isRecycled() : item.group->isRecycled()},
        {"parent", id(item.entry ? item.entry->group()->uuid() : item.group->parentGroup() ? item.group->parentGroup()->uuid() : QUuid())},
        {"previous_parent", id(item.entry ? item.entry->previousParentGroupUuid() : item.group->previousParentGroupUuid())}};
    if (item.entry) result.insert("history", item.entry->historyItems().size());
    else {
        result.insert("entries", item.group->entries().size()); result.insert("entries_recursive", item.group->entriesRecursive().size());
        result.insert("groups", item.group->children().size()); result.insert("groups_recursive", item.group->groupsRecursive(false).size());
    }
    const auto query = args.contains("query") ? text(args, "query", 1024) : QString();
    auto keys = item.data()->keys(); keys.sort(Qt::CaseSensitive);
    QStringList matching;
    int omitted = 0;
    for (const auto& key : keys) {
        if (key.size() > 32768) { ++omitted; continue; }
        if (key.contains(query, Qt::CaseInsensitive)) matching.append(key);
    }
    const auto start = offset(args);
    QJsonArray rows;
    for (int i = start; i < matching.size() && rows.size() < 100; ++i) {
        const auto& name = matching[i];
        rows.append(QJsonObject{{"name", name}, {"characters", item.data()->value(name).size()},
            {"modified", date(item.data()->lastModified(name))},
            {"automatic", item.data()->isAutoGenerated(name)}, {"protected", item.data()->isProtected(name)}});
    }
    result.insert("plugin_data", rows); result.insert("total", matching.size()); result.insert("omitted", omitted);
    return result;
}
QJsonObject KeyslotProperties::value(const QSharedPointer<Database>& db, const QJsonObject& args) {
    const auto item = find(db, args); const auto name = text(args, "name");
    if (!item.data()->contains(name)) fail("not_found", "This plugin data no longer exists. Refresh properties.");
    const auto value = item.data()->value(name);
    if (args.contains("path")) {
        const auto path = text(args, "path", 65536);
        if (path.isEmpty() || path.contains(QChar(0))) fail("invalid_request", "Choose an export file.");
        // Create plaintext with owner-only permissions from the first instant, before writing any value.
        const auto descriptor = ::open(QFile::encodeName(path).constData(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (descriptor < 0) fail("file_error", "The plugin-data export could not be created. Choose a new file.");
        QFile output;
        if (!output.open(descriptor, QIODevice::WriteOnly, QFileDevice::AutoCloseHandle)) {
            ::close(descriptor); fail("file_error", "The plugin-data export could not be opened. An empty file may remain.");
        }
        const auto bytes = value.toUtf8();
        if (output.write(bytes) != bytes.size() || !output.flush() || ::fsync(output.handle()) != 0)
            fail("file_error", "The plugin-data export could not be written completely. A partial file may remain.");
        return {{"exported", true}};
    }
    if (value.size() > 1048576) fail("invalid_request", "This value is too large to display or copy safely. Export it to inspect the complete value.");
    return {{"value", value}};
}
QJsonObject KeyslotProperties::review(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& current) {
    revision(args, current);
    const auto item = find(db, args);
    if (!args.value("names").isArray() || args.value("names").toArray().isEmpty() || args.value("names").toArray().size() > 256)
        fail("invalid_request", "Select between one and 256 plugin-data items to remove.");
    QMap<QString, QByteArray> selected;
    for (const auto& value : args.value("names").toArray()) {
        if (!value.isString() || value.toString().size() > 32768 || selected.contains(value.toString()))
            fail("invalid_request", "Select each plugin-data item once.");
        selected.insert(value.toString(), fingerprint(item.data(), value.toString()));
    }
    clear(); database = db; reviewedRevision = current; fingerprints = selected;
    target.insert(item.entry ? "entry" : "group", args.value(item.entry ? "entry" : "group"));
    token = QUuid::createUuid().toString(QUuid::WithoutBraces); expires = clock.elapsed() + 120000;
    return {{"token", token}, {"names", QJsonArray::fromStringList(selected.keys())}, {"name", item.name()},
        {"entry", bool(item.entry)}, {"history", bool(item.entry)}};
}
void KeyslotProperties::remove(const QSharedPointer<Database>& db, const QJsonObject& args,
    const QByteArray& current, const Commit& commit) {
    if (token.isEmpty() || text(args, "token", 128) != token || database.toStrongRef() != db || current != reviewedRevision || clock.elapsed() >= expires)
        fail("conflict", "The plugin-data review changed or expired. Review the removal again.");
    const auto request = target; const auto selected = fingerprints;
    clear();
    if (args.value("approved") != QJsonValue(true)) return;
    const auto item = find(db, request);
    for (auto it = selected.cbegin(); it != selected.cend(); ++it)
        if (fingerprint(item.data(), it.key()) != it.value()) fail("conflict", "Selected plugin data changed after review. Nothing was removed.");
    commit([&] {
        if (item.entry) item.entry->beginUpdate();
        for (auto it = selected.cbegin(); it != selected.cend(); ++it) item.data()->remove(it.key());
        if (item.entry) item.entry->endUpdate();
    });
}
void KeyslotProperties::cancel(const QString& value) { if (value == token) clear(); }
void KeyslotProperties::clear() { database.clear(); target = {}; fingerprints.clear(); reviewedRevision.clear(); token.clear(); expires = 0; }
