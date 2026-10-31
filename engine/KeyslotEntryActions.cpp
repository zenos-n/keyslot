// SPDX-License-Identifier: GPL-3.0-only
#include "KeyslotEntryActions.h"
#include "core/Clock.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/EntryAttributes.h"
#include "core/Group.h"
#include <QHash>
#include <QDateTime>
#include <QJsonArray>
#include <QSet>
#include <QUuid>
#include <memory>

namespace {
[[noreturn]] void fail(const char* code, const char* message) { throw KeyslotEntryActions::Failure{code, message}; }
QString text(const QJsonObject& args, const char* key) {
    if (!args.value(key).isString() || args.value(key).toString().contains(QChar('\0')))
        fail("invalid_request", "An entry action parameter is invalid.");
    return args.value(key).toString();
}
bool flag(const QJsonObject& args, const char* key) {
    if (!args.value(key).isBool()) fail("invalid_request", "An entry action switch is invalid.");
    return args.value(key).toBool();
}
QList<Entry*> selected(Database* db, const QJsonObject& args) {
    if (!args.value("entries").isArray() || args.value("entries").toArray().isEmpty())
        fail("invalid_request", "Select entries first.");
    QHash<QUuid, Entry*> index;
    QSet<QUuid> duplicate, seen;
    for (auto* entry : db->rootGroup()->entriesRecursive()) {
        if (index.contains(entry->uuid())) duplicate.insert(entry->uuid());
        index.insert(entry->uuid(), entry);
    }
    QList<Entry*> result;
    for (const auto& value : args.value("entries").toArray()) {
        const QUuid id(value.toString());
        if (!value.isString() || id.isNull() || duplicate.contains(id) || seen.contains(id))
            fail("invalid_request", "Select each unambiguous entry once.");
        auto* entry = index.value(id);
        if (!entry || entry->isRecycled()) fail("not_found", "A selected entry is missing or recycled.");
        seen.insert(id); result.append(entry);
    }
    return result;
}
bool changes(const Entry* entry, const QJsonObject& request) {
    const auto action = text(request, "action");
    if (action == "tag") return entry->tagList().contains(text(request, "tag")) != flag(request, "add");
    if (action == "expiry") {
        if (text(request, "mode") == "never") return entry->timeInfo().expires();
        return !entry->timeInfo().expires() || entry->timeInfo().expiryTime() != QDateTime::fromString(text(request, "at"), Qt::ISODateWithMs);
    }
    return true;
}
}

QJsonObject KeyslotEntryActions::review(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision) {
    cancel(m_token);
    auto request = args;
    const auto entries = selected(db.data(), request);
    const auto action = text(request, "action");
    if (action == "tag") {
        const auto tag = text(request, "tag").trimmed();
        if (tag.isEmpty() || tag.contains(',') || tag.contains(';') || tag.contains('\t'))
            fail("invalid_request", "Enter one nonempty tag without a comma, semicolon or tab.");
        request.insert("tag", tag); flag(request, "add");
    } else if (action == "expiry") {
        const auto mode = text(request, "mode");
        if (mode != "never" && mode != "now" && mode != "at") fail("invalid_request", "Choose a supported expiry action.");
        if (mode != "never") {
            const auto at = mode == "now" ? Clock::currentDateTimeUtc() : QDateTime::fromString(text(request, "at"), Qt::ISODateWithMs);
            if (!at.isValid()) fail("invalid_request", "Enter a valid ISO 8601 expiry timestamp.");
            request.insert("at", at.toUTC().toString(Qt::ISODateWithMs));
        }
    } else if (action == "duplicate") {
        if (entries.size() != 1) fail("invalid_request", "Select one entry to duplicate.");
        flag(request, "rename"); flag(request, "references"); flag(request, "history");
    } else fail("invalid_request", "Choose a supported entry action.");
    QJsonArray names;
    int count = 0;
    for (const auto* entry : entries) {
        if (changes(entry, request)) ++count;
        if (names.size() < 12) names.append(entry->attributes()->isProtected(EntryAttributes::TitleKey) ? QStringLiteral("Protected Entry") : entry->title());
    }
    m_database = db; m_revision = revision; m_request = request;
    m_token = QUuid::createUuid().toString(QUuid::WithoutBraces); m_expires = m_clock.elapsed() + 120000;
    return {{"token", m_token}, {"count", entries.size()}, {"changes", count}, {"names", names},
            {"action", action}, {"tag", request.value("tag")}, {"add", request.value("add")},
            {"mode", request.value("mode")}, {"at", request.value("at")},
            {"rename", request.value("rename")}, {"references", request.value("references")}, {"history", request.value("history")}};
}

QString KeyslotEntryActions::apply(const QSharedPointer<Database>& db, const QJsonObject& args,
                                   const QByteArray& revision, const Commit& commit) {
    if (m_token.isEmpty() || text(args, "token") != m_token || m_database.toStrongRef() != db
        || m_revision != revision || m_clock.elapsed() >= m_expires)
        fail("conflict", "The selection changed or its review expired. Review the entry action again.");
    const auto request = m_request;
    cancel(m_token);
    if (!flag(args, "approved")) return {};
    const auto entries = selected(db.data(), request);
    QList<Entry*> changed;
    for (auto* entry : entries) if (changes(entry, request)) changed.append(entry);
    QString created;
    if (!changed.isEmpty()) commit([&] {
        const auto action = text(request, "action");
        if (action == "duplicate") {
            Entry::CloneFlags flags = Entry::CloneDefault;
            if (flag(request, "rename")) flags |= Entry::CloneRenameTitle;
            if (flag(request, "references")) flags |= Entry::CloneUserAsRef | Entry::ClonePassAsRef;
            if (flag(request, "history")) flags |= Entry::CloneIncludeHistory;
            std::unique_ptr<Entry> copy(changed.first()->clone(flags));
            if (copy->uuid().isNull() || db->rootGroup()->findEntryByUuid(copy->uuid()))
                fail("conflict", "A unique identifier could not be allocated for the duplicate.");
            copy->setGroup(changed.first()->group());
            created = copy->uuid().toString(QUuid::WithoutBraces);
            copy.release();
        } else for (auto* entry : changed) {
            entry->beginUpdate();
            if (action == "tag") {
                if (flag(request, "add")) entry->addTag(text(request, "tag"));
                else entry->removeTag(text(request, "tag"));
            } else if (text(request, "mode") == "never") entry->setExpires(false);
            else {
                entry->setExpiryTime(QDateTime::fromString(text(request, "at"), Qt::ISODateWithMs));
                entry->setExpires(true);
            }
            entry->endUpdate();
        }
    });
    return created;
}
void KeyslotEntryActions::cancel(const QString& token) {
    if (token == m_token) { m_database.clear(); m_revision.clear(); m_request = {}; m_token.clear(); m_expires = 0; }
}
