// SPDX-License-Identifier: GPL-3.0-only
#include "KeyslotTrash.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/EntryAttributes.h"
#include "core/Group.h"
#include "core/Metadata.h"

#include <QHash>
#include <QJsonArray>
#include <QSet>
#include <QUuid>

namespace {
[[noreturn]] void reject(const QString& code, const QString& message) { throw KeyslotTrash::Failure{code, message}; }
QString text(const QJsonObject& args, const char* key) {
    if (!args.contains(key)) return {};
    if (!args.value(key).isString()) reject("invalid_request", "A recycle-bin parameter is invalid.");
    return args.value(key).toString();
}
bool within(const Group* group, const Group* ancestor) {
    for (auto* current = group; current; current = current->parentGroup()) if (current == ancestor) return true;
    return false;
}
struct Plan {
    bool restore = false;
    QList<Group*> groups, order;
    QList<Entry*> entries;
    QHash<Group*, bool> purgeGroups;
    QHash<Entry*, bool> purgeEntries;
    QHash<Group*, Group*> groupTargets;
    QHash<Entry*, Group*> entryTargets;
    int fallbacks = 0;
};
struct Index {
    QHash<QUuid, Group*> groups;
    QHash<QUuid, Entry*> entries;
    QSet<QUuid> duplicateGroups, duplicateEntries;
    explicit Index(Database* db) {
        for (auto* g : db->rootGroup()->groupsRecursive(true)) {
            if (groups.contains(g->uuid())) duplicateGroups.insert(g->uuid());
            groups.insert(g->uuid(), g);
        }
        for (auto* e : db->rootGroup()->entriesRecursive()) {
            if (entries.contains(e->uuid())) duplicateEntries.insert(e->uuid());
            entries.insert(e->uuid(), e);
        }
    }
    Group* group(const QUuid& id, bool optional = false) const {
        if (id.isNull() || duplicateGroups.contains(id) || !groups.contains(id)) {
            if (optional) return nullptr;
            reject("not_found", "A selected group is missing or its identifier is ambiguous.");
        }
        return groups.value(id);
    }
};
Plan plan(Database* db, const QJsonObject& request, const QString& destination = {}) {
    Plan result;
    const auto action = text(request, "action");
    if (!QStringList{"delete", "purge", "restore", "restore_all", "empty"}.contains(action))
        reject("invalid_request", "Choose a supported recycle-bin operation.");
    result.restore = action == "restore" || action == "restore_all";
    auto* root = db->rootGroup();
    auto* bin = db->metadata()->recycleBin();
    if (bin == root) reject("invalid_request", "The root group cannot be used as a recycle bin.");
    const Index index(db);
    for (const auto* name : {"entries", "groups"})
        if (request.contains(name) && !request.value(name).isArray()) reject("invalid_request", "Select items by identifier.");
    if (action == "empty" || action == "restore_all") {
        if (!request.value("entries").toArray().isEmpty() || !request.value("groups").toArray().isEmpty())
            reject("invalid_request", "Review the whole recycle bin without another selection.");
        if (bin) { result.groups = bin->children(); result.entries = bin->entries(); }
    } else {
        QSet<QUuid> groups, entries;
        for (const auto& value : request.value("groups").toArray()) {
            const QUuid id(value.toString());
            if (!value.isString() || id.isNull() || groups.contains(id)) reject("invalid_request", "Choose each group once.");
            groups.insert(id); result.groups.append(index.group(id));
        }
        for (const auto& value : request.value("entries").toArray()) {
            const QUuid id(value.toString());
            if (!value.isString() || id.isNull() || entries.contains(id) || index.duplicateEntries.contains(id))
                reject("invalid_request", "Choose each unambiguous entry once.");
            auto* entry = index.entries.value(id);
            if (!entry) reject("not_found", "A selected entry is no longer available.");
            entries.insert(id); result.entries.append(entry);
        }
        if (result.groups.isEmpty() && result.entries.isEmpty()) reject("invalid_request", "Select entries or groups first.");
    }
    const auto selectedGroups = result.groups;
    for (auto* group : selectedGroups) {
        if (group == root) reject("invalid_request", "The root group cannot be deleted or restored.");
        for (auto* other : selectedGroups) if (other != group && within(group, other)) {
            result.groups.removeOne(group); break;
        }
    }
    const auto selectedEntries = result.entries;
    for (auto* entry : selectedEntries)
        for (auto* group : result.groups) if (within(entry->group(), group)) { result.entries.removeOne(entry); break; }

    if (!result.restore) {
        const bool always = action == "purge" || action == "empty" || !db->metadata()->recycleBinEnabled();
        for (auto* group : result.groups) result.purgeGroups.insert(group, always || group->isRecycled() || (bin && within(bin, group)));
        for (auto* entry : result.entries) result.purgeEntries.insert(entry, always || entry->isRecycled());
        return result;
    }
    Group* explicitTarget = destination.isEmpty() ? nullptr : index.group(QUuid(destination));
    if (explicitTarget && explicitTarget->isRecycled()) reject("invalid_request", "Restore to a group outside the recycle bin.");
    auto owner = [&](Group* target) -> Group* {
        for (auto* group : result.groups) if (within(target, group)) return group;
        return nullptr;
    };
    for (auto* group : result.groups) {
        if (group == bin || !group->isRecycled()) reject("invalid_request", "Choose recycled groups, excluding the recycle bin itself.");
        auto* target = explicitTarget ? explicitTarget : index.group(group->previousParentGroupUuid(), true);
        if (!target || within(target, group) || (target->isRecycled() && !owner(target))) {
            target = root; ++result.fallbacks;
        }
        result.groupTargets.insert(group, target);
    }
    auto remaining = result.groups;
    QSet<Group*> ordered;
    while (!remaining.isEmpty()) {
        Group* next = nullptr;
        for (auto* group : remaining) {
            auto* dependency = owner(result.groupTargets.value(group));
            if (!dependency || ordered.contains(dependency)) { next = group; break; }
        }
        if (!next) {
            next = remaining.first(); result.groupTargets[next] = root; ++result.fallbacks;
        }
        remaining.removeOne(next); ordered.insert(next); result.order.append(next);
    }
    for (auto* entry : result.entries) {
        if (!entry->isRecycled()) reject("invalid_request", "Choose recycled entries to restore.");
        auto* target = explicitTarget ? explicitTarget : index.group(entry->previousParentGroupUuid(), true);
        if (!target || (target->isRecycled() && !owner(target))) { target = root; ++result.fallbacks; }
        result.entryTargets.insert(entry, target);
    }
    return result;
}
}

QJsonObject KeyslotTrash::review(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision)
{
    const auto selection = plan(db.data(), args);
    int recycleEntries = 0, purgeEntries = 0, recycleGroups = 0, purgeGroups = 0;
    QJsonArray names, destinations;
    for (auto* group : selection.groups) {
        const auto groups = group->groupsRecursive(true).size(), entries = group->entriesRecursive().size();
        if (selection.purgeGroups.value(group)) { purgeGroups += groups; purgeEntries += entries; }
        else { recycleGroups += groups; recycleEntries += entries; }
        if (names.size() < 12) names.append(group->fullPath());
    }
    for (auto* entry : selection.entries) {
        if (selection.purgeEntries.value(entry)) ++purgeEntries; else ++recycleEntries;
        if (names.size() < 12) names.append(entry->attributes()->isProtected(EntryAttributes::TitleKey) ? "Protected Entry" : entry->title());
    }
    if (selection.restore) {
        const Index index(db.data());
        for (auto* group : db->rootGroup()->groupsRecursive(true))
            if (!group->isRecycled() && !index.duplicateGroups.contains(group->uuid())) destinations.append(QJsonObject{
                {"id", group->uuid().toString(QUuid::WithoutBraces)}, {"path", group->fullPath()}});
    }
    m_database = db; m_revision = revision; m_request = args;
    m_token = QUuid::createUuid().toString(QUuid::WithoutBraces);
    return {{"token", m_token}, {"restore", selection.restore}, {"entries", recycleEntries + purgeEntries},
        {"groups", recycleGroups + purgeGroups}, {"recycle_entries", recycleEntries}, {"recycle_groups", recycleGroups},
        {"purge_entries", purgeEntries}, {"purge_groups", purgeGroups}, {"names", names},
        {"destinations", destinations}, {"fallbacks", selection.fallbacks}, {"root", db->rootGroup()->fullPath()}};
}

void KeyslotTrash::apply(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision, const Commit& commit)
{
    if (text(args, "token") != m_token || m_token.isEmpty() || m_database.toStrongRef() != db || m_revision != revision)
        reject("conflict", "The reviewed selection changed or expired. Review it again before continuing.");
    const auto destination = text(args, "destination");
    const auto request = m_request;
    clear();
    const auto selection = plan(db.data(), request, destination);
    if (!selection.restore && !destination.isEmpty()) reject("invalid_request", "Deletion does not have a restore destination.");
    commit([&] {
        if (selection.restore) {
            for (auto* group : selection.order) group->setParent(selection.groupTargets.value(group));
            for (auto* entry : selection.entries) entry->setGroup(selection.entryTargets.value(entry));
        } else {
            // Delete the old bin before recycling other items, so they cannot be swept into its deletion.
            for (auto* entry : selection.entries) if (selection.purgeEntries.value(entry)) delete entry;
            for (auto* group : selection.groups) if (selection.purgeGroups.value(group)) delete group;
            for (auto* entry : selection.entries) if (!selection.purgeEntries.value(entry)) db->recycleEntry(entry);
            for (auto* group : selection.groups) if (!selection.purgeGroups.value(group)) db->recycleGroup(group);
        }
    });
}
void KeyslotTrash::cancel(const QString& token) { if (token == m_token) clear(); }
void KeyslotTrash::clear() { m_database.clear(); m_revision.clear(); m_request = {}; m_token.clear(); }
