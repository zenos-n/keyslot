// SPDX-License-Identifier: GPL-3.0-only
#include "KeyslotIcons.h"
#include "core/Clock.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "core/UrlTools.h"
#include <QHostAddress>
#include <QHash>
#include <QJsonArray>
#include <cmath>

namespace {
[[noreturn]] void fail(const QString& code, const QString& message) { throw KeyslotIcons::Failure{code, message}; }
QString text(const QJsonObject& args, const char* key) {
    if (!args.value(key).isString()) fail("invalid_request", "An icon parameter is invalid.");
    return args.value(key).toString();
}
bool flag(const QJsonObject& args, const char* key) {
    if (!args.contains(key)) return false;
    if (!args.value(key).isBool()) fail("invalid_request", "An icon option is invalid.");
    return args.value(key).toBool();
}
QString uid(const QUuid& value) { return value.toString(QUuid::WithoutBraces); }
QSet<QUuid> used(Database* db) {
    QSet<QUuid> result;
    for (const auto* entry : db->rootGroup()->entriesRecursive(true)) result.insert(entry->iconUuid());
    for (const auto* group : db->rootGroup()->groupsRecursive(true)) result.insert(group->iconUuid());
    return result;
}
Entry* target(Database* db, const QUuid& id) {
    Entry* result = nullptr;
    for (auto* entry : db->rootGroup()->entriesRecursive()) if (entry->uuid() == id) {
        if (result) fail("conflict", "The website icon target is ambiguous.");
        result = entry;
    }
    if (!result || result->isRecycled()) fail("not_found", "The website icon entry is no longer available.");
    return result;
}
QJsonObject groupRequest(Database* db, const QJsonObject& args) {
    const auto id = QUuid(text(args, "group"));
    const auto customText = text(args, "custom_icon");
    const auto custom = QUuid(customText);
    const auto icon = args.value("icon"), scope = args.value("icon_scope");
    if (id.isNull() || (!customText.isEmpty() && (custom.isNull() || !db->metadata()->hasCustomIcon(custom)))
        || !icon.isDouble() || std::floor(icon.toDouble()) != icon.toDouble() || icon.toDouble() < 0 || icon.toDouble() > 68
        || !scope.isDouble() || std::floor(scope.toDouble()) != scope.toDouble() || scope.toDouble() < 1 || scope.toDouble() > 3)
        fail("invalid_request", "Choose a current group, icon and child icon scope.");
    return {{"group", uid(id)}, {"custom_icon", customText.isEmpty() ? QString() : uid(custom)},
            {"icon", icon.toInt()}, {"icon_scope", scope.toInt()}};
}
template <typename T> bool differentIcon(const T* item, int icon, const QUuid& custom) {
    return custom.isNull() ? !item->iconUuid().isNull() || item->iconNumber() != icon : item->iconUuid() != custom;
}
}

void KeyslotIcons::require(const Ticket& ticket, const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision) {
    if (ticket.token.isEmpty() || text(args, "token") != ticket.token || ticket.database.toStrongRef() != db || ticket.revision != revision)
        fail("conflict", "The database changed or this icon review ended. Start again.");
}
void KeyslotIcons::requireDownload(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision) const {
    require(m_download, db, args, m_entry.isNull() ? revision : m_download.revision);
    if (!m_entry.isNull()) {
        const auto* entry = target(db.data(), m_entry);
        if (entry->url() != m_entryUrl || entry->iconUuid() != m_entryIcon || entry->iconNumber() != m_entryStandardIcon)
            fail("conflict", "The entry website or icon changed. Its current icon was kept.");
    }
}
QString KeyslotIcons::reserve(const QSharedPointer<Database>& db, const QString& identifier) {
    for (auto it = m_reservations.begin(); it != m_reservations.end();) {
        if (it->database.isNull()) it = m_reservations.erase(it); else ++it;
    }
    if (m_reservations.size() >= 128) return {};
    const auto* entry = target(db.data(), QUuid(identifier));
    const auto token = uid(QUuid::createUuid());
    m_reservations.insert(token, {db, entry->uuid(), entry->iconUuid(), entry->url(), entry->iconNumber()});
    return token;
}
QJsonObject KeyslotIcons::reviewGroup(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision) {
    cancel(m_group.token);
    const auto request = groupRequest(db.data(), args);
    const auto id = QUuid(request.value("group").toString());
    QHash<QUuid, int> groups, entries;
    Group* source = nullptr;
    for (auto* item : db->rootGroup()->groupsRecursive(true)) {
        ++groups[item->uuid()];
        if (item->uuid() == id) source = item;
    }
    if (!source || groups.value(id) != 1) fail("conflict", "The group icon source is missing or ambiguous.");
    for (const auto* item : db->rootGroup()->entriesRecursive(false)) ++entries[item->uuid()];
    int changedGroups = 0, changedEntries = 0, recycledGroups = 0, recycledEntries = 0;
    const int scope = request.value("icon_scope").toInt(), icon = request.value("icon").toInt();
    const auto custom = QUuid(request.value("custom_icon").toString());
    if (scope & 1) for (const auto* item : source->groupsRecursive(false)) {
        if (item->uuid().isNull() || groups.value(item->uuid()) != 1)
            fail("conflict", "A child group icon target is ambiguous.");
        if (differentIcon(item, icon, custom)) { ++changedGroups; if (item->isRecycled()) ++recycledGroups; }
    }
    if (scope & 2) for (const auto* item : source->entriesRecursive(false)) {
        if (item->uuid().isNull() || entries.value(item->uuid()) != 1)
            fail("conflict", "A child entry icon target is ambiguous.");
        if (differentIcon(item, icon, custom)) { ++changedEntries; if (item->isRecycled()) ++recycledEntries; }
    }
    m_groupRequest = request;
    m_group = {db, revision, uid(QUuid::createUuid())};
    m_groupClock.start();
    return {{"token", m_group.token}, {"groups", changedGroups}, {"entries", changedEntries},
            {"recycled_groups", recycledGroups}, {"recycled_entries", recycledEntries}};
}
void KeyslotIcons::confirmGroup(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision) {
    auto tokenArgs = args;
    tokenArgs.insert("token", text(args, "icon_review"));
    require(m_group, db, tokenArgs, revision);
    if (!m_groupClock.isValid() || m_groupClock.elapsed() >= 120000 || groupRequest(db.data(), args) != m_groupRequest)
        fail("conflict", "The group icon review expired or the chosen group, icon or scope changed. Review again.");
    cancel(m_group.token);
}
void KeyslotIcons::applyGroupChildren(Group* group, int scope) {
    const int icon = group->iconNumber();
    const auto custom = group->iconUuid();
    if (scope & 1) for (auto* item : group->groupsRecursive(false))
        if (differentIcon(item, icon, custom)) group->applyGroupIconTo(item);
    if (scope & 2) for (auto* item : group->entriesRecursive(false)) if (differentIcon(item, icon, custom)) {
        item->beginUpdate();
        group->applyGroupIconTo(item);
        item->endUpdate();
    }
}
QJsonObject KeyslotIcons::reviewUnused(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision) {
    m_unused = {}; m_remove.clear(); m_keep.clear();
    if (!args.value("keep").isArray()) fail("invalid_request", "Specify draft icons to retain.");
    for (const auto& value : args.value("keep").toArray()) {
        const QUuid id(value.toString());
        if (!value.isString() || id.isNull()) fail("invalid_request", "A draft icon identifier is invalid.");
        m_keep.insert(id);
    }
    const auto references = used(db.data()) + m_keep;
    QJsonArray names;
    for (const auto& id : db->metadata()->customIconsOrder()) if (!references.contains(id)) {
        m_remove.append(id);
        if (names.size() < 12) names.append(db->metadata()->customIcon(id).name);
    }
    m_unused = {db, revision, uid(QUuid::createUuid())};
    return {{"token", m_unused.token}, {"count", m_remove.size()}, {"names", names}};
}
void KeyslotIcons::removeUnused(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision, const Commit& commit) {
    require(m_unused, db, args, revision);
    const auto references = used(db.data()) + m_keep;
    for (const auto& id : m_remove) if (references.contains(id) || !db->metadata()->hasCustomIcon(id))
        fail("conflict", "The icon library changed. Review unused icons again.");
    const auto remove = m_remove;
    cancel(m_unused.token);
    if (!remove.isEmpty()) commit([&] { for (const auto& id : remove) db->metadata()->removeCustomIcon(id); });
}
QJsonObject KeyslotIcons::prepare(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision) {
    cancel(m_download.token);
    const auto reservation = args.contains("reservation") ? text(args, "reservation") : QString();
    if (!reservation.isEmpty()) {
        const auto found = m_reservations.constFind(reservation);
        if (found == m_reservations.cend() || found->database.toStrongRef() != db || found->entry != QUuid(text(args, "entry")))
            fail("conflict", "The saved entry's website icon request ended. Its current icon was kept.");
        const auto* entry = target(db.data(), found->entry);
        if (entry->url() != found->url || entry->iconUuid() != found->icon || entry->iconNumber() != found->standardIcon)
            fail("conflict", "The saved entry website or icon changed before download. Its current icon was kept.");
    }
    if (args.contains("entry")) {
        m_entry = QUuid(text(args, "entry"));
        if (m_entry.isNull()) fail("invalid_request", "Choose a valid website icon entry.");
        const auto* entry = target(db.data(), m_entry);
        m_entryUrl = entry->url(); m_entryIcon = entry->iconUuid(); m_entryStandardIcon = entry->iconNumber();
    }
    const auto raw = (m_entry.isNull() ? text(args, "url") : target(db.data(), m_entry)->url()).trimmed();
    if (raw.isEmpty() || raw.size() > 32767 || raw.contains(QChar('\0')) || raw.contains('{') || raw.contains('}'))
        fail("invalid_request", "Enter a website address without unresolved field placeholders.");
    auto url = QUrl::fromUserInput(raw);
    if (!raw.contains("://")) url.setScheme("https");
    if (!url.isValid() || url.host().isEmpty() || (url.scheme() != "https" && url.scheme() != "http"))
        fail("invalid_request", "Choose an HTTP or HTTPS website.");
    url.setUserInfo(QString()); url.setQuery(QString()); url.setFragment(QString());
    if (!flag(args, "path")) url.setPath(QString());
    const auto timeout = args.value("timeout").toDouble(-1);
    if (!std::isfinite(timeout) || std::floor(timeout) != timeout || timeout < 1 || timeout > 300)
        fail("invalid_request", "Choose a download timeout between 1 and 300 seconds.");
    m_timeout = int(timeout * 1000);
    QHostAddress address;
    const auto base = address.setAddress(url.host()) ? QString() : urlTools()->getBaseDomainFromUrl(url.toString());
    auto add = [&](QUrl candidate) {
        for (const auto& item : m_candidates) if (item.url == candidate) return;
        m_candidates.append({candidate, 0});
    };
    if (!url.path().isEmpty()) add(url.resolved(QUrl("./favicon.ico")));
    url.setPath("/favicon.ico"); add(url);
    if (!base.isEmpty() && base != url.host()) {
        auto parent = url; parent.setHost(base); add(parent);
        if (parent.port() != -1) { parent.setPort(-1); add(parent); }
    }
    if (flag(args, "fallback")) {
        auto service = QUrl("https://icons.duckduckgo.com");
        service.setPath("/ip3/" + url.host() + ".ico"); add(service);
        if (!base.isEmpty() && base != url.host()) { service.setPath("/ip3/" + base + ".ico"); add(service); }
    }
    QJsonArray contacts;
    for (const auto& candidate : m_candidates) contacts.append(candidate.url.toString(QUrl::FullyEncoded));
    m_name = url.host(); m_download = {db, revision, uid(QUuid::createUuid())};
    if (!reservation.isEmpty()) m_reservations.remove(reservation);
    return {{"token", m_download.token}, {"urls", contacts}, {"timeout", int(timeout)}, {"insecure", url.scheme() == "http"}};
}
QJsonObject KeyslotIcons::progress() const {
    QJsonObject result{{"ready", !m_png.isEmpty()}, {"attempts", m_tried}, {"remaining", m_candidates.size()}};
    if (!m_png.isEmpty()) result.insert("preview", QString::fromLatin1(m_png.toBase64()));
    return result;
}
QJsonObject KeyslotIcons::step(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision) {
    requireDownload(db, args, revision);
    if (!m_png.isEmpty()) return progress();
    if (!flag(args, "approved")) fail("denied", "Review and approve the website icon download first.");
    if (m_waiting) fail("invalid_request", "Finish decoding the current icon before downloading another.");
    if (!m_clock.isValid()) m_clock.start();
    if (m_candidates.isEmpty()) fail("icon_download", "No usable website icon was found. Try an image file or the optional icon service.");
    const int remaining = m_timeout - int(m_clock.elapsed());
    if (remaining <= 0) fail("icon_download", "The website icon download timed out. Start a new download to try again.");
    const auto candidate = m_candidates.takeFirst();
    const auto encoded = candidate.url.toString(QUrl::FullyEncoded);
    if (m_visited.contains(encoded)) return progress();
    m_visited.insert(encoded); ++m_tried;
    m_current = candidate; m_request = uid(QUuid::createUuid()); m_waiting = true;
    auto result = progress();
    result.insert("request", m_request); result.insert("url", encoded); result.insert("timeout", qMin(remaining, 15000));
    return result;
}
QJsonObject KeyslotIcons::accept(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision, const Normalize& normalize) {
    requireDownload(db, args, revision);
    if (!m_waiting || text(args, "request") != m_request) fail("conflict", "This icon download reply is no longer expected.");
    const auto candidate = m_current;
    m_waiting = false; m_request.clear();
    const auto status = args.value("status").toDouble(-1);
    if (!std::isfinite(status) || std::floor(status) != status || status < 0 || status > 599)
        fail("invalid_request", "The icon download status is invalid.");
    const auto redirect = text(args, "redirect");
    if (flag(args, "failed")) return progress();
    if (status >= 300 && status < 400 && !redirect.isEmpty()) {
        auto target = candidate.url.resolved(QUrl(redirect));
        target.setUserInfo(QString()); target.setFragment(QString());
        if (candidate.redirects < 5 && target.isValid() && !target.host().isEmpty()
            && (target.scheme() == "https" || (target.scheme() == "http" && candidate.url.scheme() == "http")))
            m_candidates.prepend({target, candidate.redirects + 1});
        return progress();
    }
    if (status != 200) return progress();
    const auto encoded = text(args, "data").toLatin1();
    if (encoded.size() > 12 * 1024 * 1024) fail("invalid_request", "The icon is too large.");
    if (!encoded.isEmpty()) {
        const auto raw = QByteArray::fromBase64(encoded, QByteArray::AbortOnBase64DecodingErrors);
        if (raw.toBase64() != encoded) fail("invalid_request", "The icon encoding is invalid.");
        m_png = normalize(raw);
    }
    return progress();
}
QString KeyslotIcons::finish(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision, const Commit& commit) {
    requireDownload(db, args, revision);
    if (m_png.isEmpty()) fail("invalid_request", "Download and preview an icon before adding it.");
    const auto png = m_png, name = m_name.toUtf8();
    auto* entry = m_entry.isNull() ? nullptr : target(db.data(), m_entry);
    auto id = db->metadata()->findCustomIcon(png);
    const bool add = id.isNull();
    if (add) id = QUuid::createUuid();
    if (add || entry) {
        commit([&] {
            if (add) db->metadata()->addCustomIcon(id, png, QString::fromUtf8(name), Clock::currentDateTimeUtc());
            if (entry) entry->setIcon(id);
        });
    }
    cancel(m_download.token);
    return uid(id);
}
void KeyslotIcons::cancel(const QString& token) {
    m_reservations.remove(token);
    if (token == m_group.token) { m_group = {}; m_groupRequest = {}; m_groupClock.invalidate(); }
    if (token == m_unused.token) { m_unused = {}; m_remove.clear(); m_keep.clear(); }
    if (token == m_download.token) {
        m_download = {}; m_candidates.clear(); m_visited.clear(); m_png.clear(); m_name.clear();
        m_clock.invalidate(); m_tried = 0; m_waiting = false; m_request.clear(); m_current = {}; m_entry = {};
        m_entryUrl.clear(); m_entryIcon = {}; m_entryStandardIcon = 0;
    }
}
void KeyslotIcons::clear() { cancel(m_unused.token); cancel(m_download.token); cancel(m_group.token); m_reservations.clear(); }
