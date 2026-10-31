// SPDX-License-Identifier: GPL-3.0-only
#include "KeyslotIcons.h"
#include "core/Clock.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "core/UrlTools.h"
#include <QHostAddress>
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
}

void KeyslotIcons::require(const Ticket& ticket, const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision) {
    if (ticket.token.isEmpty() || text(args, "token") != ticket.token || ticket.database.toStrongRef() != db || ticket.revision != revision)
        fail("conflict", "The database changed or this icon review ended. Start again.");
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
    const auto raw = text(args, "url").trimmed();
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
    return {{"token", m_download.token}, {"urls", contacts}, {"timeout", int(timeout)}, {"insecure", url.scheme() == "http"}};
}
QJsonObject KeyslotIcons::progress() const {
    QJsonObject result{{"ready", !m_png.isEmpty()}, {"attempts", m_tried}, {"remaining", m_candidates.size()}};
    if (!m_png.isEmpty()) result.insert("preview", QString::fromLatin1(m_png.toBase64()));
    return result;
}
QJsonObject KeyslotIcons::step(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision) {
    require(m_download, db, args, revision);
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
    require(m_download, db, args, revision);
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
    require(m_download, db, args, revision);
    if (m_png.isEmpty()) fail("invalid_request", "Download and preview an icon before adding it.");
    const auto png = m_png, name = m_name.toUtf8();
    auto id = db->metadata()->findCustomIcon(png);
    if (id.isNull()) {
        id = QUuid::createUuid();
        commit([&] { db->metadata()->addCustomIcon(id, png, QString::fromUtf8(name), Clock::currentDateTimeUtc()); });
    }
    cancel(m_download.token);
    return uid(id);
}
void KeyslotIcons::cancel(const QString& token) {
    if (token == m_unused.token) { m_unused = {}; m_remove.clear(); m_keep.clear(); }
    if (token == m_download.token) {
        m_download = {}; m_candidates.clear(); m_visited.clear(); m_png.clear(); m_name.clear();
        m_clock.invalidate(); m_tried = 0; m_waiting = false; m_request.clear(); m_current = {};
    }
}
void KeyslotIcons::clear() { cancel(m_unused.token); cancel(m_download.token); }
