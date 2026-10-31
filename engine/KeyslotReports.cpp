// SPDX-License-Identifier: GPL-3.0-only
#include "KeyslotReports.h"
#include "browser/BrowserService.h"
#include "core/CustomData.h"
#include "core/Database.h"
#include "core/DatabaseStats.h"
#include "core/Entry.h"
#include "core/EntryAttributes.h"
#include "core/Group.h"
#include "core/PasswordHealth.h"
#include <QCryptographicHash>
#include <QEventLoop>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSet>
#include <QTimer>
#include <algorithm>

namespace {
[[noreturn]] void fail(const QString& code, const QString& message) { throw KeyslotReports::Failure{code, message}; }
QString text(const QJsonObject& args, const char* key) {
    if (!args.value(key).isString()) fail("invalid_request", "A report parameter is invalid.");
    return args.value(key).toString();
}
bool flag(const QJsonObject& args, const char* key) {
    if (!args.contains(key)) return false;
    if (!args.value(key).isBool()) fail("invalid_request", "A report option is invalid.");
    return args.value(key).toBool();
}
QString uid(const QUuid& value) { return value.toString(QUuid::WithoutBraces); }
QJsonObject metadata(const Entry* entry) {
    return {{"uuid", uid(entry->uuid())}, {"title", entry->title()}, {"group", entry->group()->fullPath()},
            {"excluded", entry->excludeFromReports()}, {"expired", entry->isExpired()}};
}
QHash<QUuid, Entry*> uniqueEntries(Database* db) {
    QHash<QUuid, Entry*> result;
    for (auto* entry : db->rootGroup()->entriesRecursive()) {
        const auto id = entry->uuid();
        if (result.contains(id)) result[id] = nullptr; else result[id] = entry;
    }
    return result;
}
QHash<QByteArray, qint64> parse(const QByteArray& bytes, int length) {
    static const QRegularExpression linePattern("^[0-9A-Fa-f]+:[0-9]{1,10}$");
    QHash<QByteArray, qint64> result;
    for (auto line : bytes.split('\n')) {
        if (line.endsWith('\r')) line.chop(1);
        if (line.isEmpty()) continue;
        if (line.size() < length + 2 || line.at(length) != ':'
            || !linePattern.match(QString::fromLatin1(line)).hasMatch())
            fail("report_format", "The password-hash data is malformed or uses an unsupported format.");
        const auto hash = line.left(length).toUpper();
        const auto count = line.mid(length + 1).toLongLong();
        result[hash] = std::max(count, result.value(hash));
    }
    if (result.isEmpty()) fail("report_format", "The password-hash data is empty; no clean result can be established.");
    return result;
}
QByteArray download(const QString& prefix) {
    constexpr int Limit = 1024 * 1024;
    QNetworkAccessManager manager;
    QNetworkRequest request(QUrl("https://api.pwnedpasswords.com/range/" + prefix));
    request.setRawHeader("User-Agent", "Keyslot");
    request.setRawHeader("Add-Padding", "true");
    request.setRawHeader("Accept", "text/plain");
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    request.setAttribute(QNetworkRequest::CacheSaveControlAttribute, false);
    request.setAttribute(QNetworkRequest::CookieLoadControlAttribute, QNetworkRequest::Manual);
    request.setAttribute(QNetworkRequest::CookieSaveControlAttribute, QNetworkRequest::Manual);
    auto* reply = manager.get(request);
    reply->setReadBufferSize(Limit + 1);
    QByteArray bytes;
    bool oversized = false, timedOut = false;
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    auto receive = [&] {
        bytes += reply->read(Limit + 1 - bytes.size());
        if (bytes.size() > Limit) { oversized = true; reply->abort(); }
    };
    QObject::connect(reply, &QIODevice::readyRead, &loop, receive);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, [&] { timedOut = true; reply->abort(); loop.quit(); });
    timer.start(15000);
    if (!reply->isFinished()) loop.exec();
    receive();
    if (oversized) fail("report_network", "HIBP returned too much data. The check was not completed.");
    if (timedOut) fail("report_network", "HIBP did not respond in time. Retry to continue the incomplete check.");
    if (reply->error() != QNetworkReply::NoError || reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() != 200)
        fail("report_network", "HIBP could not be reached securely or refused the request. Retry later; the check is incomplete.");
    return bytes;
}
}

QJsonObject KeyslotReports::inventory(const QSharedPointer<Database>& db, bool excluded, const QByteArray& revision)
{
    auto borrowed = db;
    DatabaseStats stats(borrowed);
    HealthChecker checker(borrowed);
    QJsonArray health, browser, duplicates;
    QHash<QString, QJsonArray> reused;
    int passkeys = 0, totp = 0;
    for (const auto* entry : db->rootGroup()->entriesRecursive()) {
        if (entry->isRecycled()) continue;
        if (entry->hasPasskey()) ++passkeys;
        if (entry->hasTotp()) ++totp;
        if (entry->excludeFromReports() && !excluded) continue;
        auto item = metadata(entry);
        const auto quality = checker.evaluate(entry);
        if (quality) {
            auto row = item;
            row.insert("score", quality->score()); row.insert("quality", static_cast<int>(quality->quality()));
            row.insert("entropy", quality->entropy()); row.insert("reason", quality->scoreReason());
            row.insert("details", quality->scoreDetails()); health.append(row);
        }
        if (!entry->password().isEmpty() && !entry->isAttributeReference("Password")) reused[entry->password()].append(item);
        QJsonArray urls;
        int hidden = 0;
        for (const auto& key : entry->attributes()->keys()) {
            if (key != EntryAttributes::URLKey && !key.startsWith(EntryAttributes::AdditionalUrlAttribute)
                && key != QString("%1_RELYING_PARTY").arg(EntryAttributes::PasskeyAttribute)) continue;
            const auto value = entry->attributes()->value(key);
            if (value.isEmpty()) continue;
            if (entry->attributes()->isProtected(key)) ++hidden; else urls.append(value);
        }
        const auto config = entry->customData()->value(BrowserService::KEEPASSXCBROWSER_NAME);
        QJsonParseError error;
        const auto document = QJsonDocument::fromJson(config.toUtf8(), &error);
        const auto settings = document.object();
        item.insert("urls", urls); item.insert("hidden_urls", hidden);
        item.insert("has_settings", entry->customData()->contains(BrowserService::KEEPASSXCBROWSER_NAME));
        bool invalid = !config.isEmpty() && (error.error != QJsonParseError::NoError || !document.isObject());
        for (const auto* name : {"Allow", "Deny"}) {
            QJsonArray values;
            if (settings.contains(name) && !settings.value(name).isArray()) invalid = true;
            for (const auto& value : settings.value(name).toArray()) {
                if (value.isString()) values.append(value); else invalid = true;
            }
            item.insert(name, values);
        }
        item.insert("invalid_settings", invalid);
        browser.append(item);
    }
    for (const auto& entries : reused) if (entries.size() > 1) duplicates.append(entries);
    return {{"revision", QString::fromLatin1(revision.toHex())}, {"groups", stats.groupCount}, {"entries", stats.entryCount},
        {"expired", stats.expiredEntries}, {"excluded", stats.excludedEntries}, {"weak", stats.weakPasswords},
        {"short", stats.shortPasswords}, {"reused", stats.reusedPasswords}, {"unique", stats.uniquePasswords},
        {"average_length", stats.averagePwdLength()}, {"passkeys", passkeys}, {"totp", totp},
        {"health", health}, {"duplicates", duplicates}, {"browser", browser}};
}

void KeyslotReports::edit(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision, const Commit& commit)
{
    if (text(args, "revision") != QString::fromLatin1(revision.toHex()))
        fail("conflict", "The database changed. Refresh the report before changing its entries.");
    const auto action = text(args, "action");
    if (!QStringList{"browser_reset", "exclude", "include"}.contains(action) || !args.value("entries").isArray())
        fail("invalid_request", "Choose a supported report action and selection.");
    const auto index = uniqueEntries(db.data());
    QList<Entry*> selected;
    QSet<QUuid> seen;
    for (const auto& value : args.value("entries").toArray()) {
        const QUuid id(value.toString());
        auto* entry = index.value(id);
        if (!value.isString() || id.isNull() || !entry || seen.contains(id) || entry->isRecycled())
            fail("invalid_request", "Choose each unambiguous active entry once.");
        seen.insert(id); selected.append(entry);
    }
    if (selected.isEmpty()) fail("invalid_request", "Choose entries from the report first.");
    commit([&] {
        for (auto* entry : selected) {
            entry->beginUpdate();
            if (action == "browser_reset") entry->customData()->remove(BrowserService::KEEPASSXCBROWSER_NAME);
            else entry->setExcludeFromReports(action == "exclude");
            entry->endUpdate();
        }
    });
}

QJsonObject KeyslotReports::prepare(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision)
{
    clear();
    const auto mode = text(args, "mode");
    if (mode != "online" && mode != "offline") fail("invalid_request", "Choose an online or offline password check.");
    const bool excluded = flag(args, "excluded");
    const auto index = uniqueEntries(db.data());
    static const QRegularExpression reference("\\{REF:", QRegularExpression::CaseInsensitiveOption);
    for (auto* entry : db->rootGroup()->entriesRecursive()) {
        if (entry->isRecycled() || (entry->excludeFromReports() && !excluded) || entry->password().isEmpty()) continue;
        const auto value = entry->resolveMultiplePlaceholders(entry->password());
        if (entry->uuid().isNull() || !index.value(entry->uuid()) || value.isEmpty() || reference.match(value).hasMatch()) { ++m_skipped; continue; }
        const auto hash = QCryptographicHash::hash(value.toUtf8(), QCryptographicHash::Sha1).toHex().toUpper();
        m_hashes[hash].append(entry->uuid()); ++m_checked;
    }
    if (mode == "offline") {
        const auto path = text(args, "path");
        const QFileInfo info(path);
        if (path.isEmpty() || path.contains(QChar('\0')) || !info.isFile()) fail("file_error", "Choose a regular SHA-1 password-hash corpus file.");
        m_file = std::make_unique<QFile>(info.canonicalFilePath());
        if (!m_file->open(QIODevice::ReadOnly)) { clear(); fail("file_error", "The offline password-hash file could not be opened."); }
        m_fileSize = m_file->size(); m_fileModified = QFileInfo(*m_file).lastModified().toMSecsSinceEpoch();
        if (m_fileSize == 0) { clear(); fail("report_format", "The offline password-hash file is empty."); }
    } else {
        QSet<QString> prefixes;
        for (auto it = m_hashes.cbegin(); it != m_hashes.cend(); ++it) prefixes.insert(QString::fromLatin1(it.key().left(5)));
        m_prefixes = prefixes.values(); m_total = m_prefixes.size();
    }
    m_database = db; m_revision = revision; m_token = QUuid::createUuid().toString(QUuid::WithoutBraces);
    return {{"token", m_token}, {"checked", m_checked}, {"skipped", m_skipped}, {"requests", m_total}, {"bytes", double(m_fileSize)}};
}

QJsonObject KeyslotReports::step(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision)
{
    if (m_token.isEmpty() || text(args, "token") != m_token || m_database.toStrongRef() != db || revision != m_revision)
        fail("conflict", "The database changed or this password check ended. Start a new check.");
    QHash<QByteArray, qint64> hashes;
    if (m_file && !m_hashes.isEmpty()) {
        if (m_file->size() != m_fileSize || QFileInfo(*m_file).lastModified().toMSecsSinceEpoch() != m_fileModified)
            fail("conflict", "The offline corpus changed during the check. Start a new check.");
        auto bytes = m_file->read(4 * 1024 * 1024);
        if (m_file->error() != QFileDevice::NoError) fail("file_error", "The offline corpus could not be read completely.");
        if (!m_file->atEnd()) {
            const auto end = bytes.lastIndexOf('\n');
            if (end < 0 || !m_file->seek(m_file->pos() - bytes.size() + end + 1))
                fail("report_format", "The offline corpus contains an invalid or oversized record.");
            bytes.truncate(end + 1);
        }
        if (!bytes.isEmpty()) hashes = parse(bytes, 40);
    } else if (!m_file && !m_prefixes.isEmpty()) {
        const auto prefix = m_prefixes.first();
        const auto suffixes = parse(download(prefix), 35);
        for (auto it = suffixes.cbegin(); it != suffixes.cend(); ++it) hashes.insert(prefix.toLatin1() + it.key(), it.value());
        m_prefixes.removeFirst(); ++m_done;
    }
    const auto index = uniqueEntries(db.data());
    QJsonArray rows;
    for (auto it = hashes.cbegin(); it != hashes.cend(); ++it) {
        if (it.value() <= 0) continue;
        for (const auto& id : m_hashes.value(it.key())) {
            if (it.value() <= m_counts.value(id)) continue;
            m_counts[id] = it.value();
            if (!index.value(id)) fail("conflict", "A report entry changed. Start a new check.");
            auto item = metadata(index.value(id)); item.insert("count", double(it.value())); rows.append(item);
        }
    }
    if (m_file && (m_file->size() != m_fileSize || QFileInfo(*m_file).lastModified().toMSecsSinceEpoch() != m_fileModified))
        fail("conflict", "The offline corpus changed during the check. Start a new check.");
    const bool complete = m_hashes.isEmpty() || (m_file ? m_file->atEnd() : m_prefixes.isEmpty());
    QJsonObject result{{"complete", complete}, {"rows", rows}, {"checked", m_checked}, {"skipped", m_skipped},
        {"done", m_done}, {"total", m_total}, {"position", m_file ? double(m_file->pos()) : 0}, {"bytes", double(m_fileSize)}};
    if (complete) clear();
    return result;
}
void KeyslotReports::cancel(const QString& token) { if (token == m_token) clear(); }
void KeyslotReports::clear() {
    m_database.clear(); m_revision.clear(); m_token.clear(); m_hashes.clear(); m_counts.clear(); m_prefixes.clear();
    m_file.reset(); m_fileSize = m_fileModified = 0; m_total = m_done = m_checked = m_skipped = 0;
}
