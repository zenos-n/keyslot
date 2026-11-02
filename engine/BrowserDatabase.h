// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "browser/BrowserService.h"
#include <QHash>
#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonObject>
#include <QSharedPointer>
#include <QSet>
#include <functional>

class Database;
class Group;
class Entry;
struct BrowserFailure { QString code, message; };
namespace KeyslotBrowser {
[[noreturn]] void reject(const char* code, const char* message);
QString text(const QJsonObject& args, const char* name, bool required = false);
bool flag(const QJsonObject& args, const char* name, bool fallback = false);
void authenticate(const QSharedPointer<Database>& db, const QString& id, const QString& key);
QString trustKey(const QString& id);
QString connectionRevision(const QString& key);
bool trusted(const QSharedPointer<Database>& db, const QString& id, const QString& key);
QString groupPath(QString path);
}

// The upstream matcher is reused without constructing windows or starting a browser socket.
class KeyslotBrowserDatabase {
    struct Request {
        QWeakPointer<Database> database;
        QByteArray fingerprint;
        QString id, key, site, form, siteHost, formHost, realm;
        bool bestMatch, allowExpired, customFields;
        QHash<QString, bool> entries;
        qint64 expires;
    };
    BrowserService service{true};
    QElapsedTimer clock;
    QHash<QString, Request> requests;
    struct SaveRequest {
        QWeakPointer<Database> database;
        QByteArray fingerprint;
        QString id, key, site, form, login, password, target;
        QSet<QString> groups;
        bool changed;
        qint64 expires;
    };
    QHash<QString, SaveRequest> saves;
    struct GroupRequest {
        QWeakPointer<Database> database;
        QByteArray fingerprint;
        QString id, key, path;
        qint64 expires;
    };
    QHash<QString, GroupRequest> groups;
    struct DeleteRequest {
        QWeakPointer<Database> database;
        QByteArray fingerprint;
        QString id, key, entry;
        qint64 expires;
    };
    QHash<QString, DeleteRequest> deletions;
    struct PasskeyRequest {
        QWeakPointer<Database> database;
        QByteArray fingerprint;
        QString id, key, origin, rp, groupPath;
        QJsonObject options;
        bool registration;
        QSet<QString> entries, groups;
        qint64 expires;
    };
    QHash<QString, PasskeyRequest> passkeys;
    Group* ensureGroup(const QSharedPointer<Database>& db, const QString& path, bool passkey = false);

public:
    KeyslotBrowserDatabase() { clock.start(); }
    QJsonObject lookup(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint);
    QJsonArray release(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint,
                       const std::function<void(const std::function<void()>&)>& commit);
    QJsonObject prepareSave(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint);
    bool save(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint,
              const std::function<void(const std::function<void()>&)>& commit, QString* savedEntry = nullptr);
    QString totp(const QSharedPointer<Database>& db, const QJsonObject& args);
    QJsonObject databaseGroups(const QSharedPointer<Database>& db, const QJsonObject& args);
    QJsonArray databaseEntries(const QSharedPointer<Database>& db, const QJsonObject& args);
    QJsonObject options(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint);
    void saveOptions(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint,
                     const std::function<void(const std::function<void()>&)>& commit);
    QJsonObject prepareGroup(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint);
    QJsonObject createGroup(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint,
                            const std::function<void(const std::function<void()>&)>& commit);
    QJsonObject prepareDelete(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint);
    bool remove(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint,
                const std::function<void(const std::function<void()>&)>& commit);
    QJsonObject preparePasskey(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint);
    QJsonObject finishPasskey(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint,
                              const std::function<void(const std::function<void()>&)>& commit);
    QJsonObject passkeyInfo(const Entry* entry) const;
    QJsonObject inspectPasskeyImport(const QJsonObject& args) const;
    void importPasskey(const QSharedPointer<Database>& db, const QJsonObject& args,
                       const std::function<void(const std::function<void()>&)>& commit);
    void exportPasskey(const Entry* entry, const QJsonObject& args) const;
};
