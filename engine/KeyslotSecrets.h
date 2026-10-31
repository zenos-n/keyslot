// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QElapsedTimer>
#include <QHash>
#include <QJsonObject>
#include <QSet>
#include <QSharedPointer>
#include <QUuid>
#include <functional>

class Database;
class Entry;
class Group;
namespace FdoSecrets { class CipherPair; }
struct SecretFailure { QString code, message; };

// This instance lives in a dedicated private helper, independently of vault locks.
class KeyslotSecretSessions {
    struct Session { QString peer; QSharedPointer<FdoSecrets::CipherPair> cipher; bool plain; };
    QHash<QString, Session> sessions;
public:
    QJsonObject call(const QString& method, const QJsonObject& args);
};

// Authorization and item access stay scoped to the exposed group of one native vault.
class KeyslotSecrets {
    struct Pending {
        QWeakPointer<Database> database;
        QByteArray fingerprint;
        QString peer, kind;
        QJsonObject request;
        qint64 expires;
    };
    struct Grant { QSet<QUuid> allowed, once, onceTotp; };
    QHash<QString, Pending> pending;
    QHash<QString, Grant> grants;
    QElapsedTimer clock;
    bool confirmAccess = true;
    QString providerInstance;
    Group* root(const QSharedPointer<Database>& db) const;
    Entry* item(const QSharedPointer<Database>& db, const QString& identifier) const;
    bool authorized(const QString& peer, const QUuid& entry) const;
    bool consume(const QString& peer, const QUuid& entry);
public:
    KeyslotSecrets() { clock.start(); }
    void clear();
    void dropPeer(const QString& peer);
    void configure(const QJsonObject& args);
    QJsonObject settings(const QSharedPointer<Database>& db) const;
    void saveSettings(const QSharedPointer<Database>& db, const QJsonObject& args);
    QJsonObject info(const QSharedPointer<Database>& db, const QJsonObject& args);
    QJsonObject search(const QSharedPointer<Database>& db, const QJsonObject& args) const;
    QJsonObject get(const QSharedPointer<Database>& db, const QJsonObject& args);
    QJsonObject prepare(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint);
    QJsonObject finish(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint,
                       const std::function<void(const std::function<void()>&)>& transaction);
    QJsonObject mutate(const QSharedPointer<Database>& db, const QJsonObject& args,
                       const std::function<void(const std::function<void()>&)>& transaction);
};
