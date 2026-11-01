// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QElapsedTimer>
#include <QHash>
#include <QJsonObject>
#include <QSharedPointer>
#include <QStringList>
#include <functional>
class Database;
class QLocalServer;
class QTemporaryDir;
struct TransferFailure { QString code, message; };
class KeyslotTransfer {
    struct Source {
        QWeakPointer<Database> database;
        QSharedPointer<Database> capsule;
        QByteArray fingerprint, key, destinationHash;
        QStringList entries, groups;
        QString destination, sourceGroup;
        qint64 expires;
        bool move = false, delivered = false, started = false;
    };
    struct Destination {
        QWeakPointer<Database> database;
        QSharedPointer<QLocalServer> server;
        QSharedPointer<QTemporaryDir> directory;
        QByteArray fingerprint;
        QString sourceToken, sourcePath, group, sourceGroup;
        QStringList entries, groups;
        qint64 expires;
        int sourcePid;
        int position = -1;
    };
    QElapsedTimer clock;
    QHash<QString, Source> sources;
    QHash<QString, Destination> destinations;
    void prune();
public:
    using Commit = std::function<void(const std::function<void()>&)>;
    KeyslotTransfer() { clock.start(); }
    void clear();
    QJsonObject prepare(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint);
    QJsonObject listen(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint);
    QJsonObject send(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint);
    QJsonObject receive(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint, const Commit& commit);
    QJsonObject finish(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint, const Commit& commit);
    QJsonObject local(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint, const Commit& commit);
    void cancel(const QJsonObject& args);
};
