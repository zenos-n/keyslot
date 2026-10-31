// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QElapsedTimer>
#include <QJsonObject>
#include <QSharedPointer>
#include <QPair>
#include <functional>
class Database;
class Entry;
struct LaunchFailure { QString code, message; };
class KeyslotLaunch {
    struct Pending {
        QWeakPointer<Database> database;
        QByteArray fingerprint;
        QString token, kind, value, entry, path, keyfile, targetHash, keyfileHash;
        QPair<QString, QString> keys;
        qint64 expires = 0;
        bool override = false, remembered = false;
    } pending;
    struct Offer {
        QString token, sourceToken, sourceKey, nonce, path, hash, keyfile, keyfileHash;
        QPair<QString, QString> keys;
        qint64 expires = 0;
    } incoming;
    QElapsedTimer clock;
public:
    struct Opened { QSharedPointer<Database> database; QString path; QByteArray hash; };
    using Commit = std::function<void(const std::function<void()>&)>;
    KeyslotLaunch() { clock.start(); }
    void clear();
    void cancel(const QJsonObject& args);
    static bool approved(const Entry* entry);
    static void forget(Entry* entry);
    QJsonObject prepare(const QSharedPointer<Database>& db, Entry* entry, const QJsonObject& args, const QByteArray& fingerprint);
    QJsonObject finish(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint, const Commit& commit);
    QJsonObject offer(const QJsonObject& args);
    Opened accept(const QJsonObject& args);
};
