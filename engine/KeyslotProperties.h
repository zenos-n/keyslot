// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QElapsedTimer>
#include <QJsonObject>
#include <QSharedPointer>
#include <QMap>
#include <functional>
class Database;
class KeyslotProperties {
public:
    struct Failure { QString code, message; };
    using Commit = std::function<void(const std::function<void()>&)>;
    KeyslotProperties() { clock.start(); }
    static QJsonObject info(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision);
    static QJsonObject value(const QSharedPointer<Database>& db, const QJsonObject& args);
    QJsonObject review(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision);
    void remove(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision, const Commit& commit);
    void cancel(const QString& token);
    void clear();
private:
    QElapsedTimer clock;
    QWeakPointer<Database> database;
    QJsonObject target;
    QMap<QString, QByteArray> fingerprints;
    QByteArray reviewedRevision;
    QString token;
    qint64 expires = 0;
};
