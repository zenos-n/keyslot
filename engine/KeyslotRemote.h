// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QByteArray>
#include <QJsonArray>
#include <QJsonObject>
#include <QSharedPointer>
#include <functional>
#include <memory>
class Database;
class CompositeKey;
class KeyslotRemote {
    struct Pending;
    std::unique_ptr<Pending> pending;
public:
    struct Failure { QString code, message; };
    using Commit = std::function<QByteArray(const std::function<void()>&)>;
    KeyslotRemote();
    ~KeyslotRemote();
    void clear();
    static QJsonArray locations(const QSharedPointer<Database>& db);
    static QJsonObject location(const QSharedPointer<Database>& db, const QString& name);
    static void edit(const QSharedPointer<Database>& db, const QJsonObject& args, bool remove);
    QJsonObject prepare(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision);
    QJsonObject call(const QString& method, const QSharedPointer<Database>& db, const QJsonObject& args,
                     const QByteArray& revision, const QSharedPointer<const CompositeKey>& key, const Commit& commit);
};
