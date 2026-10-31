// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <QJsonObject>
#include <QSharedPointer>
#include <QString>
#include <functional>

class Database;

class KeyslotTrash
{
public:
    struct Failure { QString code; QString message; };
    using Commit = std::function<void(const std::function<void()>&)>;
    QJsonObject review(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision);
    void apply(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision, const Commit& commit);
    void cancel(const QString& token);
    void clear();
private:
    QWeakPointer<Database> m_database;
    QByteArray m_revision;
    QJsonObject m_request;
    QString m_token;
};
