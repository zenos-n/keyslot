// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QElapsedTimer>
#include <QJsonObject>
#include <QSharedPointer>
#include <functional>

class Database;

class KeyslotEntryActions {
public:
    struct Failure { QString code, message; };
    using Commit = std::function<void(const std::function<void()>&)>;
    KeyslotEntryActions() { m_clock.start(); }
    QJsonObject review(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision);
    QString apply(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision, const Commit& commit);
    void cancel(const QString& token);
private:
    QElapsedTimer m_clock;
    QWeakPointer<Database> m_database;
    QByteArray m_revision;
    QJsonObject m_request;
    QString m_token;
    qint64 m_expires = 0;
};
