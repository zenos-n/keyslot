// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QFile>
#include <QHash>
#include <QJsonObject>
#include <QSharedPointer>
#include <QUuid>
#include <functional>
#include <memory>

class Database;

class KeyslotReports
{
public:
    struct Failure { QString code, message; };
    using Commit = std::function<void(const std::function<void()>&)>;
    static QJsonObject inventory(const QSharedPointer<Database>& db, bool excluded, const QByteArray& revision);
    static void edit(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision, const Commit& commit);
    QJsonObject prepare(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision);
    QJsonObject step(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision);
    void cancel(const QString& token);
    void clear();
private:
    QWeakPointer<Database> m_database;
    QByteArray m_revision;
    QString m_token;
    QHash<QByteArray, QList<QUuid>> m_hashes;
    QHash<QUuid, qint64> m_counts;
    QStringList m_prefixes;
    int m_total = 0, m_done = 0, m_checked = 0, m_skipped = 0;
    std::unique_ptr<QFile> m_file;
    qint64 m_fileSize = 0, m_fileModified = 0;
};
