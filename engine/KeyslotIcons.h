// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QElapsedTimer>
#include <QJsonObject>
#include <QHash>
#include <QSet>
#include <QSharedPointer>
#include <QUuid>
#include <QUrl>
#include <functional>

class Database;

class KeyslotIcons {
public:
    struct Failure { QString code, message; };
    using Commit = std::function<void(const std::function<void()>&)>;
    using Normalize = std::function<QByteArray(const QByteArray&)>;
    QString reserve(const QSharedPointer<Database>& db, const QString& entry);
    QJsonObject reviewUnused(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision);
    void removeUnused(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision, const Commit& commit);
    QJsonObject prepare(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision);
    QJsonObject step(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision);
    QJsonObject accept(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision, const Normalize& normalize);
    QString finish(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision, const Commit& commit);
    void cancel(const QString& token);
    void clear();
private:
    struct Ticket { QWeakPointer<Database> database; QByteArray revision; QString token; };
    Ticket m_unused, m_download;
    struct Reservation { QWeakPointer<Database> database; QUuid entry, icon; QString url; int standardIcon; };
    QHash<QString, Reservation> m_reservations;
    QList<QUuid> m_remove;
    QSet<QUuid> m_keep;
    struct Candidate { QUrl url; int redirects = 0; };
    Candidate m_current;
    QString m_request;
    QList<Candidate> m_candidates;
    QSet<QString> m_visited;
    QByteArray m_png;
    QString m_name;
    QUuid m_entry;
    QString m_entryUrl;
    QUuid m_entryIcon;
    int m_entryStandardIcon = 0;
    QElapsedTimer m_clock;
    int m_timeout = 10000, m_tried = 0;
    bool m_waiting = false;
    static void require(const Ticket& ticket, const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision);
    void requireDownload(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& revision) const;
    QJsonObject progress() const;
};
