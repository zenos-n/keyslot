// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "sshagent/KeeAgentSettings.h"
#include "sshagent/OpenSSHKey.h"
#include <QElapsedTimer>
#include <QHash>
#include <QJsonObject>
#include <QLocalSocket>
#include <QSharedPointer>

class Entry;
class Database;
struct SSHFailure { QString code, message; };
class KeyslotSSH {
    struct Pending {
        QWeakPointer<Database> database;
        QByteArray fingerprint;
        QString entry;
        QSharedPointer<OpenSSHKey> key;
        KeeAgentSettings settings;
        qint64 expires;
    };
    struct Removal {
        QWeakPointer<Database> database;
        QByteArray fingerprint;
        QString relayToken;
        qint64 expires;
    };
    QElapsedTimer clock;
    QLocalSocket relay;
    QString endpoint, agent, provider;
    int sequence = 0;
    QHash<QString, Pending> pending;
    QHash<QString, Removal> removals;
    QJsonObject request(QJsonObject value);
    void clearPending();
    void prunePending();
public:
    KeyslotSSH() { clock.start(); }
    ~KeyslotSSH() { clearPending(); }
    void configure(const QJsonObject& args);
    QJsonObject settings(const Entry* entry) const;
    QJsonObject keyInfo(const Entry* entry, bool decrypt) const;
    void saveSettings(Entry* entry, const QJsonObject& args);
    void updatePolicy(const Entry* entry);
    QJsonObject prepare(const QSharedPointer<Database>& db, Entry* entry, const QByteArray& fingerprint);
    QJsonObject add(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint);
    QJsonObject owned();
    QJsonObject remove(const QJsonObject& args);
    QJsonObject agentKeys();
    QJsonObject reviewRemoval(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint);
    QJsonObject finishRemoval(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint);
};
