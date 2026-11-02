// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QElapsedTimer>
#include <QJsonObject>
#include <QSharedPointer>
#include <QUuid>
#include <memory>

class Entry;
class Group;
class Database;
class AutoTypePlatformX11;
struct AutoTypeFailure { QString code, message; };

class KeyslotAutoType {
    struct Pending {
        QWeakPointer<Database> database;
        QByteArray fingerprint;
        QUuid entry;
        QString token, sequence, backend, target, title;
        qint64 expires = 0;
        int delay = 25, startDelay = 500;
    } pending;
    QElapsedTimer clock;
    std::unique_ptr<AutoTypePlatformX11> platform;
    AutoTypePlatformX11* x11();
public:
    KeyslotAutoType();
    ~KeyslotAutoType();
    void clear();
    QJsonObject fields(const Entry* entry) const;
    QJsonObject settings(const Entry* entry) const;
    QJsonObject settings(const Group* group) const;
    void saveSettings(Entry* entry, const QJsonObject& args);
    void saveSettings(Group* group, const QJsonObject& args);
    QJsonObject targets();
    QJsonObject matches(const QSharedPointer<Database>& db, const QJsonObject& args);
    QJsonObject search(const QSharedPointer<Database>& db, const QJsonObject& args);
    QJsonObject sort(const QJsonObject& args) const;
    QJsonObject prepare(const QSharedPointer<Database>& db, Entry* entry, const QJsonObject& args,
                        const QByteArray& fingerprint);
    QJsonObject finish(const QSharedPointer<Database>& db, const QJsonObject& args, const QByteArray& fingerprint);
};
