// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QSharedPointer>
#include <functional>

class Database;
class Group;
struct KeeShareFailure { QString code, message; };
class KeyslotKeeShare {
    QHash<QString, QByteArray> imported, exported;
    bool allowImport = false, allowExport = false;
    QString identityPath;
    QByteArray signedIdentity;
    void identity();
public:
    void configure(const QJsonObject& args);
    static QJsonObject identitySettings(const QJsonObject& args);
    QJsonObject settings(const Group* group) const;
    void saveSettings(Group* group, const QJsonObject& args);
    QJsonObject sync(const QSharedPointer<Database>& db, const QByteArray& fingerprint,
                     const std::function<void(const std::function<void()>&)>& transaction,
                     const std::function<QByteArray()>& currentFingerprint, bool force);
};
