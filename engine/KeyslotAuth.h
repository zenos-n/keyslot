// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QJsonObject>
#include <QLocalSocket>
class KeyslotAuth {
    QLocalSocket socket;
    QByteArray input;
    QString path;
    qint64 broker = 0;
public:
    struct Failure { QString code, message; };
    void configure(const QString& endpoint, qint64 pid);
    QJsonObject request(const QJsonObject& args, int timeout = 10000);
};
