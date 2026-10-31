// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QByteArray>
#include <QJsonObject>
#include "core/Totp.h"
class Entry;
namespace KeyslotTotp {
struct Failure { QString code; QString message; };
QJsonObject config(const Entry* entry);
QSharedPointer<Totp::Settings> settings(const Entry* entry, const QJsonObject& args);
QJsonObject sample(const Entry* entry, const QJsonObject& args = {});
QByteArray qr(const Entry* entry, bool png);
}
