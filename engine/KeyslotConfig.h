// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QJsonObject>
#include <QString>

namespace KeyslotConfig {
struct Failure { QString code, message; QJsonObject details; };
QJsonObject read(const QJsonObject& arguments);
QJsonObject write(const QJsonObject& arguments);
}
