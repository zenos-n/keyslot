// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QJsonObject>
class Entry;
namespace KeyslotHistory {
QJsonObject compare(const Entry* left, const Entry* right);
QString value(const Entry* entry, const QString& section, const QString& key);
}
