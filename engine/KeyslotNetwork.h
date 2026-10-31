// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QUrl>

namespace KeyslotNetwork {
struct Reply { QByteArray bytes; QUrl redirect; int status = 0; QString error; };
Reply get(const QUrl& url, int limit, int timeout, const QList<QPair<QByteArray, QByteArray>>& headers = {});
}
