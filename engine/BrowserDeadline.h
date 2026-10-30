// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QJsonObject>
#include <QtGlobal>
#include <cmath>

constexpr qint64 PasskeyTimeoutDefault = 300000;
inline qint64 passkeyRequestTimeout(const QJsonObject& options) {
    const auto requested = options.value("timeout").toDouble(PasskeyTimeoutDefault);
    return !std::isfinite(requested) || requested <= 0 ? PasskeyTimeoutDefault
        : qint64(qBound(1000.0, requested, double(PasskeyTimeoutDefault)));
}
