// SPDX-License-Identifier: GPL-3.0-only
// Adapted from KeePassXC EntryPlaceholders (2.8.0), GPL-2.0-or-GPL-3.0.
// Retain the existing boundary policy using the native 2.8 classifier.
#pragma once
#include "core/EntryPlaceholders.h"
#include <QRegularExpression>

inline bool keyslotBrowserHasPlaceholder(const QString& input)
{
    // A nested REF can exceed the normal placeholder-classification depth.
    if (EntryPlaceholders::matchReference(input).hasMatch()) return true;
    static const QRegularExpression expression("({(?>[^{}]+?|(?1))+?})");
    auto matches = expression.globalMatch(input);
    while (matches.hasNext()) {
        auto value = matches.next().captured(0);
        if (value.startsWith("\\{")) value.replace(0, 2, "{");
        if (value.endsWith("\\}")) value.replace(value.size() - 2, 2, "}");
        for (int depth = 0; depth < 10; ++depth) {
            const auto type = EntryPlaceholders::placeholderType(value);
            if (type != EntryPlaceholders::PlaceholderType::NotPlaceholder && type != EntryPlaceholders::PlaceholderType::Unknown) return true;
            if (!value.startsWith('{') || !value.endsWith('}')) break;
            value = value.mid(1, value.size() - 2);
        }
    }
    return false;
}
