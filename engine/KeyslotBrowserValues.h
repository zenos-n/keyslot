// SPDX-License-Identifier: GPL-3.0-only
// Adapted from KeePassXC EntryPlaceholders (2.8.0), GPL-2.0-or-GPL-3.0.
// Retain the pinned 2.7 Entry API while applying upstream browser placeholder rejection.
#pragma once
#include "core/Entry.h"
#include <QRegularExpression>

inline bool keyslotBrowserHasPlaceholder(const QString& input)
{
    // A nested REF can exceed the normal placeholder-classification depth.
    if (EntryAttributes::matchReference(input).hasMatch()) return true;
    static const QRegularExpression expression("({(?>[^{}]+?|(?1))+?})");
    auto matches = expression.globalMatch(input);
    Entry classifier;
    while (matches.hasNext()) {
        auto value = matches.next().captured(0);
        if (value.startsWith("\\{")) value.replace(0, 2, "{");
        if (value.endsWith("\\}")) value.replace(value.size() - 2, 2, "}");
        for (int depth = 0; depth < 10; ++depth) {
            const auto type = classifier.placeholderType(value);
            if (type != Entry::PlaceholderType::NotPlaceholder && type != Entry::PlaceholderType::Unknown) return true;
            if (!value.startsWith('{') || !value.endsWith('}')) break;
            value = value.mid(1, value.size() - 2);
        }
    }
    return false;
}
