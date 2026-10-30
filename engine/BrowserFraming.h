// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <QByteArray>

// The official proxy uses a JSON stream over the local socket, without length headers.
inline int browserFrameEnd(const QByteArray& bytes) {
    int depth = 0;
    bool quoted = false, escaped = false;
    for (int i = 0; i < bytes.size(); ++i) {
        const char c = bytes[i];
        if (quoted) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') quoted = false;
        } else if (c == '"') quoted = true;
        else if (c == '{' || c == '[') {
            if (++depth > 64) return -1;
        } else if (c == '}' || c == ']') {
            if (--depth < 0) return -1;
            if (!depth) return i + 1;
        }
    }
    return 0;
}
