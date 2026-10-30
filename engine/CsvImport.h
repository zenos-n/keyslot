// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "format/CsvParser.h"
#include <QJsonObject>
#include <QSharedPointer>

class Database;

class CsvImport {
public:
    bool load(const QString& path, const QJsonObject& options);
    QJsonObject inspect(int row, int column, bool reveal) const;
    QSharedPointer<Database> build();
    QString error() const { return m_error; }
private:
    CsvParser m_parser;
    CsvTable m_table;
    QJsonObject m_mapping;
    QString m_path, m_error;
    int m_skip = 1;
    bool m_header = true, m_allowEmptyTitle = false;
    bool reject(const char* message) { m_error = QString::fromUtf8(message); return false; }
};
