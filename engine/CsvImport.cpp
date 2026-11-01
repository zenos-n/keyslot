// SPDX-License-Identifier: GPL-3.0-only
// Mapping and group/time/TOTP conversion adapted from KeePassXC 2.7.12 CsvImportWidget.
// Copyright (C) 2016 Enrico Mariotti; Copyright (C) 2017 KeePassXC Team.
#include "CsvImport.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "core/Totp.h"
#include <QFile>
#include <QJsonArray>
#include <QRegularExpression>
#include <QStringConverter>
#include <cmath>
#include <limits>

namespace {
const QStringList Fields{"group", "title", "username", "password", "url", "tags", "notes", "totp", "icon", "modified", "created"};
const QStringList Labels{"Group", "Title", "Username", "Password", "URL", "Tags", "Notes", "TOTP", "Icon", "Last Modified", "Created"};
bool whole(const QJsonValue& value, int low, int high) {
    const auto number = value.toDouble(-2);
    return value.isDouble() && std::isfinite(number) && number == std::floor(number) && number >= low && number <= high;
}
QDateTime timestamp(const QString& value) {
    if (QRegularExpression("^\\d+$").match(value).hasMatch()) {
        bool valid;
        auto time = value.toLongLong(&valid);
        if (!valid) return {};
        if (time <= std::numeric_limits<qint32>::max()) time *= 1000;
        return QDateTime::fromMSecsSinceEpoch(time, Qt::UTC);
    }
    return QDateTime::fromString(value, Qt::ISODate).toUTC();
}
}

bool CsvImport::load(const QString& path, const QJsonObject& options) {
    m_error.clear(); m_table.clear(); m_mapping = {}; m_path = path;
    const QStringList allowed{"codec", "separator", "qualifier", "comment", "backslash", "has_header", "skip_rows", "mapping", "allow_empty_title"};
    for (auto it = options.begin(); it != options.end(); ++it)
        if (!allowed.contains(it.key())) return reject("An unknown CSV option was supplied.");
    for (const auto* key : {"codec", "separator", "qualifier", "comment"})
        if (options.contains(key) && !options.value(key).isString()) return reject("CSV text options must be strings.");
    for (const auto* key : {"backslash", "has_header", "allow_empty_title"})
        if (options.contains(key) && !options.value(key).isBool()) return reject("CSV switches must be booleans.");
    const auto codec = options.value("codec").toString("UTF-8");
    if (!QStringConverter::encodingForName(codec.toUtf8())) return reject("The selected CSV encoding is unavailable.");
    const auto separator = options.value("separator").toString(",");
    const auto qualifier = options.value("qualifier").toString("\"");
    const auto comment = options.value("comment").toString("#");
    if (separator.size() != 1 || separator.at(0).isNull() || separator.contains('\n') || separator.contains('\r')
        || qualifier.size() > 1 || comment.size() > 1)
        return reject("Choose one separator character and at most one quote or comment character.");
    m_parser.setCodec(codec); m_parser.setFieldSeparator(separator.at(0));
    m_parser.setTextQualifier(qualifier.isEmpty() ? QChar() : qualifier.at(0));
    m_parser.setComment(comment.isEmpty() ? QChar() : comment.at(0));
    m_parser.setBackslashSyntax(options.value("backslash").toBool());
    QFile file(path);
    if (!m_parser.parse(&file)) return reject("KeePassXC could not parse this CSV. Check encoding, separators, quotes and escapes.");
    m_table = m_parser.getCsvTable();
    m_header = options.value("has_header").toBool(true);
    m_allowEmptyTitle = options.value("allow_empty_title").toBool(false);
    m_skip = m_header ? 1 : 0;
    if (options.contains("skip_rows")) {
        if (!whole(options.value("skip_rows"), m_header ? 1 : 0, std::numeric_limits<int>::max()))
            return reject("The CSV skipped-row count is invalid.");
        m_skip = options.value("skip_rows").toInt();
    }
    if (m_skip >= m_table.size()) return reject("No CSV data rows remain after skipping rows.");
    const int columns = m_parser.getCsvCols();
    for (int field = 0; field < Fields.size(); ++field) {
        int found = -1;
        if (m_header) for (int column = 0; column < columns; ++column)
            if (m_table.first().at(column).trimmed().compare(Labels.at(field), Qt::CaseInsensitive) == 0) { found = column; break; }
        m_mapping.insert(Fields.at(field), found);
    }
    if (options.contains("mapping")) {
        if (!options.value("mapping").isObject()) return reject("CSV field mapping must be an object.");
        const auto mapping = options.value("mapping").toObject();
        for (auto it = mapping.begin(); it != mapping.end(); ++it) {
            if (!Fields.contains(it.key()) || !whole(it.value(), -1, columns - 1))
                return reject("A CSV field maps to an invalid column.");
            m_mapping.insert(it.key(), it.value());
        }
    }
    return true;
}

QJsonObject CsvImport::inspect(int row, int column, bool reveal) const {
    QJsonArray headers, previewHeaders, rows, codecs;
    const int columns = m_parser.getCsvCols();
    auto label = [&](int index) { return m_header ? m_table.first().at(index).left(128) : QString("Column %1").arg(index + 1); };
    for (int index = 0; index < qMin(columns, 128); ++index) headers.append(label(index));
    for (const auto* codec : {"UTF-8", "UTF-16", "UTF-16LE", "UTF-16BE", "UTF-32", "UTF-32LE", "UTF-32BE", "ISO-8859-1", "System"})
        if (QStringConverter::encodingForName(codec)) codecs.append(QString::fromLatin1(codec));
    row = qBound(0, row < 0 ? m_skip : row, m_table.size() - 1);
    column = qBound(0, column, columns - 1);
    for (int index = column; index < qMin(columns, column + 16); ++index) previewHeaders.append(label(index));
    bool shortened = false;
    if (reveal) for (int index = row; index < qMin(m_table.size(), row + 20); ++index) {
        QJsonArray cells;
        for (int col = column; col < qMin(columns, column + 16); ++col) {
            const auto value = m_table.at(index).at(col);
            shortened |= value.size() > 256;
            cells.append(value.left(256));
        }
        rows.append(cells);
    }
    return {{"rows", m_table.size()}, {"columns", columns}, {"skip_rows", m_skip},
            {"headers", headers}, {"mapping", m_mapping}, {"codecs", codecs},
            {"row_start", row}, {"column_start", column}, {"preview_headers", previewHeaders},
            {"preview", rows}, {"shortened", shortened}};
}

QSharedPointer<Database> CsvImport::build() {
    if (m_mapping.value("title").toInt() < 0 && !m_allowEmptyTitle) {
        reject("Map a title column or confirm importing entries without titles."); return {};
    }
    auto database = QSharedPointer<Database>::create();
    database->rootGroup()->setNotes(QString("Imported from CSV file: %1").arg(m_path));
    auto value = [&](int row, const char* field) {
        const auto column = m_mapping.value(field).toInt(-1);
        return column < 0 ? QString() : m_table.at(row).at(column);
    };
    QString rootName;
    for (int row = m_skip; row < m_table.size(); ++row) {
        const auto path = value(row, "group");
        const auto name = path.mid(0, path.indexOf('/'));
        if (!rootName.isNull() && rootName != name) { rootName.clear(); break; }
        rootName = name;
    }
    if (!rootName.isEmpty()) database->rootGroup()->setName(rootName);
    for (int row = m_skip; row < m_table.size(); ++row) {
        auto* group = database->rootGroup();
        auto parts = value(row, "group").split('/', Qt::SkipEmptyParts);
        if (!rootName.isEmpty() && !parts.isEmpty() && parts.first().compare(rootName, Qt::CaseInsensitive) == 0) parts.removeFirst();
        for (const auto& name : parts) {
            auto* child = group->findChildByName(name);
            if (!child) { child = new Group(); child->setUuid(QUuid::createUuid()); child->setName(name); child->setParent(group); }
            group = child;
        }
        auto* entry = new Entry(); entry->setUuid(QUuid::createUuid()); entry->setGroup(group);
        entry->setTitle(value(row, "title")); entry->setUsername(value(row, "username"));
        entry->setPassword(value(row, "password")); entry->setUrl(value(row, "url"));
        entry->setTags(value(row, "tags")); entry->setNotes(value(row, "notes"));
        const auto otp = value(row, "totp");
        if (!otp.isEmpty()) {
            auto settings = Totp::parseSettings(otp);
            if (!settings || settings->key.isEmpty()) settings = Totp::parseSettings({}, otp);
            entry->setTotp(settings);
        }
        bool valid;
        const int icon = value(row, "icon").toInt(&valid);
        if (valid) entry->setIcon(icon);
        TimeInfo time;
        const auto modified = timestamp(value(row, "modified"));
        if (modified.isValid()) { time.setLastModificationTime(modified); time.setLastAccessTime(modified); }
        const auto created = timestamp(value(row, "created"));
        if (created.isValid()) time.setCreationTime(created);
        entry->setTimeInfo(time);
    }
    return database;
}
