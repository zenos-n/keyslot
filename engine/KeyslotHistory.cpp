// SPDX-License-Identifier: GPL-3.0-only
#include "KeyslotHistory.h"
#include "core/Entry.h"
#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMap>
#include <QSet>

namespace {
struct Cell { QString value; bool protectedValue = false; bool storedProtection = false; };
using Fields = QMap<QString, Cell>;
using Sections = QMap<QString, Fields>;
QString json(const QJsonValue& value) {
    return QString::fromUtf8(QJsonDocument(value.toArray()).toJson(QJsonDocument::Compact));
}
QString date(const QDateTime& value) { return value.toString(Qt::ISODate); }
QString id(const QUuid& value) { return value.isNull() ? QString() : value.toString(QUuid::WithoutBraces); }
Sections describe(const Entry* entry) {
    Sections result;
    auto& attributes = result["attributes"];
    for (const auto& key : entry->attributes()->keys()) {
        // Custom fields can contain OTP/private-key material even without a protection flag.
        attributes[key] = {entry->attributes()->value(key), entry->attributes()->isProtected(key)
            || key == EntryAttributes::PasswordKey || !EntryAttributes::isDefaultAttribute(key), entry->attributes()->isProtected(key)};
    }
    auto& properties = result["properties"];
    properties["UUID"] = {id(entry->uuid())};
    properties["Tags"] = {entry->tags()};
    properties["Icon"] = {QString::number(entry->iconNumber())};
    properties["Custom Icon"] = {id(entry->iconUuid())};
    properties["Text Color"] = {entry->foregroundColor()};
    properties["Background Color"] = {entry->backgroundColor()};
    properties["URL Override"] = {entry->overrideUrl(), true};
    properties["Exclude from Password Reports"] = {entry->excludeFromReports() ? "Yes" : "No"};
    properties["Expires"] = {entry->timeInfo().expires() ? "Yes" : "No"};
    properties["Expiry"] = {date(entry->timeInfo().expiryTime())};
    properties["Created"] = {date(entry->timeInfo().creationTime())};
    properties["Modified"] = {date(entry->timeInfo().lastModificationTime())};
    properties["Accessed"] = {date(entry->timeInfo().lastAccessTime())};
    properties["Usage Count"] = {QString::number(entry->timeInfo().usageCount())};
    properties["Location Changed"] = {date(entry->timeInfo().locationChanged())};
    properties["Previous Parent Group"] = {id(entry->previousParentGroupUuid())};
    properties["One-Time Password Settings"] = {entry->totpSettingsString(), true};
    auto& autotype = result["autotype"];
    autotype["Enabled"] = {entry->autoTypeEnabled() ? "Yes" : "No"};
    autotype["Obfuscation"] = {QString::number(entry->autoTypeObfuscation())};
    autotype["Default Sequence"] = {entry->defaultAutoTypeSequence(), true};
    QJsonArray associations;
    for (const auto& association : entry->autoTypeAssociations()->getAll())
        associations.append(QJsonArray{association.window, association.sequence});
    autotype["Window Associations"] = {json(associations), true};
    auto& data = result["data"];
    for (const auto& key : entry->customData()->keys())
        data[key] = {json(QJsonArray{entry->customData()->value(key), date(entry->customData()->lastModified(key))}), true};
    auto& attachments = result["attachments"];
    for (const auto& key : entry->attachments()->keys()) {
        const auto bytes = entry->attachments()->value(key);
        attachments[key] = {QString::number(bytes.size()) + " bytes · SHA-256 "
            + QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex())};
    }
    return result;
}
QJsonObject cell(const Fields& fields, const QString& key) {
    if (!fields.contains(key)) return {{"present", false}, {"protected", false}};
    const auto& value = fields[key];
    QJsonObject result{{"present", true}, {"protected", value.protectedValue}, {"storage_protected", value.storedProtection}};
    if (!value.protectedValue) result.insert("value", value.value);
    return result;
}
}
QJsonObject KeyslotHistory::compare(const Entry* left, const Entry* right) {
    const auto before = describe(left), after = describe(right);
    QJsonArray sections;
    int changed = 0;
    for (const auto& name : {"attributes", "properties", "autotype", "data", "attachments"}) {
        const auto a = before.value(name), b = after.value(name);
        auto keys = a.keys();
        for (const auto& key : b.keys()) if (!keys.contains(key)) keys.append(key);
        keys.sort();
        QJsonArray rows;
        for (const auto& key : keys) {
            const bool differs = a.contains(key) != b.contains(key) || a.value(key).value != b.value(key).value
                || a.value(key).protectedValue != b.value(key).protectedValue
                || a.value(key).storedProtection != b.value(key).storedProtection;
            changed += differs;
            rows.append(QJsonObject{{"key", key}, {"left", cell(a, key)}, {"right", cell(b, key)}, {"changed", differs}});
        }
        sections.append(QJsonObject{{"section", name}, {"rows", rows}});
    }
    return {{"sections", sections}, {"changed", changed}};
}
QString KeyslotHistory::value(const Entry* entry, const QString& section, const QString& key) {
    return describe(entry).value(section).value(key).value;
}
