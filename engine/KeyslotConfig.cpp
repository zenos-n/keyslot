// SPDX-License-Identifier: GPL-3.0-only
// Qt's own INI codec preserves QVariant encodings and settings unknown to GTK.
#include "KeyslotConfig.h"
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLockFile>
#include <QSaveFile>
#include <QSettings>
#include <QSet>
#include <QTemporaryDir>
#include <algorithm>
#include <atomic>
#include <cmath>
#include <memory>
#include <vector>

namespace {
[[noreturn]] void reject(const QString& code, const QString& message) { throw KeyslotConfig::Failure{code, message, {}}; }
constexpr qint64 MaxIni = 16 * 1024 * 1024;
std::atomic_bool iniWarning{false};
class IniWarnings {
    QtMessageHandler previous;
public:
    IniWarnings() : previous(qInstallMessageHandler([](QtMsgType type, const QMessageLogContext&, const QString&) {
        if (type == QtWarningMsg || type == QtCriticalMsg || type == QtFatalMsg) iniWarning.store(true);
    })) { iniWarning.store(false); }
    ~IniWarnings() { qInstallMessageHandler(previous); }
    void check() const {
        // Qt otherwise turns an unregistered streamed QVariant into @Invalid().
        if (iniWarning.load()) reject("configuration_format", "This build cannot safely decode a value in the Qt configuration. Original files have been preserved.");
    }
};
QString pathOf(const QJsonObject& entry, bool writing = false)
{
    const auto path = entry.value("path").toString();
    const QFileInfo info(path);
    if (path.isEmpty() || path.contains(QChar('\0')) || !info.isAbsolute() || (writing && info.isSymLink())
        || (info.exists() && !info.isFile())) reject("invalid_request", "Choose a regular configuration file.");
    return QDir::cleanPath(path);
}
QByteArray bytes(const QString& path)
{
    if (!QFileInfo::exists(path)) return {};
    QFile input(path);
    if (!input.open(QIODevice::ReadOnly)) reject("file_error", "The configuration could not be read.");
    const auto value = input.read(MaxIni + 1);
    if (value.size() > MaxIni) reject("invalid_request", "The configuration exceeds the 16 MiB limit.");
    if (input.error() != QFile::NoError || !input.atEnd()) reject("file_error", "The configuration could not be read completely.");
    return value;
}
QString revision(const QByteArray& value, bool exists)
{
    return exists ? QString::fromLatin1(QCryptographicHash::hash(value, QCryptographicHash::Sha256).toHex()) : QStringLiteral("missing");
}
QVariant converted(const QVariant& value, const QJsonValue& type)
{
    if (type.isBool()) return value.toBool();
    if (type.isString()) return value.toString();
    if (type.isDouble()) {
        bool ok;
        const auto result = value.toLongLong(&ok);
        if (!ok || result < -2147483648LL || result > 2147483647LL)
            reject("invalid_request", "The configuration contains an invalid integer.");
        return result;
    }
    if (type.isArray()) {
        for (const auto& item : type.toArray())
            if (!item.isString()) reject("invalid_request", "The configuration schema is invalid.");
        return value.toStringList();
    }
    if (type.isObject()) {
        if (!type.toObject().isEmpty() || (value.userType() != QMetaType::QVariantMap && value.userType() != QMetaType::QVariantHash))
            reject("invalid_request", "The configuration contains an unsupported dictionary.");
        QVariantHash result;
        if (value.userType() == QMetaType::QVariantHash) result = value.toHash();
        else {
            const auto map = value.toMap();
            for (auto it = map.begin(); it != map.end(); ++it) result.insert(it.key(), it.value());
        }
        for (auto it = result.begin(); it != result.end(); ++it)
            if (it.value().userType() != QMetaType::QString)
                reject("invalid_request", "The configuration dictionary must contain strings.");
        return result;
    }
    reject("invalid_request", "The configuration schema is invalid.");
}
QJsonObject schemaOf(const QJsonObject& entry)
{
    if (!entry.value("defaults").isObject()) reject("invalid_request", "The configuration schema is missing.");
    const auto schema = entry.value("defaults").toObject();
    if (schema.isEmpty() || schema.size() > 256) reject("invalid_request", "The configuration schema is invalid.");
    for (auto it = schema.begin(); it != schema.end(); ++it) {
        if (it.key().size() > 512 || it.key().contains(QChar('\0')) || it.key().split('/').contains(QString()))
            reject("invalid_request", "The configuration key is invalid.");
        converted(it.value().toVariant(), it.value());
    }
    return schema;
}
QJsonObject values(QSettings& settings, const QJsonObject& schema)
{
    settings.setFallbacksEnabled(false);
    settings.allKeys();
    if (settings.status() != QSettings::NoError) reject("file_error", "The configuration is unreadable or is not a valid Qt INI file.");
    QJsonObject result;
    for (auto it = schema.begin(); it != schema.end(); ++it)
        result.insert(it.key(), QJsonValue::fromVariant(converted(settings.value(it.key(), it.value().toVariant()), it.value())));
    return result;
}
bool atomicWrite(const QString& path, const QByteArray& data, QFile::Permissions permissions)
{
    QSaveFile output(path);
    output.setDirectWriteFallback(false);
    return output.open(QIODevice::WriteOnly) && output.setPermissions(permissions)
        && output.write(data) == data.size() && output.commit();
}
QJsonArray filesOf(const QJsonObject& arguments)
{
    const auto files = arguments.value("files").toArray();
    if (files.isEmpty() || files.size() > 2) reject("invalid_request", "Choose one or two configuration files.");
    QStringList paths;
    for (const auto& value : files) {
        if (!value.isObject()) reject("invalid_request", "The configuration request is invalid.");
        const auto path = pathOf(value.toObject());
        if (paths.contains(path)) reject("invalid_request", "The configuration file was supplied twice.");
        paths.append(path);
        schemaOf(value.toObject());
    }
    return files;
}
}

QJsonObject KeyslotConfig::read(const QJsonObject& arguments)
{
    QJsonArray result;
    for (const auto& value : filesOf(arguments)) {
        const auto entry = value.toObject();
        const auto path = pathOf(entry);
        const bool exists = QFileInfo::exists(path);
        const auto original = bytes(path);
        QTemporaryDir temporary(QDir::tempPath() + "/keyslot-settings-read-XXXXXX");
        const auto stage = temporary.path() + "/settings.ini";
        if (!temporary.isValid() || !atomicWrite(stage, original, QFile::ReadOwner | QFile::WriteOwner))
            reject("file_error", "A private configuration snapshot could not be created.");
        IniWarnings warnings;
        QSettings settings(stage, QSettings::IniFormat);
        const auto data = values(settings, schemaOf(entry));
        warnings.check();
        if (revision(bytes(path), QFileInfo::exists(path)) != revision(original, exists))
            reject("conflict", "The configuration changed while it was read. Try again.");
        result.append(QJsonObject{{"path", path}, {"values", data}, {"revision", revision(original, exists)}});
    }
    return {{"files", result}};
}

QJsonObject KeyslotConfig::write(const QJsonObject& arguments)
{
    auto files = filesOf(arguments);
    std::vector<QJsonObject> ordered;
    for (const auto& value : files) ordered.push_back(value.toObject());
    std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) { return a.value("path").toString() < b.value("path").toString(); });
    std::vector<std::unique_ptr<QLockFile>> locks;
    for (const auto& entry : ordered) {
        const auto path = pathOf(entry, true);
        if (!QDir().mkpath(QFileInfo(path).absolutePath())) reject("file_error", "The configuration folder could not be created.");
        auto lock = std::make_unique<QLockFile>(path + ".lock");
        if (!lock->tryLock(0)) reject("conflict", "Another application is saving the configuration. Try again.");
        locks.push_back(std::move(lock));
    }
    QTemporaryDir temporary(QDir::tempPath() + "/keyslot-settings-XXXXXX");
    if (!temporary.isValid()) reject("file_error", "A private configuration staging folder could not be created.");
    struct Change { QString path, before, after; QByteArray original, replacement; bool existed; QFile::Permissions permissions; };
    std::vector<Change> changes;
    QJsonArray manifest;
    for (const auto& entry : ordered) {
        const auto path = pathOf(entry, true);
        const bool existed = QFileInfo::exists(path);
        if (existed) {
            QFile writable(path);
            if (!writable.open(QIODevice::ReadWrite)) reject("file_error", "The configuration is read-only. Original files have been preserved.");
        }
        const auto original = bytes(path);
        const auto permissions = existed ? QFileInfo(path).permissions() : QFile::ReadOwner | QFile::WriteOwner;
        const auto stage = temporary.path() + QString("/staged-%1.ini").arg(changes.size());
        const auto backup = temporary.path() + QString("/original-%1.ini").arg(changes.size());
        if (!atomicWrite(stage, original, QFile::ReadOwner | QFile::WriteOwner)
            || !atomicWrite(backup, original, QFile::ReadOwner | QFile::WriteOwner))
            reject("file_error", "The original configuration could not be staged safely.");
        const auto schema = schemaOf(entry);
        IniWarnings warnings;
        QSettings settings(stage, QSettings::IniFormat);
        const auto current = values(settings, schema);
        warnings.check();
        const auto updated = entry.value("values").toObject();
        const auto expected = entry.value("expected").toObject();
        for (auto it = expected.begin(); it != expected.end(); ++it) {
            if (!schema.contains(it.key())) reject("invalid_request", "The configuration comparison is invalid.");
            if (current.value(it.key()) != it.value())
                reject("conflict", "This setting changed in another application. Reopen it before saving.");
        }
        for (auto it = updated.begin(); it != updated.end(); ++it) {
            if (!schema.contains(it.key()) || !expected.contains(it.key())) reject("invalid_request", "The configuration update is invalid.");
            if (current.value(it.key()) != expected.value(it.key()))
                reject("conflict", "This setting changed in another application. Reopen Keyslot before saving it.");
            if (it.value().type() != schema.value(it.key()).type()
                || (it.value().isDouble() && (!std::isfinite(it.value().toDouble()) || std::floor(it.value().toDouble()) != it.value().toDouble())))
                reject("invalid_request", "The configuration value has the wrong type.");
            if (it.value().isArray()) for (const auto& item : it.value().toArray())
                if (!item.isString()) reject("invalid_request", "The configuration list must contain strings.");
            settings.setValue(it.key(), converted(it.value().toVariant(), schema.value(it.key())));
        }
        if (entry.contains("remove") && !entry.value("remove").isArray())
            reject("invalid_request", "Specify individual settings to reset.");
        QSet<QString> removed;
        const auto allKeys = settings.allKeys();
        for (const auto& value : entry.value("remove").toArray()) {
            const auto key = value.toString();
            if (!value.isString() || !schema.contains(key) || !expected.contains(key) || updated.contains(key) || removed.contains(key))
                reject("invalid_request", "The configuration reset is invalid.");
            if (current.value(key) != expected.value(key))
                reject("conflict", "This setting changed in another application. Reopen it before resetting it.");
            for (const auto& existing : allKeys) if (existing.startsWith(key + '/'))
                reject("invalid_request", "Only individual configuration values can be reset.");
            removed.insert(key);
            settings.remove(key);
        }
        settings.sync();
        warnings.check();
        if (settings.status() != QSettings::NoError) reject("file_error", "The configuration update could not be staged.");
        const auto replacement = bytes(stage);
        changes.push_back({path, revision(original, existed), revision(replacement, true), original, replacement, existed, permissions});
        manifest.append(QJsonObject{{"path", path}, {"existed", existed}, {"backup", backup}, {"qt_permissions", int(permissions)}});
    }
    if (!atomicWrite(temporary.path() + "/recovery.json", QJsonDocument(manifest).toJson(), QFile::ReadOwner | QFile::WriteOwner))
        reject("file_error", "Configuration recovery information could not be staged.");
    size_t committed = 0;
    try {
        for (const auto& change : changes) {
            if (revision(bytes(change.path), QFileInfo::exists(change.path)) != change.before)
                reject("conflict", "The configuration changed before it could be saved. Try again.");
            pathOf(QJsonObject{{"path", change.path}}, true);
            ++committed;
            if (!atomicWrite(change.path, change.replacement, change.permissions))
                reject("file_error", "The configuration could not be saved atomically.");
        }
        return read(arguments);
    } catch (...) {
        bool restored = true;
        while (committed) {
            const auto& change = changes[--committed];
            try {
                const auto now = revision(bytes(change.path), QFileInfo::exists(change.path));
                if (now == change.before) continue;
                pathOf(QJsonObject{{"path", change.path}}, true);
                if (now != change.after || (change.existed ? !atomicWrite(change.path, change.original, change.permissions) : !QFile::remove(change.path)))
                    restored = false;
            } catch (...) { restored = false; }
        }
        if (!restored) {
            temporary.setAutoRemove(false);
            throw Failure{"configuration_recovery", "The configuration rollback needs attention. Original files were retained privately.",
                          {{"recovery_path", temporary.path()}}};
        }
        throw;
    }
}
