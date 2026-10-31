// SPDX-License-Identifier: GPL-3.0-only
#include "KeyslotTotp.h"
#include "core/Base32.h"
#include "core/Clock.h"
#include "core/Entry.h"
#include "qrcode/QrCode.h"
#include <QBuffer>
#include <QImage>
#include <QPainter>
#include <QSvgRenderer>
#include <QUrl>
#include <cmath>

namespace {
[[noreturn]] void reject(const char* message) { throw KeyslotTotp::Failure{"invalid_request", message}; }
QString text(const QJsonObject& args, const char* key, const QString& fallback = {}) {
    if (!args.contains(key)) return fallback;
    if (!args.value(key).isString()) reject("Expected a text field.");
    return args.value(key).toString();
}
qint64 number(const QJsonObject& args, const char* key, qint64 low, qint64 high, qint64 fallback) {
    if (!args.contains(key)) return fallback;
    const auto value = args.value(key);
    const double n = value.toDouble(-1);
    if (!value.isDouble() || !std::isfinite(n) || std::floor(n) != n || n < low || n > high)
        reject("A one-time password setting is outside the supported range.");
    return static_cast<qint64>(n);
}
QString algorithm(Totp::Algorithm value) {
    if (value == Totp::Sha256) return "SHA-256";
    if (value == Totp::Sha512) return "SHA-512";
    return "SHA-1";
}
void valid(const QSharedPointer<Totp::Settings>& settings) {
    if (!Totp::checkValidSettings(settings).isEmpty()) reject("This entry has no valid one-time password settings.");
}
}
QJsonObject KeyslotTotp::config(const Entry* entry) {
    auto settings = entry->totpSettings();
    if (!settings) return {{"configured", false}, {"key", ""}, {"uri", ""}, {"mode", "standard"},
                          {"digits", 6}, {"period", 30}, {"algorithm", "SHA-1"}, {"valid", false}};
    const bool isValid = Totp::checkValidSettings(settings).isEmpty();
    return {{"configured", true}, {"valid", isValid}, {"key", settings->key},
            {"uri", isValid ? Totp::writeSettings(settings, entry->title(), entry->username(), true) : QString()},
            {"mode", settings->encoder.shortName == Totp::STEAM_SHORTNAME ? "steam" : Totp::hasCustomSettings(settings) ? "custom" : "standard"},
            {"digits", static_cast<qint64>(settings->digits)}, {"period", static_cast<qint64>(settings->step)},
            {"algorithm", algorithm(settings->algorithm)}};
}
QSharedPointer<Totp::Settings> KeyslotTotp::settings(const Entry* entry, const QJsonObject& args) {
    if (args.contains("uri")) {
        if (args.contains("key")) reject("Choose a setup link or a secret key, not both.");
        const auto uri = text(args, "uri").trimmed();
        const QUrl url(uri);
        if (!url.isValid() || url.scheme() != "otpauth" || url.host() != "totp")
            reject("Enter an otpauth://totp/ setup link.");
        auto result = Totp::parseSettings(uri);
        valid(result);
        return result;
    }
    auto key = text(args, "key").toUpper().remove(' ').remove('=').trimmed().toLatin1();
    if (key.isEmpty() || !Base32::sanitizeInput(key).startsWith(key))
        reject("Enter a nonempty Base32 secret key.");
    const auto mode = text(args, "mode", "standard");
    if (mode != "standard" && mode != "steam" && mode != "custom") reject("Choose standard, Steam or custom settings.");
    Totp::Algorithm hash = Totp::Sha1;
    const auto name = text(args, "algorithm", "SHA-1");
    if (name != "SHA-1" && name != "SHA-256" && name != "SHA-512") reject("Choose a supported one-time password algorithm.");
    if (mode == "custom") hash = name == "SHA-256" ? Totp::Sha256 : name == "SHA-512" ? Totp::Sha512 : Totp::Sha1;
    const auto digits = number(args, "digits", 1, 10, 6);
    const auto period = number(args, "period", 1, 86400, 30);
    auto format = entry->hasTotp() ? entry->totpSettings()->format : Totp::DEFAULT_FORMAT;
    if (format == Totp::LEGACY && mode == "custom") format = Totp::OTPURL;
    auto result = Totp::createSettings(QString::fromLatin1(key), mode == "steam" ? 5 : mode == "custom" ? digits : 6,
        mode == "custom" ? period : 30, format, mode == "steam" ? Totp::STEAM_SHORTNAME : QString(), hash);
    valid(result);
    return result;
}
QJsonObject KeyslotTotp::sample(const Entry* entry, const QJsonObject& args) {
    auto settings = entry->totpSettings();
    valid(settings);
    const auto ms = args.contains("at") ? number(args, "at", 1, 9007199254740LL, 1) * 1000
                                        : Clock::currentDateTimeUtc().toMSecsSinceEpoch();
    if (ms <= 0) reject("The system clock is outside the supported range.");
    bool ok = false;
    const auto code = Totp::generateTotp(settings, &ok, ms / 1000);
    if (!ok) reject("The one-time password could not be generated.");
    const qint64 period = settings->step;
    return {{"code", code}, {"time", ms / 1000}, {"period", period},
            {"remaining_ms", period * 1000 - ms % (period * 1000)}, {"digits", static_cast<qint64>(settings->digits)},
            {"encoder", settings->encoder.name}, {"algorithm", algorithm(settings->algorithm)}};
}
QByteArray KeyslotTotp::qr(const Entry* entry, bool png) {
    valid(entry->totpSettings());
    const auto uri = Totp::writeSettings(entry->totpSettings(), entry->title(), entry->username(), true);
    const QrCode code(uri);
    if (!code.isValid()) reject("These one-time password settings do not fit in a QR code.");
    QByteArray svg;
    QBuffer output(&svg);
    if (!output.open(QIODevice::WriteOnly)) reject("The QR code could not be created.");
    code.writeSvg(&output, 96);
    output.close();
    if (!png) return svg;
    QSvgRenderer renderer(svg);
    if (!renderer.isValid() || renderer.defaultSize().width() < 1) reject("The QR code could not be rendered.");
    const int modules = renderer.defaultSize().width();
    const int size = modules * qMax(1, 512 / modules);
    if (size > 1024) reject("The QR code is too large to display.");
    QImage image(size, size, QImage::Format_ARGB32);
    image.fill(Qt::white);
    QPainter painter(&image);
    renderer.render(&painter);
    painter.end();
    QByteArray bytes;
    QBuffer buffer(&bytes);
    if (!buffer.open(QIODevice::WriteOnly) || !image.save(&buffer, "PNG")) reject("The QR code could not be rendered.");
    return bytes;
}
