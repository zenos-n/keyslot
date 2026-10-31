// SPDX-License-Identifier: GPL-3.0-only
#include "KeyslotNetwork.h"
#include <QEventLoop>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>

KeyslotNetwork::Reply KeyslotNetwork::get(const QUrl& url, int limit, int timeout,
    const QList<QPair<QByteArray, QByteArray>>& headers)
{
    Reply result;
    if (limit < 1 || timeout < 1 || (url.scheme() != "https" && url.scheme() != "http") || !url.userInfo().isEmpty()) {
        result.error = "The network request is invalid."; return result;
    }
    QNetworkAccessManager manager;
    QNetworkRequest request(url);
    request.setRawHeader("User-Agent", "Keyslot");
    for (const auto& header : headers) request.setRawHeader(header.first, header.second);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    request.setAttribute(QNetworkRequest::CacheSaveControlAttribute, false);
    request.setAttribute(QNetworkRequest::CookieLoadControlAttribute, QNetworkRequest::Manual);
    request.setAttribute(QNetworkRequest::CookieSaveControlAttribute, QNetworkRequest::Manual);
    auto* reply = manager.get(request);
    reply->setReadBufferSize(limit + 1);
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    bool oversized = false, timedOut = false;
    auto receive = [&] {
        result.bytes += reply->read(limit + 1 - result.bytes.size());
        if (result.bytes.size() > limit) { oversized = true; reply->abort(); }
    };
    QObject::connect(reply, &QIODevice::readyRead, &loop, receive);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, [&] { timedOut = true; reply->abort(); loop.quit(); });
    timer.start(timeout);
    if (!reply->isFinished()) loop.exec();
    receive();
    result.status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    result.redirect = reply->attribute(QNetworkRequest::RedirectionTargetAttribute).toUrl();
    if (oversized) result.error = "The response exceeded the download limit.";
    else if (timedOut) result.error = "The network request timed out.";
    else if (reply->error() != QNetworkReply::NoError) result.error = "The server could not be reached securely or refused the request.";
    if (!result.error.isEmpty()) result.bytes.clear();
    return result;
}
