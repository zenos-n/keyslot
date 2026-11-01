// SPDX-License-Identifier: GPL-3.0-only
#include "KeyslotAuth.h"
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

void KeyslotAuth::configure(const QString& endpoint, qint64 pid) {
    if (socket.state() == QLocalSocket::ConnectedState && path == endpoint && broker == pid) return;
    socket.abort(); input.clear(); path.clear();
    struct stat info{};
    if (!QFileInfo(endpoint).isAbsolute() || ::lstat(QFile::encodeName(endpoint).constData(), &info)
        || !S_ISSOCK(info.st_mode) || info.st_uid != ::getuid() || (info.st_mode & 0077))
        throw Failure{"auth_unavailable", "The native authentication broker socket is not private."};
    socket.connectToServer(endpoint);
    if (!socket.waitForConnected(3000)) throw Failure{"auth_unavailable", "The native authentication broker is unavailable."};
    struct ucred credentials{}; socklen_t length = sizeof(credentials);
    if (::getsockopt(socket.socketDescriptor(), SOL_SOCKET, SO_PEERCRED, &credentials, &length)
        || credentials.uid != ::getuid() || pid <= 1 || credentials.pid != pid) { socket.abort(); throw Failure{"auth_unavailable", "The authentication broker identity could not be verified."}; }
    path = endpoint; broker = pid;
}
QJsonObject KeyslotAuth::request(const QJsonObject& args, int timeout) {
    if (socket.state() != QLocalSocket::ConnectedState) throw Failure{"auth_unavailable", "The native authentication broker stopped. Set up system authentication again."};
    auto frame = QJsonDocument(args).toJson(QJsonDocument::Compact) + '\n';
    if (frame.size() > 131072 || socket.write(frame) != frame.size()) throw Failure{"auth_error", "The authentication request could not be submitted."};
    QElapsedTimer clock; clock.start();
    while (socket.bytesToWrite() && clock.elapsed() < timeout)
        if (!socket.waitForBytesWritten(qMax(1, timeout - int(clock.elapsed())))) break;
    while (!input.contains('\n') && clock.elapsed() < timeout) {
        input += socket.readAll();
        if (input.size() > 131072) { socket.abort(); throw Failure{"auth_error", "The authentication response is invalid."}; }
        if (!input.contains('\n') && !socket.waitForReadyRead(qMax(1, timeout - int(clock.elapsed())))) break;
    }
    input += socket.readAll();
    const auto end = input.indexOf('\n');
    if (end < 0 || end > 131072 || end + 1 != input.size()) { socket.abort(); input.clear(); throw Failure{"auth_error", "Authentication stopped or timed out. Use the master password."}; }
    QJsonParseError error;
    const auto reply = QJsonDocument::fromJson(input.left(end), &error); input.fill(0); input.clear();
    if (error.error != QJsonParseError::NoError || !reply.isObject()) throw Failure{"auth_error", "The authentication response is invalid."};
    const auto object = reply.object();
    if (object.value("ok") != QJsonValue(true)) throw Failure{object.value("code").toString("auth_error"), object.value("message").toString("System authentication failed. Use the master password.")};
    return object;
}
