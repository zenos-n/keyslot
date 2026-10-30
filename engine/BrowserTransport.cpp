// SPDX-License-Identifier: GPL-3.0-only
// Browser encryption is the pinned upstream implementation; authorization stays in the GTK parent.
#include "browser/BrowserMessageBuilder.h"
#include "BrowserFraming.h"
#include "BrowserDeadline.h"
#include "browser/BrowserShared.h"
#include "core/Bootstrap.h"
#include "crypto/Crypto.h"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QDir>
#include <QFileInfo>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QPointer>
#include <QSet>
#include <QSocketNotifier>
#include <QStandardPaths>
#include <QTimer>
#include <QUuid>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr int Limit = BrowserShared::NATIVEMSG_MAX_LENGTH;
bool base64(const QString& value, int size) {
    const auto encoded = value.toLatin1();
    const auto bytes = QByteArray::fromBase64(encoded);
    return bytes.size() == size && QString::fromLatin1(bytes.toBase64()) == value;
}

struct Client {
    QString peerKey, publicKey, secretKey;
    quint64 generation = 0;
    QSet<QString> nonces;
};
struct Peer {
    QString id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    QByteArray input;
    QHash<QString, Client> clients;
};
struct Pending {
    QPointer<QLocalSocket> socket;
    QString client, action, nonce;
    quint64 generation;
    qint64 expires;
};
class Transport : public QObject {
    QElapsedTimer clock;
    QLocalServer server;
    QHash<QLocalSocket*, Peer> peers;
    QHash<QString, Pending> pending;
    QByteArray input, output;
    QByteArray alias, target;
    struct stat aliasInfo {};
    bool failed = false;
    QSocketNotifier inputReady{STDIN_FILENO, QSocketNotifier::Read};
    QSocketNotifier outputReady{STDOUT_FILENO, QSocketNotifier::Write};
    QTimer timer;

    void flush() {
        while (!output.isEmpty()) {
            const auto count = ::write(STDOUT_FILENO, output.constData(), output.size());
            if (count > 0) output.remove(0, count);
            else if (count < 0 && errno == EINTR) continue;
            else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            else { failed = true; QCoreApplication::exit(2); return; }
        }
        outputReady.setEnabled(!output.isEmpty());
    }
    void event(const QJsonObject& value) {
        const auto bytes = QJsonDocument(value).toJson(QJsonDocument::Compact) + '\n';
        if (bytes.size() > Limit || output.size() + bytes.size() > 4 * Limit) {
            QCoreApplication::exit(2);
            return;
        }
        output += bytes;
        flush();
    }
    void send(QLocalSocket* socket, const QJsonObject& value) {
        const auto bytes = QJsonDocument(value).toJson(QJsonDocument::Compact);
        if (bytes.size() > Limit || socket->bytesToWrite() + bytes.size() > 2 * Limit
            || socket->write(bytes) != bytes.size()) socket->abort();
        else socket->flush();
    }
    void error(QLocalSocket* socket, const QString& action, int code) {
        send(socket, browserMessageBuilder()->getErrorReply(action, code));
    }
    void cancel(QLocalSocket* socket, const QString& client = {}) {
        for (auto it = pending.begin(); it != pending.end();) {
            if (it->socket == socket && (client.isEmpty() || it->client == client)) {
                event({{"event", "cancel"}, {"id", it.key()}});
                it = pending.erase(it);
            } else ++it;
        }
    }
    void receive(QLocalSocket* socket, const QJsonObject& json) {
        auto& peer = peers[socket];
        const auto action = json.value("action").toString();
        const auto id = json.value("clientID").toString();
        const auto nonce = json.value("nonce").toString();
        if (action.isEmpty() || action.size() > 64 || id.isEmpty() || id.size() > 128) {
            error(socket, action, ERROR_KEEPASS_INCORRECT_ACTION);
            return;
        }
        if (!base64(nonce, 24)) {
            error(socket, action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE);
            return;
        }
        if (action == "change-public-keys") {
            const auto key = json.value("publicKey").toString();
            if (!base64(key, 32) || (!peer.clients.contains(id) && peer.clients.size() >= 8)) {
                error(socket, action, ERROR_KEEPASS_CLIENT_PUBLIC_KEY_NOT_RECEIVED);
                return;
            }
            cancel(socket, id);
            auto& client = peer.clients[id];
            client.secretKey.fill(QChar('\0'));
            const auto keys = browserMessageBuilder()->getKeyPair();
            client.peerKey = key;
            client.publicKey = keys.first;
            client.secretKey = keys.second;
            ++client.generation;
            client.nonces.clear();
            const auto replyNonce = browserMessageBuilder()->incrementNonce(nonce);
            client.nonces.insert(nonce);
            client.nonces.insert(replyNonce);
            auto response = browserMessageBuilder()->buildMessage(replyNonce);
            response.insert("action", action);
            response.insert("publicKey", client.publicKey);
            send(socket, response);
            return;
        }
        if (!peer.clients.contains(id)) {
            error(socket, action, ERROR_KEEPASS_CLIENT_PUBLIC_KEY_NOT_RECEIVED);
            return;
        }
        auto& client = peer.clients[id];
        const auto replyNonce = browserMessageBuilder()->incrementNonce(nonce);
        const auto encrypted = json.value("message").toString();
        const auto decoded = QByteArray::fromBase64(encrypted.toLatin1());
        if (client.nonces.contains(nonce) || client.nonces.contains(replyNonce) || client.nonces.size() >= 4096
            || decoded.size() < 16 || decoded.size() >= Limit || QString::fromLatin1(decoded.toBase64()) != encrypted) {
            error(socket, action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE);
            return;
        }
        const auto body = browserMessageBuilder()->decryptMessage(encrypted, nonce, client.peerKey, client.secretKey);
        if (body.isEmpty() || body.value("action").toString() != action) {
            error(socket, action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE);
            return;
        }
        client.nonces.insert(nonce);
        client.nonces.insert(replyNonce);
        if (pending.size() >= 128) {
            error(socket, action, ERROR_KEEPASS_TIMEOUT_OR_NOT_CONNECTED);
            return;
        }
        const auto request = QUuid::createUuid().toString(QUuid::WithoutBraces);
        pending.insert(request, {socket, id, action, replyNonce, client.generation,
            clock.elapsed() + ((action == "passkeys-register" || action == "passkeys-get")
                ? passkeyRequestTimeout(body.value("publicKey").toObject()) : 30000)});
        event({{"event", "request"}, {"id", request}, {"connection", peer.id}, {"client", id},
               {"generation", QString::number(client.generation)},
               {"public_key", client.peerKey}, {"action", action}, {"body", body},
               {"trigger_unlock", json.value("triggerUnlock").toString() == "true"}});
    }
    void respond(const QJsonObject& json) {
        if (json.contains("notification")) {
            const auto notification = json.value("notification").toString();
            if (json.size() == 1 && (notification == "database-locked" || notification == "database-unlocked")) {
                for (auto* socket : peers.keys()) send(socket, {{"action", notification}});
            }
            return;
        }
        const auto id = json.value("id").toString();
        if (!pending.contains(id)) return;
        const auto request = pending.take(id);
        auto* socket = request.socket.data();
        if (!socket || !peers.contains(socket) || !peers[socket].clients.contains(request.client)) return;
        const auto& client = peers[socket].clients[request.client];
        if (client.generation != request.generation) return;
        if (json.contains("error_code")) {
            const int code = json.value("error_code").toInt();
            error(socket, request.action, code >= 1 && code <= 33 ? code : ERROR_KEEPASS_ACTION_CANCELLED_OR_DENIED);
            return;
        }
        if (!json.value("result").isObject()) {
            error(socket, request.action, ERROR_KEEPASS_ACTION_CANCELLED_OR_DENIED);
            return;
        }
        const auto result = json.value("result").toObject();
        const bool validSuccess = !result.contains("success") || (request.action == "delete-entry"
            && result.value("success").isString()
            && (result.value("success").toString() == "true" || result.value("success").toString() == "false"));
        if (QJsonDocument(result).toJson(QJsonDocument::Compact).size() > (Limit / 2)
            || result.contains("nonce") || !validSuccess || result.contains("version")) {
            error(socket, request.action, ERROR_KEEPASS_CANNOT_ENCRYPT_MESSAGE);
            return;
        }
        send(socket, browserMessageBuilder()->buildResponse(request.action, request.nonce,
             result.toVariantMap(), client.peerKey, client.secretKey));
    }
    void readParent() {
        char bytes[65536];
        while (true) {
            const auto count = ::read(STDIN_FILENO, bytes, sizeof bytes);
            if (!count) { QCoreApplication::quit(); return; }
            if (count < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                QCoreApplication::exit(2); return;
            }
            input.append(bytes, count);
            while (input.contains('\n')) {
                const auto end = input.indexOf('\n');
                if (end > Limit) { QCoreApplication::exit(2); return; }
                const auto frame = input.left(end);
                input.remove(0, end + 1);
                QJsonParseError parse;
                const auto json = QJsonDocument::fromJson(frame, &parse);
                if (parse.error != QJsonParseError::NoError || !json.isObject()) {
                    QCoreApplication::exit(2); return;
                }
                respond(json.object());
            }
            if (input.size() > Limit) { QCoreApplication::exit(2); return; }
        }
    }
public:
    ~Transport() override {
        for (auto* socket : peers.keys()) {
            QObject::disconnect(socket, nullptr, this, nullptr);
            socket->abort();
            for (auto& client : peers[socket].clients) client.secretKey.fill(QChar('\0'));
        }
        server.close();
        struct stat current {};
        if (!alias.isEmpty() && !::lstat(alias.constData(), &current)
            && S_ISLNK(current.st_mode) && current.st_dev == aliasInfo.st_dev
            && current.st_ino == aliasInfo.st_ino
            && QFileInfo(QString::fromLocal8Bit(alias)).symLinkTarget() == QString::fromLocal8Bit(target)) {
            ::unlink(alias.constData());
        }
        input.fill('\0');
        output.fill('\0');
    }
    Transport() {
        ::fcntl(STDIN_FILENO, F_SETFL, ::fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK);
        ::fcntl(STDOUT_FILENO, F_SETFL, ::fcntl(STDOUT_FILENO, F_GETFL) | O_NONBLOCK);
        outputReady.setEnabled(false);
        connect(&inputReady, &QSocketNotifier::activated, this, [this] { readParent(); });
        connect(&outputReady, &QSocketNotifier::activated, this, [this] { flush(); });
        // Qt's explicit permission option may rename over an existing socket; bind directly instead.
        server.setSocketOptions(QLocalServer::NoOptions);
        connect(&server, &QLocalServer::newConnection, this, [this] {
            while (server.hasPendingConnections()) {
                auto* socket = server.nextPendingConnection();
                if (peers.size() >= 8) { socket->abort(); socket->deleteLater(); continue; }
                peers.insert(socket, {});
                socket->setReadBufferSize(Limit + 1);
                connect(socket, &QLocalSocket::readyRead, this, [this, socket] {
                    auto& buffer = peers[socket].input;
                    buffer += socket->readAll();
                    if (buffer.size() > Limit) { socket->abort(); return; }
                    while (!buffer.isEmpty()) {
                        if (buffer[0] == ' ' || buffer[0] == '\n' || buffer[0] == '\r' || buffer[0] == '\t') {
                            buffer.remove(0, 1); continue;
                        }
                        const int end = browserFrameEnd(buffer);
                        if (buffer[0] != '{' || end < 0) { socket->abort(); return; }
                        if (!end) return;
                        QJsonParseError parse;
                        const auto json = QJsonDocument::fromJson(buffer.left(end), &parse);
                        buffer.remove(0, end);
                        if (parse.error != QJsonParseError::NoError || !json.isObject()) { socket->abort(); return; }
                        receive(socket, json.object());
                        if (!peers.contains(socket)) return;
                    }
                });
                connect(socket, &QLocalSocket::disconnected, this, [this, socket] {
                    cancel(socket);
                    for (auto& client : peers[socket].clients) client.secretKey.fill(QChar('\0'));
                    event({{"event", "disconnected"}, {"connection", peers[socket].id}});
                    peers.remove(socket);
                    socket->deleteLater();
                });
            }
        });
        connect(&timer, &QTimer::timeout, this, [this] {
            const auto now = clock.elapsed();
            const auto ids = pending.keys();
            for (const auto& id : ids) {
                if (!pending.contains(id) || pending[id].expires > now) continue;
                const auto request = pending.value(id);
                event({{"event", "cancel"}, {"id", id}});
                if (request.action == "passkeys-register" || request.action == "passkeys-get") {
                    respond({{"id", id}, {"result", QJsonObject{{"response", QJsonObject{{"errorCode", ERROR_PASSKEYS_REQUEST_CANCELED}}}}}});
                } else {
                    pending.remove(id);
                    if (request.socket) error(request.socket, request.action, ERROR_KEEPASS_TIMEOUT_OR_NOT_CONNECTED);
                }
            }
        });
        timer.start(1000);
    }
    bool start() {
        clock.start();
        const auto runtime = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
        struct stat info {};
        if (::lstat(QFile::encodeName(runtime).constData(), &info) || !S_ISDIR(info.st_mode)
            || info.st_uid != ::getuid() || (info.st_mode & 0077)) return false;
        const auto directory = runtime + "/app/org.keepassxc.KeePassXC";
        if (!QDir().mkpath(directory)) return false;
        const auto endpoint = directory + "/org.keepassxc.KeePassXC.BrowserServer";
        const auto encoded = QFile::encodeName(endpoint);
        if (!::lstat(encoded.constData(), &info) || errno != ENOENT) return false;
        // Qt unlinks its bound name on close, even if another app has replaced it.
        const auto privateEndpoint = directory + "/Keyslot.BrowserServer";
        if (!server.listen(privateEndpoint)) return false;
        target = QFile::encodeName(privateEndpoint);
        if (::symlink(target.constData(), encoded.constData())) return false;
        alias = encoded;
        if (::lstat(alias.constData(), &aliasInfo)) return false;
        event({{"event", "ready"}, {"protocol", 1}, {"socket", endpoint}});
        return !failed;
    }
};
}
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    Bootstrap::disableCoreDumps();
    ::umask(0077);
    std::signal(SIGPIPE, SIG_IGN);
    if (!Crypto::init()) return 1;
    Bootstrap::bootstrap();
    Transport transport;
    if (!transport.start()) return 2;
    return app.exec();
}
