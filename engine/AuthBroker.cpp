// SPDX-License-Identifier: GPL-3.0-only
// Native-only session credentials; the GTK control pipe carries handles and process IDs.
#include "core/Bootstrap.h"
#include "crypto/Crypto.h"
#include "crypto/Random.h"
#include "crypto/SymmetricCipher.h"
#include <botan/mem_ops.h>
#include <QCoreApplication>
#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDBusMetaType>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QPointer>
#include <QSocketNotifier>
#include <QTimer>
#include <QUuid>
#include <cmath>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <keyutils.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

using Details = QMap<QString, QString>;
struct Subject { QString kind; QVariantMap details; };
struct Authorization { bool authorized = false, challenge = false; Details details; };
Q_DECLARE_METATYPE(Subject)
Q_DECLARE_METATYPE(Authorization)
Q_DECLARE_METATYPE(Details)
QDBusArgument& operator<<(QDBusArgument& args, const Subject& value) { args.beginStructure(); args << value.kind << value.details; args.endStructure(); return args; }
const QDBusArgument& operator>>(const QDBusArgument& args, Subject& value) { args.beginStructure(); args >> value.kind >> value.details; args.endStructure(); return args; }
QDBusArgument& operator<<(QDBusArgument& args, const Authorization& value) { args.beginStructure(); args << value.authorized << value.challenge << value.details; args.endStructure(); return args; }
const QDBusArgument& operator>>(const QDBusArgument& args, Authorization& value) { args.beginStructure(); args >> value.authorized >> value.challenge >> value.details; args.endStructure(); return args; }

namespace {
const QString Service = QStringLiteral("org.freedesktop.PolicyKit1");
const QString Object = QStringLiteral("/org/freedesktop/PolicyKit1/Authority");
const QString Interface = QStringLiteral("org.freedesktop.PolicyKit1.Authority");
const QString Action = QStringLiteral("com.neg-zero.keyslot.unlockDatabase");
void wipe(QByteArray& bytes) { if (!bytes.isEmpty()) Botan::secure_scrub_memory(bytes.data(), bytes.size()); bytes.clear(); }
QByteArray startTime(qint64 pid, qint64 parent = 0) {
    QFile stat("/proc/" + QString::number(pid) + "/stat");
    if (!stat.open(QIODevice::ReadOnly)) return {};
    const auto line = stat.readAll(); const auto tail = line.mid(line.lastIndexOf(')') + 2).simplified().split(' ');
    if (tail.size() < 20 || (parent && tail[1].toLongLong() != parent)) return {};
    return tail[19];
}
struct Record {
    QByteArray encrypted;
    QString path, generation;
    key_serial_t key = -1;
    QPointer<QLocalSocket> enrollment;
    bool committed = false;
};
struct Peer {
    QPointer<QLocalSocket> socket;
    QByteArray input;
    QString cancellation, token, generation;
    bool busy = false, alive = true;
};
bool connected(const QSharedPointer<Peer>& peer) {
    if (!peer->alive || !peer->socket || peer->socket->state() != QLocalSocket::ConnectedState) return false;
    char byte; const auto result = ::recv(peer->socket->socketDescriptor(), &byte, 1, MSG_PEEK | MSG_DONTWAIT);
    return result > 0 || (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR));
}
class Broker : public QObject {
    QLocalServer server;
    QDBusConnection bus;
    QMap<qint64, QByteArray> allowed;
    QMap<QLocalSocket*, QSharedPointer<Peer>> peers;
    QMap<QString, Record> records;
    QPointer<QLocalSocket> authenticating;
    QByteArray control;
    qint64 parent;
    int parentDescriptor;
    bool available = false;
    QString unavailable = "Install Keyslot's Polkit action system-wide, then use an active GNOME session with an authentication agent.";
    bool parentAlive() const {
        struct pollfd state[2]{{parentDescriptor, POLLIN, 0}, {STDIN_FILENO, 0, 0}};
        // POLLHUP is reported regardless of events, even before control-pipe EOF has reached the Qt notifier.
        return ::poll(state, 2, 0) == 0;
    }
    void reply(const QSharedPointer<Peer>& peer, QJsonObject object) {
        if (!connected(peer) || !parentAlive()) return;
        object.insert("ok", true); peer->socket->write(QJsonDocument(object).toJson(QJsonDocument::Compact) + '\n');
        peer->socket->flush();
    }
    void error(const QSharedPointer<Peer>& peer, const QString& message, const QString& code = "auth_error") {
        if (!connected(peer)) return;
        peer->socket->write(QJsonDocument(QJsonObject{{"ok", false}, {"code", code}, {"message", message}}).toJson(QJsonDocument::Compact) + '\n'); peer->socket->flush();
    }
    bool authority() {
        if (!bus.isConnected() || !bus.interface()) return false;
        const auto owner = bus.interface()->serviceUid(Service);
        return owner.isValid() && owner.value() == 0;
    }
    QDBusMessage message(const QString& method) { return QDBusMessage::createMethodCall(Service, Object, Interface, method); }
    bool policy() {
        if (!authority()) return false;
        auto request = message("EnumerateActions"); request.setArguments({QString()});
        const auto response = bus.call(request, QDBus::Block, 3000);
        if (response.type() != QDBusMessage::ReplyMessage || response.arguments().size() != 1) return false;
        const auto list = response.arguments().first().value<QDBusArgument>();
        if (list.currentSignature() != "a(ssssssuuua{ss})") return false;
        list.beginArray();
        bool found = false;
        while (!list.atEnd()) {
            QString id, description, prompt, vendor, url, icon; uint any, inactive, active; Details annotations;
            list.beginStructure(); list >> id >> description >> prompt >> vendor >> url >> icon >> any >> inactive >> active >> annotations; list.endStructure();
            if (id == Action) found = any == 0 && inactive == 0 && active == 1;
        }
        list.endArray(); return found;
    }
    void forget(const QString& token) {
        const auto record = records.take(token);
        if (record.key > 0) ::keyctl_revoke(record.key);
        for (const auto& peer : peers) if (peer->token == token) cancel(peer);
    }
    void cancel(const QSharedPointer<Peer>& peer) {
        if (!peer->cancellation.isEmpty()) {
            auto request = message("CancelCheckAuthorization"); request.setArguments({peer->cancellation}); bus.asyncCall(request, 3000);
        }
        peer->cancellation.clear(); peer->busy = false;
        if (authenticating == peer->socket) authenticating.clear();
    }
    void authenticate(const QSharedPointer<Peer>& peer, const QString& token) {
        if (!available || !authority()) { error(peer, unavailable, "auth_unavailable"); return; }
        if (authenticating) { error(peer, "Finish or cancel the current system authentication first."); return; }
        if (!records.contains(token) || !records[token].committed) { error(peer, "This session credential is no longer available. Use the master password.", "auth_missing"); return; }
        peer->busy = true; peer->token = token; peer->generation = records[token].generation;
        peer->cancellation = QUuid::createUuid().toString(QUuid::WithoutBraces); authenticating = peer->socket;
        // The authority resolves our unique system-bus name to its real process/session identity.
        Subject subject{QStringLiteral("system-bus-name"), {{"name", bus.baseService()}}};
        auto request = message("CheckAuthorization");
        request.setArguments({QVariant::fromValue(subject), Action, QVariant::fromValue(Details{}), uint(1), peer->cancellation});
        const auto cancellation = peer->cancellation;
        auto* watcher = new QDBusPendingCallWatcher(bus.asyncCall(request, 120000), this);
        connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, peer, cancellation](QDBusPendingCallWatcher* watcher) {
            QDBusPendingReply<Authorization> result = *watcher; watcher->deleteLater();
            if (!connected(peer) || !parentAlive() || peer->cancellation != cancellation) return;
            cancel(peer);
            if (result.isError() || !result.value().authorized || !records.contains(peer->token)
                || records[peer->token].generation != peer->generation || !authority()) {
                error(peer, "System authentication was denied, cancelled, or became unavailable. Use the master password or try again."); return;
            }
            const auto& record = records[peer->token];
            QByteArray material(44, 0);
            if (::keyctl_read(record.key, material.data(), material.size()) != material.size()) {
                wipe(material); error(peer, "The Linux session key is unavailable. Set up system authentication again.", "auth_missing"); return;
            }
            auto key = material.left(32), iv = material.mid(32); auto payload = record.encrypted;
            SymmetricCipher cipher;
            const bool valid = cipher.init(SymmetricCipher::Aes256_GCM, SymmetricCipher::Decrypt, key, iv) && cipher.finish(payload);
            wipe(key); wipe(iv); wipe(material);
            if (!valid || !connected(peer) || !parentAlive()) { wipe(payload); error(peer, "The session credential could not be decrypted.", "auth_missing"); return; }
            const auto credential = QJsonDocument::fromJson(payload).object(); wipe(payload);
            if (credential.value("path").toString() != record.path) { error(peer, "The session credential belongs to another vault."); return; }
            reply(peer, {{"credentials", credential}});
        });
        QTimer::singleShot(121000, watcher, [this, peer, cancellation] {
            if (peer->cancellation == cancellation) { cancel(peer); error(peer, "System authentication timed out. Use the master password."); }
        });
    }
    void request(const QSharedPointer<Peer>& peer, const QJsonObject& request) {
        const auto method = request.value("method").toString();
        if (peer->busy) { peer->socket->abort(); return; }
        if (method == "get") {
            const auto token = request.value("token").toString();
            if (!records.contains(token) || records[token].path != request.value("path").toString()) {
                error(peer, "This system-authentication credential is unavailable for this vault.", "auth_missing"); return;
            }
            authenticate(peer, token); return;
        }
        if (method != "put" || !available || !request.value("credentials").isObject() || records.size() >= 128) {
            error(peer, available ? "The session credential request is invalid or the session limit was reached." : unavailable, "auth_unavailable"); return;
        }
        auto credential = request.value("credentials").toObject(); const auto path = credential.value("path").toString();
        auto payload = QJsonDocument(credential).toJson(QJsonDocument::Compact);
        if (path.isEmpty() || QFileInfo(path).canonicalFilePath() != path || payload.size() > 65536) {
            wipe(payload); error(peer, "The session credential path or size is invalid."); return;
        }
        auto key = randomGen()->randomArray(32), iv = randomGen()->randomArray(12); auto material = key + iv;
        SymmetricCipher cipher;
        const bool valid = cipher.init(SymmetricCipher::Aes256_GCM, SymmetricCipher::Encrypt, key, iv) && cipher.finish(payload);
        wipe(key); wipe(iv);
        if (!valid) { wipe(material); wipe(payload); error(peer, "The session credential could not be encrypted."); return; }
        const auto token = QUuid::createUuid().toString(QUuid::WithoutBraces);
        const auto serial = ::add_key("user", ("keyslot:" + token).toUtf8().constData(), material.constData(), material.size(), KEY_SPEC_PROCESS_KEYRING);
        wipe(material);
        if (serial < 0 || ::keyctl_setperm(serial, KEY_POS_ALL)) {
            if (serial > 0) ::keyctl_revoke(serial);
            wipe(payload); error(peer, "The private Linux process keyring is unavailable.", "auth_unavailable"); return;
        }
        records.insert(token, {std::move(payload), path, QUuid::createUuid().toString(), serial, peer->socket, false});
        QTimer::singleShot(10000, this, [this, token] { if (records.contains(token) && !records[token].committed) forget(token); });
        reply(peer, {{"token", token}});
    }
    void controlRequest(const QJsonObject& request) {
        const auto method = request.value("method").toString(); const auto id = request.value("id");
        bool ok = true;
        if (method == "register") {
            const double n = request.value("pid").toDouble(-1);
            if (!std::isfinite(n) || std::floor(n) != n || n <= 1 || n > 2147483647 || allowed.size() >= 128) ok = false;
            else {
                const qint64 pid = qint64(n); const auto time = startTime(pid, parent);
                if (time.isEmpty()) ok = false;
                else allowed.insert(pid, time);
            }
        } else if (method == "commit") {
            const auto token = request.value("token").toString();
            if (!records.contains(token) || !records[token].enrollment || records[token].enrollment->state() != QLocalSocket::ConnectedState) ok = false;
            else { records[token].committed = true; records[token].enrollment.clear(); }
        } else if (method == "forget") forget(request.value("token").toString());
        else if (method == "unregister") allowed.remove(request.value("pid").toVariant().toLongLong());
        else if (method != "status") ok = false;
        const auto frame = QJsonDocument(QJsonObject{{"id", id}, {"ok", ok}, {"available", available}, {"message", available ? QString() : unavailable}}).toJson(QJsonDocument::Compact) + '\n';
        if (::write(STDOUT_FILENO, frame.constData(), frame.size()) != frame.size()) QCoreApplication::quit();
    }
public:
    Broker(const QString& endpoint, qint64 owner, int parentFd) : bus(QDBusConnection::connectToBus("unix:path=/run/dbus/system_bus_socket", "keyslot-auth-system")), parent(owner), parentDescriptor(parentFd) {
        const auto ring = ::keyctl_get_keyring_ID(KEY_SPEC_PROCESS_KEYRING, 1);
        available = ring > 0 && ::keyctl_setperm(ring, KEY_POS_ALL) == 0 && policy();
        server.setSocketOptions(QLocalServer::UserAccessOption);
        if (!server.listen(endpoint)) return;
        connect(&server, &QLocalServer::newConnection, this, [this] {
            while (server.hasPendingConnections()) {
                auto* socket = server.nextPendingConnection(); struct ucred credentials{}; socklen_t size = sizeof(credentials);
                if (!socket) continue;
                if (::getsockopt(socket->socketDescriptor(), SOL_SOCKET, SO_PEERCRED, &credentials, &size)
                    || credentials.uid != ::getuid() || !allowed.contains(credentials.pid)
                    || allowed.take(credentials.pid) != startTime(credentials.pid, parent) || peers.size() >= 128) {
                    socket->abort(); socket->deleteLater(); continue;
                }
                auto peer = QSharedPointer<Peer>::create(); peer->socket = socket; peers.insert(socket, peer);
                connect(socket, &QLocalSocket::disconnected, this, [this, socket, peer] {
                    peer->alive = false; cancel(peer); peers.remove(socket);
                    const auto tokens = records.keys();
                    for (const auto& token : tokens) if (!records[token].committed && records[token].enrollment == socket) forget(token);
                    socket->deleteLater();
                });
                connect(socket, &QLocalSocket::readyRead, this, [this, peer] {
                    peer->input += peer->socket->readAll();
                    if (peer->input.size() > 131072) { peer->socket->abort(); return; }
                    const auto end = peer->input.indexOf('\n'); if (end < 0) return;
                    if (end + 1 != peer->input.size()) { peer->socket->abort(); return; }
                    QJsonParseError error; const auto document = QJsonDocument::fromJson(peer->input.left(end), &error); wipe(peer->input);
                    if (error.error != QJsonParseError::NoError || !document.isObject()) { peer->socket->abort(); return; }
                    request(peer, document.object());
                });
                QTimer::singleShot(10000, socket, [peer] { if (peer->socket && !peer->busy && !peer->input.isEmpty()) peer->socket->abort(); });
            }
        });
        ::fcntl(STDIN_FILENO, F_SETFL, ::fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK);
        auto* notifier = new QSocketNotifier(STDIN_FILENO, QSocketNotifier::Read, this);
        connect(notifier, &QSocketNotifier::activated, this, [this] {
            char chunk[4096]; const auto count = ::read(STDIN_FILENO, chunk, sizeof(chunk));
            if (count == 0) { QCoreApplication::quit(); return; }
            if (count < 0) { if (errno != EAGAIN && errno != EINTR) QCoreApplication::quit(); return; }
            control.append(chunk, int(count)); if (control.size() > 65536) { QCoreApplication::quit(); return; }
            while (control.contains('\n')) {
                const auto end = control.indexOf('\n'); const auto request = QJsonDocument::fromJson(control.left(end)).object(); control.remove(0, end + 1); controlRequest(request);
            }
        });
        const auto ready = QJsonDocument(QJsonObject{{"event", "ready"}, {"protocol", 1}, {"available", available}, {"message", available ? QString() : unavailable}}).toJson(QJsonDocument::Compact) + '\n';
        if (::write(STDOUT_FILENO, ready.constData(), ready.size()) != ready.size()) server.close();
    }
    bool listening() const { return server.isListening(); }
    ~Broker() {
        server.close();
        for (const auto& peer : peers) {
            cancel(peer); peer->alive = false;
            if (peer->socket) { QObject::disconnect(peer->socket, nullptr, this, nullptr); peer->socket->abort(); }
        }
        peers.clear();
        for (const auto& record : records) if (record.key > 0) ::keyctl_revoke(record.key);
        records.clear();
    }
};
}
int main(int argc, char** argv) {
    const auto parent = ::getppid();
    if (::signal(SIGTERM, SIG_DFL) == SIG_ERR || parent <= 1 || ::prctl(PR_SET_DUMPABLE, 0)) return 1;
    // A pidfd follows the whole GTK process; PDEATHSIG would follow its short-lived launching worker thread.
    const int parentFd = ::syscall(SYS_pidfd_open, parent, 0);
    if (parentFd < 0 || ::getppid() != parent) { if (parentFd >= 0) ::close(parentFd); return 1; }
    QCoreApplication app(argc, argv); Bootstrap::disableCoreDumps();
    if (app.arguments().size() != 3 || app.arguments()[2].toLongLong() != parent || !Crypto::init()) return 1;
    qDBusRegisterMetaType<Subject>(); qDBusRegisterMetaType<Authorization>(); qDBusRegisterMetaType<Details>();
    const QFileInfo endpoint(app.arguments()[1]), directory(endpoint.absolutePath()); struct stat info{};
    if (::lstat(QFile::encodeName(directory.absoluteFilePath()).constData(), &info) || !S_ISDIR(info.st_mode)
        || info.st_uid != ::getuid() || (info.st_mode & 0077)) return 1;
    Broker broker(endpoint.absoluteFilePath(), parent, parentFd);
    QSocketNotifier watcher(parentFd, QSocketNotifier::Read);
    QObject::connect(&watcher, &QSocketNotifier::activated, &app, [&] { watcher.setEnabled(false); app.quit(); });
    const auto status = broker.listening() ? app.exec() : 1;
    watcher.setEnabled(false); ::close(parentFd);
    return status;
}
