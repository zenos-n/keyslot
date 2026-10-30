// SPDX-License-Identifier: GPL-3.0-only
// Native-only key transfer; the GTK parent's control pipe carries process IDs/status only.
#include "core/Bootstrap.h"
#include "core/Config.h"
#include "crypto/Crypto.h"
#include "sshagent/BinaryStream.h"
#include "sshagent/KeeAgentSettings.h"
#include "sshagent/OpenSSHKey.h"
#include "sshagent/SSHAgent.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QPointer>
#include <QSet>
#include <QSocketNotifier>
#include <QTemporaryDir>
#include <QTimer>
#include <QUuid>
#include <cerrno>
#include <csignal>
#include <cmath>
#include <limits>
#include <chrono>
#include <algorithm>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr int FrameLimit = 4 * 1024 * 1024;
volatile sig_atomic_t signalWrite = -1;
void stopSignal(int) {
    const auto saved = errno;
    const char byte = 1;
    const int descriptor = signalWrite;
    if (descriptor >= 0) ::write(descriptor, &byte, 1);
    errno = saved;
}
qint64 monotonicNow() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
struct Problem { QString message; };
[[noreturn]] void reject(const char* message) { throw Problem{QString::fromUtf8(message)}; }
QString text(const QJsonObject& value, const char* name, bool required = false) {
    const auto item = value.value(name);
    if ((required || value.contains(name)) && !item.isString()) reject("Invalid SSH text field.");
    const auto result = item.toString();
    if ((required && result.isEmpty()) || result.size() > FrameLimit || result.contains(QChar('\0')))
        reject("Invalid SSH text field.");
    return result;
}
bool flag(const QJsonObject& value, const char* name) {
    if (value.contains(name) && !value.value(name).isBool()) reject("Invalid SSH option.");
    return value.value(name).toBool();
}
QByteArray bytes(const QJsonObject& value, const char* name) {
    const auto encoded = text(value, name, true).toLatin1();
    const auto result = QByteArray::fromBase64(encoded);
    if (result.isEmpty() || result.toBase64() != encoded || result.size() > 1024 * 1024)
        reject("Invalid SSH key data.");
    return result;
}
struct Owner {
    QUuid id = QUuid::createUuid();
    qint64 pid = 0;
    QPointer<QLocalSocket> socket;
    QByteArray input;
    bool alive = true, busy = false;
};
bool ownerActive(const QSharedPointer<Owner>& owner) {
    if (!owner->alive || !owner->socket || owner->socket->state() != QLocalSocket::ConnectedState) return false;
    char byte;
    const auto result = ::recv(owner->socket->socketDescriptor(), &byte, 1, MSG_PEEK | MSG_DONTWAIT);
    return result > 0 || (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR));
}
struct Identity {
    QSharedPointer<Owner> owner;
    QSharedPointer<OpenSSHKey> key;
    QString agent, entry, stamp;
    QStringList paths;
    bool removeOnLock = false, uncertain = false;
};
struct RemovalReview {
    QUuid owner;
    QString agent, target, stamp;
    QList<QSharedPointer<OpenSSHKey>> keys;
    QHash<QString, QString> ownership;
    qint64 expires = 0;
    bool clear = false;
};
QString identityId(const QString& stamp, const OpenSSHKey& key) { return stamp + QChar('\0') + key.fingerprint(); }
QString socketStamp(const QString& path) {
    struct stat info {};
    if (::stat(QFile::encodeName(path).constData(), &info) || !S_ISSOCK(info.st_mode))
        reject("The SSH agent socket is unavailable.");
    return QString::number(qulonglong(info.st_dev)) + ':' + QString::number(qulonglong(info.st_ino));
}

class Relay : public QObject {
    QLocalServer server;
    QHash<QLocalSocket*, QSharedPointer<Owner>> peers;
    QSet<qint64> allowed;
    QHash<QString, Identity> identities;
    QHash<QString, RemovalReview> removals;
    QByteArray parentInput, parentOutput;
    QSocketNotifier inputReady{STDIN_FILENO, QSocketNotifier::Read};
    QSocketNotifier outputReady{STDOUT_FILENO, QSocketNotifier::Write};
    bool stopping = false, finalized = false;
    int activeRequests = 0;
    QSet<QString> shutdownUnavailable;
    bool cleanupOK() const {
        for (const auto& record : identities)
            if (record.uncertain || (!record.owner->alive && record.removeOnLock)) return false;
        return true;
    }

    void flushParent() {
        while (!parentOutput.isEmpty()) {
            const auto written = ::write(STDOUT_FILENO, parentOutput.constData(), parentOutput.size());
            if (written > 0) parentOutput.remove(0, written);
            else if (written < 0 && errno == EINTR) continue;
            else if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            else { parentOutput.clear(); shutdown(); break; }
        }
        outputReady.setEnabled(!parentOutput.isEmpty());
        if (stopping && finalized && peers.isEmpty() && parentOutput.isEmpty()) QCoreApplication::quit();
    }
    void parentEvent(const QJsonObject& event) {
        const auto data = QJsonDocument(event).toJson(QJsonDocument::Compact) + '\n';
        if (parentOutput.size() + data.size() > 65536) { shutdown(); return; }
        parentOutput += data;
        flushParent();
    }
    bool send(const QSharedPointer<Owner>& owner, const QJsonObject& result) {
        if (!owner->alive || !owner->socket) return false;
        auto data = QJsonDocument(result).toJson(QJsonDocument::Compact) + '\n';
        if (data.size() > FrameLimit) data = QJsonDocument(QJsonObject{{"id", result.value("id")},
            {"error", "The SSH metadata response is too large."}}).toJson(QJsonDocument::Compact) + '\n';
        if (owner->socket->bytesToWrite() + data.size() > FrameLimit
            || owner->socket->write(data) != data.size()) { owner->socket->abort(); return false; }
        owner->socket->flush();
        return true;
    }
    void selectAgent(const QString& path, const QString& provider = {}) {
        if (!QDir::isAbsolutePath(path) || path.size() > 4096 || path.contains(QChar('\0')))
            reject("Choose an absolute SSH agent socket path.");
        config()->set(Config::SSHAgent_AuthSockOverride, path);
        config()->set(Config::SSHAgent_SecurityKeyProviderOverride, provider);
    }
    QList<QSharedPointer<OpenSSHKey>> list(SSHAgent& agent) {
        QList<QSharedPointer<OpenSSHKey>> result;
        if (!agent.listIdentities(result)) reject("The SSH agent could not list its keys.");
        return result;
    }
    bool present(SSHAgent& agent, const OpenSSHKey& key) {
        for (const auto& candidate : list(agent)) if (*candidate == key) return true;
        return false;
    }
    QString ownership(const QString& stamp, const OpenSSHKey& key) const {
        const auto record = identities.constFind(identityId(stamp, key));
        if (record == identities.cend() || record->stamp != stamp) return {};
        return record->owner->id.toString() + '/' + record->entry;
    }
    QJsonObject keyInfo(const QSharedPointer<Owner>& owner, const QString& socket, const QString& stamp, const OpenSSHKey& key) const {
        const auto record = identities.constFind(identityId(stamp, key));
        const bool managed = record != identities.cend() && record->stamp == stamp;
        return {{"fingerprint", key.fingerprint()}, {"type", key.type()}, {"comment", key.comment().left(1024)},
            {"public_key", key.publicKey()}, {"socket", socket}, {"owned", managed && record->owner == owner},
            {"other_vault", managed && record->owner != owner}, {"cleanup_pending", managed && !record->owner->alive}};
    }
    bool remove(const QString& id) {
        if (!identities.contains(id)) return true;
        const auto record = identities.value(id);
        try {
            QString route;
            for (const auto& path : record.paths) {
                try { if (socketStamp(path) == record.stamp) { route = path; break; } } catch (const Problem&) {}
            }
            if (route.isEmpty()) { identities[id].uncertain = true; return false; }
            selectAgent(route);
            SSHAgent agent;
            if (!present(agent, *record.key)) { identities.remove(id); return true; }
            if (!agent.removeIdentity(*record.key) || present(agent, *record.key)) return false;
            identities.remove(id);
            return true;
        } catch (const Problem&) { identities[id].uncertain = true; return false; }
    }
    QJsonObject finishRemoval(const QSharedPointer<Owner>& owner, const QJsonObject& value, qint64 deadline) {
        const auto token = text(value, "token", true);
        auto found = removals.find(token);
        if (found == removals.end() || found->owner != owner->id) reject("The SSH removal approval is no longer valid.");
        const auto review = found.value();
        removals.erase(found);
        if (review.expires < monotonicNow()) reject("The SSH removal approval expired. Review the keys again.");
        if (!flag(value, "approved")) return {{"cancelled", true}, {"removed", 0}};
        if (!ownerActive(owner) || stopping) reject("The SSH removal request was cancelled.");
        selectAgent(review.target);
        if (socketStamp(review.agent) != review.stamp) reject("The SSH agent changed. Review its keys again.");
        SSHAgent agent;
        const auto current = list(agent);
        if (review.clear && current.size() != review.keys.size()) reject("The SSH agent's key list changed. Review it again.");
        for (const auto& key : review.keys) {
            const auto match = std::find_if(current.cbegin(), current.cend(), [&key](const auto& candidate) { return *key == *candidate; });
            if (match == current.cend() || (*match)->comment() != key->comment()
                || ownership(review.stamp, *key) != review.ownership.value(key->fingerprint()))
                reject("An SSH key or its ownership changed. Review the keys again.");
        }
        int attempted = 0;
        for (const auto& key : review.keys) {
            if (!ownerActive(owner) || stopping || monotonicNow() > qMin(deadline, review.expires)) break;
            try { if (socketStamp(review.agent) != review.stamp) break; }
            catch (const Problem&) { break; }
            ++attempted;
            if (!agent.removeIdentity(*key)) break;
        }
        int removed = 0, remaining = -1;
        bool confirmed = false;
        try {
            if (socketStamp(review.agent) != review.stamp) reject("The SSH agent changed during removal.");
            const auto after = list(agent);
            if (socketStamp(review.agent) != review.stamp) reject("The SSH agent changed during removal.");
            remaining = after.size();
            for (const auto& key : review.keys) {
                if (std::none_of(after.cbegin(), after.cend(), [&key](const auto& candidate) { return *key == *candidate; })) {
                    ++removed;
                    const auto id = identityId(review.stamp, *key);
                    if (identities.contains(id) && identities.value(id).stamp == review.stamp) identities.remove(id);
                }
            }
            confirmed = true;
        } catch (const Problem&) {
            for (const auto& key : review.keys) {
                const auto id = identityId(review.stamp, *key);
                if (identities.contains(id) && identities.value(id).stamp == review.stamp) identities[id].uncertain = true;
            }
        }
        return {{"removed", removed}, {"attempted", attempted}, {"total", review.keys.size()}, {"agent_remaining", remaining},
            {"confirmed", confirmed}, {"complete", confirmed && removed == review.keys.size() && (!review.clear || remaining == 0)}};
    }
    void cleanup(const QSharedPointer<Owner>& owner) {
        if (owner->busy) return;
        QSet<QString> unavailable;
        bool failed = false;
        for (const auto& id : identities.keys()) {
            const auto record = identities.value(id);
            if (record.owner != owner) continue;
            if (!record.removeOnLock) { identities.remove(id); continue; }
            if (unavailable.contains(record.stamp) || (stopping && shutdownUnavailable.contains(record.stamp)) || !remove(id)) {
                failed = true;
                unavailable.insert(record.stamp);
                if (stopping) shutdownUnavailable.insert(record.stamp);
            }
        }
        if (failed) parentEvent({{"event", "cleanup-failed"}});
    }
    QJsonObject info(const Identity& record) const {
        return {{"entry", record.entry}, {"fingerprint", record.key->fingerprint()}, {"type", record.key->type()},
            {"comment", record.key->comment().left(1024)}, {"socket", record.agent}, {"remove_on_lock", record.removeOnLock},
            {"uncertain", record.uncertain}};
    }
    QJsonObject request(const QSharedPointer<Owner>& owner, const QJsonObject& value) {
        const auto limit = value.value("deadline");
        if (!limit.isDouble() || !std::isfinite(limit.toDouble()) || limit.toDouble() < monotonicNow()
            || limit.toDouble() > monotonicNow() + 15000) reject("The SSH relay request expired.");
        const auto method = text(value, "method", true);
        for (auto it = removals.begin(); it != removals.end();) {
            if (it->expires < monotonicNow()) it = removals.erase(it); else ++it;
        }
        if (method == "finish-remove") return finishRemoval(owner, value, qint64(limit.toDouble()));
        if (method == "owned") {
            QJsonArray result;
            for (const auto& record : identities) if (record.owner == owner) result.append(info(record));
            return {{"keys", result}};
        }
        if (method == "policy") {
            const auto entry = text(value, "entry", true);
            const auto removeOnLock = flag(value, "remove_on_lock");
            for (auto& record : identities) if (record.owner == owner && record.entry == entry) record.removeOnLock = removeOnLock;
            return {{"updated", true}};
        }
        if (method == "remove") {
            const auto fingerprint = text(value, "fingerprint", true);
            const auto socket = text(value, "socket", true);
            const auto canonical = QFileInfo(socket).canonicalFilePath();
            QString stamp;
            try { stamp = socketStamp(socket); } catch (const Problem&) {}
            QString id;
            for (auto it = identities.cbegin(); it != identities.cend(); ++it) {
                const auto& record = it.value();
                if (record.owner != owner || record.key->fingerprint() != fingerprint
                    || (record.agent != socket && !record.paths.contains(socket) && !record.paths.contains(canonical) && record.stamp != stamp)) continue;
                if (!id.isEmpty()) reject("Multiple SSH agents match this key. Review removal in Agent Keys.");
                id = it.key();
            }
            if (id.isEmpty()) reject("This SSH key is not managed by this vault.");
            if (!remove(id)) reject("The SSH agent did not confirm key removal.");
            return {{"removed", true}};
        }
        const auto socket = text(value, "socket", true);
        const auto stamp = socketStamp(socket);
        const auto canonical = QFileInfo(socket).canonicalFilePath();
        if (canonical.isEmpty()) reject("The SSH agent socket is unavailable.");
        for (auto& record : identities) {
            if (record.stamp == stamp && !record.paths.contains(canonical)) {
                if (record.paths.size() >= 16) record.paths.removeFirst();
                record.paths.append(canonical);
            }
            else if (record.stamp != stamp && record.paths.contains(canonical)) record.uncertain = true;
        }
        selectAgent(canonical, text(value, "provider"));
        SSHAgent agent;
        if (method == "list") {
            QJsonArray result;
            for (const auto& key : list(agent)) {
                result.append(keyInfo(owner, socket, stamp, *key));
            }
            if (socketStamp(socket) != stamp) reject("The SSH agent changed while listing keys. Try again.");
            return {{"keys", result}, {"socket", socket}};
        }
        if (method == "review-remove") {
            const bool clear = flag(value, "clear");
            if (!value.value("fingerprints").isArray()) reject("Choose SSH keys to remove.");
            const auto requested = value.value("fingerprints").toArray();
            if ((clear && !requested.isEmpty()) || (!clear && requested.isEmpty()) || requested.size() > 1024)
                reject("Choose SSH keys or clear the agent.");
            QSet<QString> selected;
            for (const auto& item : requested) {
                if (!item.isString() || item.toString().isEmpty() || item.toString().size() > 128 || selected.contains(item.toString()))
                    reject("Choose distinct SSH key fingerprints.");
                selected.insert(item.toString());
            }
            RemovalReview review;
            review.owner = owner->id; review.agent = socket; review.target = canonical; review.stamp = stamp;
            review.expires = monotonicNow() + 30000; review.clear = clear;
            QJsonArray metadata;
            for (const auto& key : list(agent)) if (clear || selected.contains(key->fingerprint())) {
                review.keys.append(key);
                review.ownership.insert(key->fingerprint(), ownership(review.stamp, *key));
                metadata.append(keyInfo(owner, socket, review.stamp, *key));
            }
            if ((!clear && review.keys.size() != selected.size()) || socketStamp(socket) != review.stamp)
                reject("The SSH agent changed. Review its keys again.");
            int retained = review.keys.size();
            for (const auto& pending : removals) retained += pending.keys.size();
            if (removals.size() >= 128 || review.keys.size() > 1024 || retained > 4096) reject("Too many SSH key reviews are pending.");
            const auto token = QUuid::createUuid().toString(QUuid::WithoutBraces);
            removals.insert(token, review);
            return {{"token", token}, {"keys", metadata}, {"socket", socket}, {"clear", clear}};
        }
        if (method != "add") reject("Unsupported SSH relay operation.");
        auto privateData = bytes(value, "private"), publicData = bytes(value, "public");
        BinaryStream privateStream(&privateData), publicStream(&publicData);
        OpenSSHKey key;
        if (!key.readPrivate(privateStream)) reject("The SSH private key could not be decoded.");
        const auto type = key.type();
        if (!key.readPublic(publicStream) || key.type() != type) reject("The SSH public key could not be decoded.");
        KeeAgentSettings settings;
        settings.setUseConfirmConstraintWhenAdding(flag(value, "confirm"));
        settings.setRemoveAtDatabaseClose(flag(value, "remove_on_lock"));
        settings.setUseLifetimeConstraintWhenAdding(flag(value, "lifetime"));
        const auto seconds = value.value("seconds");
        if (!seconds.isDouble() || seconds.toDouble() != seconds.toInt() || seconds.toInt() < 1)
            reject("Choose a positive SSH key lifetime in seconds.");
        settings.setLifetimeConstraintDuration(seconds.toInt());
        const auto entry = text(value, "entry", true);
        const auto id = identityId(stamp, key);
        const bool loaded = present(agent, key);
        if (socketStamp(socket) != stamp) reject("The SSH agent changed before the key was added.");
        if (loaded && identities.contains(id) && identities.value(id).owner != owner)
            reject("Another open vault manages this SSH key.");
        if (loaded && !identities.contains(id)) {
            key.clearPrivate(); privateData.fill('\0');
            return {{"added", false}, {"existing", true}, {"owned", false}};
        }
        if (!loaded) identities.remove(id);
        if (identities.size() >= 1024 && !identities.contains(id)) reject("Too many SSH keys are managed.");
        QSet<QString> endpoints;
        for (const auto& record : identities) endpoints.insert(record.stamp);
        if (endpoints.size() >= 16 && !endpoints.contains(stamp)) reject("Too many SSH agents are in use.");
        if (limit.toDouble() < monotonicNow() || !ownerActive(owner)) reject("The SSH add request was cancelled or expired.");
        auto publicKey = QSharedPointer<OpenSSHKey>::create(key);
        publicKey->clearPrivate();
        const auto paths = identities.contains(id) ? identities.value(id).paths : QStringList{canonical};
        identities.insert(id, {owner, publicKey, canonical, entry, stamp, paths, settings.removeAtDatabaseClose(), true});
        const bool added = agent.addIdentity(key, settings, owner->id);
        key.clearPrivate(); privateData.fill('\0');
        if (socketStamp(socket) != stamp) reject("The SSH agent changed while adding a key. Its cleanup status needs review.");
        if (!added) {
            // Failed/unknown adds remain cleanup candidates until the agent confirms absence.
            remove(id);
            reject("The SSH agent did not confirm adding the key. Its cleanup status may need review.");
        }
        identities[id].uncertain = false;
        return {{"added", true}, {"existing", loaded}, {"owned", true}};
    }
    void readPeer(const QSharedPointer<Owner>& owner) {
        if (!owner->alive || !owner->socket || owner->busy || owner->socket->state() != QLocalSocket::ConnectedState) return;
        owner->input += owner->socket->readAll();
        if (!owner->alive || owner->socket->state() != QLocalSocket::ConnectedState) return;
        if (owner->input.size() > FrameLimit) { owner->socket->abort(); return; }
        const auto newline = owner->input.indexOf('\n');
        if (newline < 0) return;
        auto frame = owner->input.left(newline);
        owner->input.remove(0, newline + 1);
        QJsonParseError error;
        const auto document = QJsonDocument::fromJson(frame, &error);
        frame.fill('\0');
        if (error.error != QJsonParseError::NoError || !document.isObject()) { owner->socket->abort(); return; }
        const auto value = document.object();
        const auto id = value.value("id");
        if (!id.isDouble() || id.toDouble() < 0 || id.toDouble() != id.toInt()) { owner->socket->abort(); return; }
        owner->busy = true;
        ++activeRequests;
        try { send(owner, {{"id", id}, {"result", request(owner, value)}}); }
        catch (const Problem& problem) { send(owner, {{"id", id}, {"error", problem.message}}); }
        catch (...) { send(owner, {{"id", id}, {"error", "The SSH relay could not complete this operation."}}); }
        owner->busy = false;
        --activeRequests;
        if (!owner->alive || !owner->socket || owner->socket->state() != QLocalSocket::ConnectedState) cleanup(owner);
        else if (!owner->input.isEmpty()) QTimer::singleShot(0, this, [this, owner] { readPeer(owner); });
        if (stopping) finalize();
    }
    void readParent() {
        char data[8192];
        while (true) {
            const auto count = ::read(STDIN_FILENO, data, sizeof(data));
            if (count > 0) parentInput.append(data, count);
            else if (!count) { shutdown(); return; }
            else if (errno == EINTR) continue;
            else if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            else { shutdown(); return; }
        }
        if (parentInput.size() > 65536) { shutdown(); return; }
        while (parentInput.contains('\n')) {
            const auto newline = parentInput.indexOf('\n');
            const auto document = QJsonDocument::fromJson(parentInput.left(newline));
            parentInput.remove(0, newline + 1);
            const auto value = document.object();
            const auto method = value.value("method").toString();
            const auto pid = value.value("pid").toDouble(-1);
            bool ok = false;
            const bool validPid = std::isfinite(pid) && pid >= 1 && pid <= std::numeric_limits<int>::max() && std::floor(pid) == pid;
            if (method == "register" && validPid && allowed.size() < 64 && !stopping) {
                allowed.insert(qint64(pid)); ok = true;
            } else if (method == "unregister" && validPid) {
                allowed.remove(qint64(pid));
                for (const auto& owner : peers.values()) if (owner->pid == qint64(pid) && owner->socket) owner->socket->abort();
                ok = true;
            } else if (method == "status") ok = true;
            else if (method == "cleanup") {
                QSet<QString> unavailable;
                for (const auto& id : identities.keys()) {
                    const auto record = identities.value(id);
                    if (!record.uncertain && (record.owner->alive || !record.removeOnLock)) continue;
                    if (!unavailable.contains(record.stamp) && !remove(id)) unavailable.insert(record.stamp);
                }
                ok = true;
            }
            else if (method == "shutdown") { shutdown(); return; }
            parentEvent({{"id", value.value("id")}, {"ok", ok}, {"managed", identities.size()}, {"cleanup_ok", cleanupOK()}});
        }
    }
    void shutdown() {
        if (stopping) return;
        stopping = true;
        inputReady.setEnabled(false);
        server.close();
        const auto owners = peers.values();
        for (const auto& owner : owners) if (owner->socket) owner->socket->abort();
        finalize();
    }
    void finalize() {
        if (finalized || activeRequests) return;
        finalized = true;
        // Keep only public cleanup records; do not retry each key when its agent is unavailable.
        QSet<Owner*> seen;
        for (const auto& record : identities.values()) if (!seen.contains(record.owner.data())) {
            seen.insert(record.owner.data());
            const auto owner = record.owner;
            cleanup(owner);
        }
        parentEvent({{"event", "stopped"}, {"cleanup_ok", identities.isEmpty() && cleanupOK()}});
        flushParent();
    }
public:
    void stop() { shutdown(); }
    Relay() {
        ::fcntl(STDIN_FILENO, F_SETFL, ::fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK);
        ::fcntl(STDOUT_FILENO, F_SETFL, ::fcntl(STDOUT_FILENO, F_GETFL) | O_NONBLOCK);
        outputReady.setEnabled(false);
        connect(&inputReady, &QSocketNotifier::activated, this, [this] { readParent(); });
        connect(&outputReady, &QSocketNotifier::activated, this, [this] { flushParent(); });
        server.setSocketOptions(QLocalServer::NoOptions);
        connect(&server, &QLocalServer::newConnection, this, [this] {
            while (server.hasPendingConnections()) {
                auto* socket = server.nextPendingConnection();
                struct ucred credentials {};
                socklen_t length = sizeof(credentials);
                if (::getsockopt(socket->socketDescriptor(), SOL_SOCKET, SO_PEERCRED, &credentials, &length)
                    || credentials.uid != ::getuid() || !allowed.remove(credentials.pid) || peers.size() >= 64 || stopping) {
                    socket->abort(); socket->deleteLater(); continue;
                }
                auto owner = QSharedPointer<Owner>::create();
                owner->pid = credentials.pid; owner->socket = socket;
                peers.insert(socket, owner);
                socket->setReadBufferSize(FrameLimit + 1);
                connect(socket, &QLocalSocket::readyRead, this, [this, owner] { readPeer(owner); });
                connect(socket, &QLocalSocket::disconnected, this, [this, owner, socket] {
                    owner->alive = false;
                    owner->input.fill('\0'); owner->input.clear();
                    peers.remove(socket);
                    for (auto it = removals.begin(); it != removals.end();) {
                        if (it->owner == owner->id) it = removals.erase(it); else ++it;
                    }
                    cleanup(owner);
                    socket->deleteLater();
                    if (stopping) flushParent();
                });
                if (socket->bytesAvailable()) readPeer(owner);
            }
        });
    }
    bool start(const QString& path) {
        const auto directory = QFileInfo(path).absolutePath();
        struct stat info {};
        if (::lstat(QFile::encodeName(directory).constData(), &info) || !S_ISDIR(info.st_mode)
            || info.st_uid != ::getuid() || (info.st_mode & 0077)) return false;
        if (!::lstat(QFile::encodeName(path).constData(), &info) || errno != ENOENT) return false;
        if (!server.listen(path)) return false;
        parentEvent({{"event", "ready"}, {"protocol", 1}, {"socket", path}});
        return true;
    }
};
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    if (argc != 2) return 1;
    Bootstrap::disableCoreDumps();
    ::umask(0077);
    std::signal(SIGPIPE, SIG_IGN);
    QTemporaryDir settings;
    if (!settings.isValid()) return 1;
    Config::createConfigFromFile(settings.path() + "/settings.ini", settings.path() + "/settings-local.ini");
    if (!Crypto::init()) return 1;
    Bootstrap::bootstrap();
    Relay relay;
    if (!relay.start(QString::fromLocal8Bit(argv[1]))) return 2;
    int wake[2];
    if (::pipe2(wake, O_NONBLOCK | O_CLOEXEC)) return 2;
    signalWrite = wake[1];
    struct sigaction action {};
    action.sa_handler = stopSignal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, nullptr);
    sigaction(SIGINT, &action, nullptr);
    QSocketNotifier signalReady(wake[0], QSocketNotifier::Read);
    QObject::connect(&signalReady, &QSocketNotifier::activated, &app, [&] {
        char bytes[64];
        while (::read(wake[0], bytes, sizeof(bytes)) > 0) {}
        relay.stop();
    });
    const auto result = app.exec();
    signalWrite = -1;
    ::close(wake[0]); ::close(wake[1]);
    return result;
}
