// SPDX-License-Identifier: GPL-3.0-only
// Keyless command supervisor. No vault/key objects or command output cross this process.
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcessEnvironment>
#include <QStandardPaths>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {
volatile sig_atomic_t child = 0;
void terminate(int) {
    const auto pid = child;
    if (pid > 0) { ::kill(-pid, SIGKILL); ::kill(pid, SIGKILL); }
    ::_exit(125);
}
}
int main(int argc, char** argv) {
    const auto parent = ::getppid();
    struct sigaction action{};
    action.sa_handler = terminate;
    ::sigemptyset(&action.sa_mask);
    if (::sigaction(SIGTERM, &action, nullptr) || ::sigaction(SIGINT, &action, nullptr)
        || ::sigaction(SIGHUP, &action, nullptr) || ::prctl(PR_SET_PDEATHSIG, SIGTERM) || ::getppid() != parent) return 125;
    ::signal(SIGPIPE, SIG_IGN);
    QCoreApplication app(argc, argv);
    bool validParent = false;
    const auto expectedParent = app.arguments().value(1).toLongLong(&validParent);
    if (!validParent || parent <= 1 || parent != expectedParent || ::getppid() != expectedParent) return 125;
    QByteArray bytes;
    char chunk[8192];
    while (true) {
        const auto count = ::read(STDIN_FILENO, chunk, sizeof(chunk));
        if (count == 0) break;
        if (count < 0) { if (errno == EINTR) continue; return 125; }
        bytes.append(chunk, int(count));
        if (bytes.size() > 1048576) return 125;
    }
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(bytes, &error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) return 125;
    const auto object = document.object();
    const auto program = object.value("program").toString();
    const auto arguments = object.value("arguments").toArray();
    const auto input = object.value("input").toString();
    const auto timeout = object.value("timeout").toInt();
    if (!object.value("program").isString() || !object.value("arguments").isArray() || !object.value("input").isString()
        || !object.value("timeout").isDouble() || program.isEmpty() || program.size() > 32768
        || program.contains(QChar(0)) || arguments.size() > 16384 || input.size() > 65536
        || input.contains(QChar(0)) || timeout < 100 || timeout > 3600000) return 125;
    const auto executable = QStandardPaths::findExecutable(program);
    if (executable.isEmpty()) return 127;
    std::vector<QByteArray> encoded{QFile::encodeName(executable)};
    for (const auto& value : arguments) {
        if (!value.isString() || value.toString().contains(QChar(0))) return 125;
        encoded.push_back(value.toString().toLocal8Bit());
    }
    std::vector<char*> command;
    for (auto& word : encoded) command.push_back(word.data());
    command.push_back(nullptr);
    for (const auto& key : QProcessEnvironment::systemEnvironment().keys())
        if (key.startsWith("KEYSLOT_")) ::qunsetenv(key.toLocal8Bit().constData());
    auto payload = input.isEmpty() ? QByteArray{} : input.toUtf8() + '\n';
    int channel[2];
    if (::pipe2(channel, O_CLOEXEC)) return 125;
    sigset_t blocked, previous;
    ::sigemptyset(&blocked); ::sigaddset(&blocked, SIGTERM); ::sigaddset(&blocked, SIGINT); ::sigaddset(&blocked, SIGHUP);
    if (::sigprocmask(SIG_BLOCK, &blocked, &previous)) return 125;
    const auto supervisor = ::getpid();
    const auto pid = ::fork();
    if (pid < 0) return 125;
    if (!pid) {
        // Only the external child leads a new session; the supervisor never signals a user's process group.
        if (::setsid() < 0 || ::prctl(PR_SET_PDEATHSIG, SIGKILL) || ::getppid() != supervisor) ::_exit(125);
        const auto null = ::open("/dev/null", O_WRONLY);
        if (null < 0 || ::dup2(channel[0], STDIN_FILENO) < 0 || ::dup2(null, STDOUT_FILENO) < 0 || ::dup2(null, STDERR_FILENO) < 0) ::_exit(125);
        ::close(channel[0]); ::close(channel[1]); if (null > STDERR_FILENO) ::close(null);
        ::signal(SIGTERM, SIG_DFL); ::signal(SIGINT, SIG_DFL); ::signal(SIGHUP, SIG_DFL); ::signal(SIGPIPE, SIG_DFL);
        ::sigprocmask(SIG_SETMASK, &previous, nullptr);
        ::execv(command[0], command.data());
        ::_exit(127);
    }
    child = pid;
    ::close(channel[0]);
    ::fcntl(channel[1], F_SETFL, ::fcntl(channel[1], F_GETFL) | O_NONBLOCK);
    ::sigprocmask(SIG_SETMASK, &previous, nullptr);
    QElapsedTimer clock; clock.start();
    qint64 written = 0;
    const auto inputSize = payload.size();
    bool pipeOpen = true;
    int result = 124;
    while (clock.elapsed() < timeout) {
        if (pipeOpen) {
            if (written < payload.size()) {
                const auto count = ::write(channel[1], payload.constData() + written, payload.size() - written);
                if (count > 0) written += count;
                else if (count < 0 && errno != EAGAIN && errno != EINTR) { result = 126; break; }
            }
            if (written == payload.size()) { ::close(channel[1]); pipeOpen = false; payload.fill(0); payload.clear(); }
        }
        siginfo_t info{};
        if (::waitid(P_PID, pid, &info, WEXITED | WNOHANG | WNOWAIT)) { if (errno == EINTR) continue; result = 126; break; }
        if (info.si_pid) { result = info.si_code == CLD_EXITED && info.si_status == 0 && written == inputSize ? 0 : 126; break; }
        ::poll(nullptr, 0, 20);
    }
    if (pipeOpen) ::close(channel[1]);
    ::sigprocmask(SIG_BLOCK, &blocked, nullptr);
    ::kill(-pid, SIGKILL); ::kill(pid, SIGKILL);
    int status; while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    child = 0;
    return result;
}
