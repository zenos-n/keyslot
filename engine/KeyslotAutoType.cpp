// SPDX-License-Identifier: GPL-3.0-only
// Sequence parsing, placeholders, matching and X11 execution belong to KeePassXC.
#include "KeyslotAutoType.h"
#include "autotype/AutoType.h"
#include "core/AutoTypeAssociations.h"
#include "core/Config.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/EntrySearcher.h"
#include "core/Group.h"
#include "core/Tools.h"
#include <QJsonArray>
#include <QMap>
#include <QRegularExpression>
#include <QThread>
#include <unistd.h>
#include "autotype/xcb/AutoTypeXCB.h"
#include "gui/osutils/nixutils/X11Funcs.h"

namespace {
[[noreturn]] void reject(const char* code, const char* message) { throw AutoTypeFailure{code, message}; }
QString text(const QJsonObject& o, const char* name, int maximum = 16384) {
    if (!o.value(name).isString() || o.value(name).toString().size() > maximum
        || o.value(name).toString().contains(QChar('\0')))
        reject("invalid_request", "An auto-type text setting is invalid.");
    return o.value(name).toString();
}
int number(const QJsonValue& v, int low, int high) {
    if (!v.isDouble() || v.toDouble() != v.toInt(-1) || v.toInt() < low || v.toInt() > high)
        reject("invalid_request", "An auto-type number is outside the supported range.");
    return v.toInt();
}
bool flag(const QJsonObject& o, const char* name) {
    if (!o.value(name).isBool()) reject("invalid_request", "An auto-type switch is invalid.");
    return o.value(name).toBool();
}
void eligible(const Entry* entry) {
    if (entry->isRecycled() || !entry->autoTypeEnabled() || !entry->group()->resolveAutoTypeEnabled())
        reject("disabled", "Auto-type is disabled for this entry or its group.");
}
void options(const QJsonObject& args) {
    config()->set(Config::AutoTypeEntryTitleMatch, flag(args, "match_title"));
    config()->set(Config::AutoTypeEntryURLMatch, flag(args, "match_url"));
}
bool ownWindow(Display* display, Window window) {
    Atom actual;
    int format;
    unsigned long count = 0, remaining = 0;
    unsigned char* data = nullptr;
    const auto atom = XInternAtom(display, "_NET_WM_PID", True);
    const auto ok = atom && XGetWindowProperty(display, window, atom, 0, 1, False, AnyPropertyType,
                                               &actual, &format, &count, &remaining, &data) == Success;
    const bool own = ok && format == 32 && count == 1 && data
        && *reinterpret_cast<unsigned long*>(data) == static_cast<unsigned long>(getppid());
    if (data) XFree(data);
    return own;
}
void boundPlan(const QList<QSharedPointer<AutoTypeAction>>& actions, int startDelay) {
    qint64 duration = startDelay;
    int delay = 25;
    for (const auto& action : actions) {
        if (const auto* wait = dynamic_cast<const AutoTypeDelay*>(action.data())) {
            if (wait->setExecDelay) delay = wait->delayMs;
            else duration += wait->delayMs;
        } else if (dynamic_cast<const AutoTypeKey*>(action.data())) duration += delay;
        else if (dynamic_cast<const AutoTypeClearField*>(action.data())) duration += 3 * delay;
        if (duration > 60000) reject("invalid_request", "Auto-type is limited to a one-minute sequence. Shorten the sequence or delays.");
    }
}
}

KeyslotAutoType::KeyslotAutoType() { clock.start(); }
KeyslotAutoType::~KeyslotAutoType() = default;
void KeyslotAutoType::clear() { pending = {}; }
AutoTypePlatformX11* KeyslotAutoType::x11() {
    if (!platform) {
        auto candidate = std::make_unique<AutoTypePlatformX11>();
        if (!candidate->isAvailable()) {
            reject("unavailable", "X11 auto-type is unavailable. Use the GNOME companion on Wayland.");
        }
        platform = std::move(candidate);
        XSetErrorHandler(AutoTypePlatformX11::MyErrorHandler);
    }
    return platform.get();
}
QJsonObject KeyslotAutoType::fields(const Entry* entry) const {
    return {{"eligible", !entry->isRecycled() && entry->autoTypeEnabled() && entry->group()->resolveAutoTypeEnabled()},
            {"username", !entry->username().isEmpty()}, {"password", !entry->password().isEmpty()},
            {"totp", entry->hasValidTotp()}, {"url", !entry->url().isEmpty()}};
}
QJsonObject KeyslotAutoType::settings(const Entry* entry) const {
    QJsonArray associations;
    for (const auto& association : entry->autoTypeAssociations()->getAll())
        associations.append(QJsonObject{{"window", association.window}, {"sequence", association.sequence}});
    return {{"enabled", entry->autoTypeEnabled()}, {"group_enabled", entry->group()->resolveAutoTypeEnabled()},
            {"sequence", entry->defaultAutoTypeSequence()}, {"effective_sequence", entry->effectiveAutoTypeSequence()},
            {"associations", associations}, {"obfuscation", entry->autoTypeObfuscation()}};
}
QJsonObject KeyslotAutoType::settings(const Group* group) const {
    return {{"enabled", int(group->autoTypeEnabled())}, {"resolved_enabled", group->resolveAutoTypeEnabled()},
            {"sequence", group->defaultAutoTypeSequence()}, {"effective_sequence", group->effectiveAutoTypeSequence()}};
}
void KeyslotAutoType::saveSettings(Entry* entry, const QJsonObject& args) {
    const auto enabled = flag(args, "enabled");
    const auto sequence = text(args, "sequence");
    if (!args.value("associations").isArray() || args.value("associations").toArray().size() > 256)
        reject("invalid_request", "Choose at most 256 window associations.");
    QList<AutoTypeAssociations::Association> associations;
    QString error;
    if (!AutoType::verifyAutoTypeSyntax(sequence, entry, error))
        reject("invalid_request", "The auto-type sequence is invalid. Check placeholders, braces and delays.");
    for (const auto& value : args.value("associations").toArray()) {
        if (!value.isObject()) reject("invalid_request", "An auto-type window association is invalid.");
        const auto association = value.toObject();
        const auto window = text(association, "window", 4096), custom = text(association, "sequence");
        if (window.startsWith("//") && window.endsWith("//") && window.size() >= 4
            && !QRegularExpression(window.mid(2, window.size()-4)).isValid())
            reject("invalid_request", "A window association has an invalid regular expression.");
        if (!AutoType::verifyAutoTypeSyntax(custom, entry, error))
            reject("invalid_request", "A window association has an invalid auto-type sequence.");
        associations.append({window, custom});
    }
    entry->beginUpdate();
    entry->setAutoTypeEnabled(enabled);
    entry->setDefaultAutoTypeSequence(sequence);
    // Preserve the upstream obfuscation field; Linux upstream does not execute it.
    entry->autoTypeAssociations()->clear();
    for (const auto& association : associations) entry->autoTypeAssociations()->add(association);
    entry->endUpdate();
    clear();
}
void KeyslotAutoType::saveSettings(Group* group, const QJsonObject& args) {
    const auto enabled = number(args.value("enabled"), 0, 2);
    const auto sequence = text(args, "sequence");
    group->setAutoTypeEnabled(static_cast<Group::TriState>(enabled));
    group->setDefaultAutoTypeSequence(sequence);
    clear();
}
QJsonObject KeyslotAutoType::targets() {
    auto* p = x11();
    QJsonArray windows;
    std::function<void(Window)> visit = [&](Window parent) {
        Window root, ancestor, *children = nullptr;
        unsigned count = 0;
        if (!XQueryTree(p->m_dpy, parent, &root, &ancestor, &children, &count)) return;
        for (unsigned i = 0; i < count && windows.size() < 1024; ++i) {
            const auto title = p->windowTitle(children[i], true);
            if (!title.isEmpty() && p->isTopLevelWindow(children[i]) && !ownWindow(p->m_dpy, children[i]))
                windows.append(QJsonObject{{"target", QString::number(children[i])}, {"title", title}});
            else if (parent == p->m_rootWindow) visit(children[i]);
        }
        if (children) XFree(children);
    };
    visit(p->m_rootWindow);
    return {{"windows", windows}};
}
QJsonObject KeyslotAutoType::matches(const QSharedPointer<Database>& db, const QJsonObject& args) {
    options(args);
    const auto title = text(args, "title", 4096);
    const auto hideExpired = flag(args, "hide_expired");
    QJsonArray result;
    for (auto* entry : db->rootGroup()->entriesRecursive()) {
        if (entry->isRecycled() || !entry->autoTypeEnabled() || !entry->group()->resolveAutoTypeEnabled()
            || (hideExpired && entry->isExpired())) continue;
        QStringList sequences;
        for (const auto& sequence : entry->autoTypeSequences(title))
            if (!sequences.contains(sequence)) sequences.append(sequence);
        for (const auto& sequence : sequences) result.append(QJsonObject{
            {"entry", entry->uuid().toString(QUuid::WithoutBraces)}, {"sequence", sequence}});
    }
    return {{"matches", result}};
}
QJsonObject KeyslotAutoType::search(const QSharedPointer<Database>& db, const QJsonObject& args) {
    options(args);
    const auto query = text(args, "query");
    const auto title = text(args, "title", 4096);
    const bool all = flag(args, "all"), hideExpired = flag(args, "hide_expired");
    EntrySearcher searcher;
    const auto entries = all ? searcher.search(query.isEmpty() ? "*" : query, db->rootGroup())
                             : db->rootGroup()->entriesRecursive();
    const QRegularExpression filter(QRegularExpression::wildcardToRegularExpression(query,
        QRegularExpression::UnanchoredWildcardConversion), QRegularExpression::CaseInsensitiveOption);
    QJsonArray result;
    for (auto* entry : entries) {
        if (entry->isRecycled() || !entry->autoTypeEnabled() || !entry->group()->resolveAutoTypeEnabled()
            || (hideExpired && entry->isExpired())) continue;
        if (!all && !query.isEmpty() && !filter.match(entry->group()->name()).hasMatch()
            && !filter.match(entry->resolveMultiplePlaceholders(entry->title())).hasMatch()
            && !filter.match(entry->resolveMultiplePlaceholders(entry->username())).hasMatch()) continue;
        QStringList sequences;
        if (all) {
            const auto sequence = entry->effectiveAutoTypeSequence();
            if (!sequence.isEmpty()) sequences.append(sequence);
            for (const auto& association : entry->autoTypeAssociations()->getAll())
                if (!association.sequence.isEmpty() && !sequences.contains(association.sequence))
                    sequences.append(association.sequence);
        } else {
            for (const auto& sequence : entry->autoTypeSequences(title))
                if (!sequences.contains(sequence)) sequences.append(sequence);
        }
        for (const auto& sequence : sequences) result.append(QJsonObject{
            {"entry", entry->uuid().toString(QUuid::WithoutBraces)}, {"sequence", sequence}});
    }
    return {{"matches", result}};
}
QJsonObject KeyslotAutoType::prepare(const QSharedPointer<Database>& db, Entry* entry,
                                    const QJsonObject& args, const QByteArray& fingerprint) {
    clear();
    eligible(entry);
    Pending candidate;
    candidate.database = db;
    candidate.entry = entry->uuid();
    candidate.fingerprint = fingerprint;
    candidate.backend = text(args, "backend", 16);
    candidate.target = text(args, "target", 256);
    candidate.title = text(args, "title", 4096);
    candidate.sequence = text(args, "sequence");
    if (args.contains("field")) {
        const QMap<QString, QString> sequences{
            {"username", "{USERNAME}"}, {"username-enter", "{USERNAME}{ENTER}"},
            {"password", "{PASSWORD}"}, {"password-enter", "{PASSWORD}{ENTER}"},
            {"totp", "{TOTP}"}, {"url", "{URL}"}, {"url-enter", "{URL}{ENTER}"}};
        const auto field = text(args, "field", 32);
        if (!sequences.contains(field) || candidate.sequence != sequences.value(field))
            reject("invalid_request", "Choose a supported Auto-Type field action.");
        if (!fields(entry).value(field.section('-', 0, 0)).toBool())
            reject("disabled", "This entry does not contain the requested Auto-Type field.");
    }
    candidate.delay = number(args.value("delay"), 0, 500);
    candidate.startDelay = number(args.value("start_delay"), 100, 10000);
    if (candidate.sequence.isEmpty()) candidate.sequence = entry->effectiveAutoTypeSequence();
    if (candidate.target.isEmpty() || (candidate.backend != "x11" && candidate.backend != "portal"))
        reject("invalid_request", "Choose an auto-type target window.");
    if (candidate.backend == "x11") {
        bool valid = false;
        const auto window = candidate.target.toULong(&valid);
        if (!valid || !window || x11()->windowTitle(window, true) != candidate.title || ownWindow(x11()->m_dpy, window))
            reject("conflict", "The target window changed. Choose it again.");
    }
    config()->set(Config::AutoTypeDelay, candidate.delay);
    config()->set(Config::AutoTypeStartDelay, candidate.startDelay);
    QString error;
    QJsonArray pick;
    auto actions = AutoType::parseSequence(candidate.sequence, entry, error, false,
        [&](const QString& attribute, const QString& password) {
            if (pick.size() >= 64) reject("invalid_request", "There are too many PICKCHARS requests.");
            pick.append(QJsonObject{{"attribute", attribute}, {"length", password.toUcs4().size()}});
            return qMakePair(QString(), false);
        });
    if (!error.isEmpty() || actions.size() > 65536)
        reject("invalid_request", "The auto-type sequence is invalid or too large.");
    boundPlan(actions, candidate.startDelay);
    candidate.token = QUuid::createUuid().toString(QUuid::WithoutBraces);
    candidate.expires = clock.elapsed() + 120000;
    pending = candidate;
    return {{"token", candidate.token}, {"title", candidate.title}, {"sequence", candidate.sequence}, {"pick", pick}};
}
QJsonObject KeyslotAutoType::finish(const QSharedPointer<Database>& db, const QJsonObject& args,
                                   const QByteArray& fingerprint) {
    const auto request = pending;
    clear();
    if (request.token.isEmpty() || request.token != text(args, "token", 64)
        || request.expires < clock.elapsed() || request.database.toStrongRef() != db || request.fingerprint != fingerprint)
        reject("expired", "Auto-type approval expired or the vault changed. Start again.");
    if (!flag(args, "approved")) return {{"typed", false}};
    auto* entry = db->rootGroup()->findEntryByUuid(request.entry);
    if (!entry) reject("not_found", "The auto-type entry no longer exists.");
    eligible(entry);
    if (!args.value("pick").isArray()) reject("invalid_request", "Auto-type character choices are invalid.");
    const auto picks = args.value("pick").toArray();
    int pickIndex = 0;
    QString error;
    config()->set(Config::AutoTypeDelay, request.delay);
    config()->set(Config::AutoTypeStartDelay, request.startDelay);
    auto actions = AutoType::parseSequence(request.sequence, entry, error, false,
        [&](const QString&, const QString& password) {
            if (pickIndex >= picks.size() || !picks[pickIndex].isObject())
                reject("invalid_request", "Choose characters for every PICKCHARS request.");
            const auto selection = picks[pickIndex++].toObject();
            if (!selection.value("positions").isArray() || selection.value("positions").toArray().isEmpty()
                || selection.value("positions").toArray().size() > 1024)
                reject("invalid_request", "Choose the requested character positions.");
            QString selected;
            const auto characters = password.toUcs4();
            for (const auto& pos : selection.value("positions").toArray()) {
                const auto index = number(pos, 1, characters.size()) - 1;
                const uint character = characters[index];
                selected.append(QString::fromUcs4(&character, 1));
            }
            return qMakePair(selected, flag(selection, "tab"));
        });
    if (!error.isEmpty() || pickIndex != picks.size() || actions.size() > 65536)
        reject("invalid_request", "The auto-type sequence or character choices are invalid.");
    boundPlan(actions, request.startDelay);
    if (request.backend == "portal") {
        QJsonArray plan;
        for (int index = 0; index < actions.size(); ++index) {
            const auto& action = actions[index];
            if (const auto* key = dynamic_cast<const AutoTypeKey*>(action.data())) {
                KeySym symbol;
                if (key->key == Qt::Key_unknown && key->character.isHighSurrogate()) {
                    const auto* next = index + 1 < actions.size() ? dynamic_cast<const AutoTypeKey*>(actions[index + 1].data()) : nullptr;
                    if (!next || !next->character.isLowSurrogate() || next->modifiers != key->modifiers)
                        reject("unsupported", "The sequence contains an invalid Unicode character.");
                    symbol = 0x01000000 | QChar::surrogateToUcs4(key->character, next->character);
                    ++index;
                } else {
                    if (key->character.isLowSurrogate()) reject("unsupported", "The sequence contains an invalid Unicode character.");
                    symbol = key->key == Qt::Key_unknown ? qcharToNativeKeyCode(key->character) : qtToNativeKeyCode(key->key);
                }
                if (!symbol) reject("unsupported", "The sequence contains an unsupported key.");
                plan.append(QJsonObject{{"type", "key"}, {"keysym", qint64(symbol)}, {"modifiers", int(key->modifiers)}});
            } else if (const auto* delay = dynamic_cast<const AutoTypeDelay*>(action.data())) {
                plan.append(QJsonObject{{"type", delay->setExecDelay ? "key_delay" : "delay"}, {"milliseconds", delay->delayMs}});
            } else if (dynamic_cast<const AutoTypeClearField*>(action.data())) plan.append(QJsonObject{{"type", "clear"}});
        }
        return {{"plan", plan}, {"start_delay", request.startDelay}};
    }
    auto* p = x11();
    const auto window = request.target.toULong();
    if (p->windowTitle(window, true) != request.title || ownWindow(p->m_dpy, window) || !p->raiseWindow(window))
        reject("conflict", "The auto-type target is no longer available.");
    auto& executor = p->executor();
    Tools::wait(request.startDelay);
    int typed = 0;
    for (const auto& action : actions) {
        for (int attempt = 0; ; ++attempt) {
            if (p->activeWindow() != window) reject("focus_changed", "Auto-type stopped because the active window changed.");
            const auto result = action->exec(executor);
            if (result.isOk()) break;
            if (!result.canRetry() || attempt == 4) reject("type_failed", "Auto-type could not send a key. Release modifiers and check Caps Lock.");
            Tools::wait(100);
        }
        if (dynamic_cast<const AutoTypeKey*>(action.data())) ++typed;
    }
    return {{"typed", true}, {"keys", typed}};
}
