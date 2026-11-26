#include "backend.hpp"

#include <QDateTime>
#include <QJsonDocument>
#include <QRandomGenerator>

#include <iterator>
#include <vector>

// ----------------------------------------------------------------------------- Backend

void Backend::answer(qint64 id, bool allow, const QString& scope, const QString& duration) {
    send({{"type", "verdict"},
          {"id", id},
          {"action", allow ? "allow" : "deny"},
          {"scope", scope},
          {"duration", duration}});
}

void Backend::setSetting(const QString& key, const QString& value) {
    send({{"type", "set_setting"}, {"key", key}, {"value", value}});
}

void Backend::addRule(const QJsonObject& rule) { send({{"type", "rule_add"}, {"rule", rule}}); }

void Backend::updateRule(qint64 id, const QJsonObject& fields) {
    send({{"type", "rule_update"}, {"id", id}, {"rule", fields}});
}

void Backend::deleteRule(qint64 id) { send({{"type", "rule_delete"}, {"id", id}}); }

void Backend::clearHistory() { send({{"type", "clear_history"}}); }

void Backend::dispatch(const QJsonObject& m) {
    const QString t = m.value("type").toString();
    if (t == "hello") {
        emit hello(m);
        emit settings(m.value("settings").toObject());
    } else if (t == "history") {
        emit history(m.value("events").toArray());
    } else if (t == "event") {
        emit event(m);
    } else if (t == "ask") {
        emit ask(m);
    } else if (t == "ask_done") {
        emit askDone(m.value("id").toInteger());
    } else if (t == "rules") {
        emit rules(m.value("rules").toArray());
    } else if (t == "settings") {
        emit settings(m.value("settings").toObject());
    } else if (t == "error") {
        emit error(m.value("message").toString());
    }
}

// ----------------------------------------------------------------------- SocketBackend

SocketBackend::SocketBackend(const QString& path, QObject* parent) : Backend(parent), path_(path) {
    connect(&socket_, &QLocalSocket::connected, this, [this] {
        lastError_.clear();
        emit connectedChanged(true);
    });
    connect(&socket_, &QLocalSocket::disconnected, this, [this] {
        buffer_.clear();
        emit connectedChanged(false);
        reconnect_.start();
    });
    connect(&socket_, &QLocalSocket::errorOccurred, this, [this](QLocalSocket::LocalSocketError e) {
#ifdef Q_OS_WIN
        if (e == QLocalSocket::SocketAccessError)
            lastError_ = tr("Permission denied by the vartad service.");
        else if (e == QLocalSocket::ServerNotFoundError || e == QLocalSocket::ConnectionRefusedError)
            lastError_ = tr("The vartad service is not running (as Administrator: sc start vartad).");
#else
        if (e == QLocalSocket::SocketAccessError)
            lastError_ = tr("Permission denied - add yourself to the 'varta' group and log in again.");
        else if (e == QLocalSocket::ServerNotFoundError || e == QLocalSocket::ConnectionRefusedError)
            lastError_ = tr("vartad is not running (sudo systemctl start vartad).");
#endif
        else
            lastError_ = socket_.errorString();
        emit connectedChanged(false);
        reconnect_.start();
    });
    connect(&socket_, &QLocalSocket::readyRead, this, &SocketBackend::onReadyRead);
    reconnect_.setInterval(3000);
    reconnect_.setSingleShot(true);
    connect(&reconnect_, &QTimer::timeout, this, &SocketBackend::tryConnect);
    QTimer::singleShot(0, this, &SocketBackend::tryConnect);
}

void SocketBackend::tryConnect() {
    if (socket_.state() != QLocalSocket::UnconnectedState) return;
    socket_.connectToServer(path_);
}

bool SocketBackend::isConnected() const { return socket_.state() == QLocalSocket::ConnectedState; }

void SocketBackend::send(const QJsonObject& msg) {
    if (!isConnected()) return;
    socket_.write(QJsonDocument(msg).toJson(QJsonDocument::Compact) + '\n');
}

void SocketBackend::onReadyRead() {
    buffer_ += socket_.readAll();
    int nl;
    while ((nl = buffer_.indexOf('\n')) >= 0) {
        const QByteArray line = buffer_.left(nl);
        buffer_.remove(0, nl + 1);
        QJsonParseError err;
        const QJsonDocument doc = QJsonDocument::fromJson(line, &err);
        if (doc.isObject()) dispatch(doc.object());
    }
}

// ------------------------------------------------------------------------- DemoBackend

namespace {

struct DemoApp {
    const char* name;
    const char* exe;
    const char* user;
    std::vector<int> dests;  // indexes into kDests this program talks to
};
struct DemoDest {
    const char* host;
    const char* ip;
    int port;
    const char* org;
    int asn;
    const char* cc;
    const char* category;
    const char* categoryTitle;
};

const DemoApp kApps[] = {
    {"firefox", "/usr/lib/firefox-esr/firefox-esr", "master", {0, 2, 3, 8, 10, 11}},
    {"code", "/usr/share/code/code", "master", {1, 3}},
    {"spotify", "/usr/share/spotify/spotify", "master", {5, 11}},
    {"telegram-desktop", "/usr/bin/telegram-desktop", "master", {6}},
    {"steam", "/home/master/.local/share/Steam/ubuntu12_32/steam", "master", {7}},
    {"curl", "/usr/bin/curl", "master", {3, 8}},
    {"python3", "/usr/bin/python3.13", "master", {9, 3}},
    {"http", "/usr/lib/apt/methods/http", "_apt", {4}},
};

const DemoDest kDests[] = {
    {"www.google-analytics.com", "142.250.74.46", 443, "Google LLC", 15169, "US", "google",
     "Google Analytics, Tag Manager and ad networks (DoubleClick, AdSense)"},
    {"dc.services.visualstudio.com", "20.42.65.85", 443, "Microsoft Corporation", 8075, "US", "apps",
     "Developer & app telemetry (Firefox, VS Code / .NET CLI)"},
    {"incoming.telemetry.mozilla.org", "34.120.208.123", 443, "Google LLC", 396982, "US", "apps",
     "Developer & app telemetry (Firefox, VS Code / .NET CLI)"},
    {"github.com", "140.82.121.4", 443, "GitHub, Inc.", 36459, "DE", "", ""},
    {"deb.debian.org", "151.101.86.132", 80, "Fastly, Inc.", 54113, "DK", "", ""},
    {"api.spotify.com", "35.186.224.25", 443, "Google LLC", 396982, "US", "", ""},
    {"venus.web.telegram.org", "149.154.167.91", 443, "Telegram Messenger Inc", 62041, "NL", "", ""},
    {"store.steampowered.com", "23.36.213.194", 443, "Akamai International B.V.", 20940, "SE", "", ""},
    {"en.cppreference.com", "74.114.90.46", 443, "Cloudflare, Inc.", 13335, "US", "", ""},
    {"", "185.199.108.133", 443, "Fastly, Inc.", 54113, "NL", "", ""},
    {"www.dr.dk", "104.18.32.47", 443, "Cloudflare, Inc.", 13335, "DK", "", ""},
    {"stats.g.doubleclick.net", "142.250.27.154", 443, "Google LLC", 15169, "US", "google",
     "Google Analytics, Tag Manager and ad networks (DoubleClick, AdSense)"},
};

QJsonObject makeConn(qint64 id, const DemoApp& a, const DemoDest& d, int pid) {
    return QJsonObject{{"id", id},
                       {"time", QDateTime::currentMSecsSinceEpoch()},
                       {"dir", "out"},
                       {"proto", "tcp"},
                       {"local", "192.168.1.23"},
                       {"local_port", 40000 + int(id % 20000)},
                       {"remote", d.ip},
                       {"remote_port", d.port},
                       {"pid", pid},
                       {"exe", a.exe},
                       {"name", a.name},
                       {"cmdline", a.exe},
                       {"user", a.user},
                       {"uid", 1000},
                       {"host", d.host},
                       {"asn", d.asn},
                       {"org", d.org},
                       {"country", d.cc},
                       {"special", ""},
                       {"category", d.category},
                       {"category_title", d.categoryTitle}};
}

}  // namespace

DemoBackend::DemoBackend(QObject* parent) : Backend(parent) {
    settings_ = {{"mode", "ask"},           {"prompt_timeout", 30},     {"timeout_action", "deny"},
                 {"no_gui_action", "allow"}, {"ask_inbound", true},      {"auto_allow_dns", true},
                 {"queue", 0},               {"history", 3000}};
    auto rule = [&](qint64 id, const char* action, const char* exe, const char* host, const char* note,
                    int hits) {
        rules_.append(QJsonObject{{"id", id},       {"enabled", true}, {"action", action},
                                  {"duration", "forever"}, {"exe", exe}, {"direction", "out"},
                                  {"host", host},   {"ip", ""},        {"port", 0},
                                  {"proto", ""},    {"note", note},    {"created", 1795600000},
                                  {"hits", hits}});
    };
    rule(1, "allow", "/usr/lib/systemd/systemd-resolved", "", "default: system service", 412);
    rule(2, "allow", "/usr/lib/apt/methods/http", "", "default: system service", 37);
    rule(3, "allow", "/usr/lib/firefox-esr/firefox-esr", "", "created from prompt", 1290);
    rule(4, "deny", "/usr/share/code/code", "dc.services.visualstudio.com", "created from prompt", 58);
    rule(5, "allow", "/usr/bin/telegram-desktop", "*.telegram.org", "created from prompt", 211);
    connect(&timer_, &QTimer::timeout, this, &DemoBackend::tick);
}

void DemoBackend::start() {
    emit connectedChanged(true);
    emit hello({{"type", "hello"},
                {"version", "0.2.0"},
                {"settings", settings_},
                {"ipdb_ranges", 1216826},
                {"ipdb_attribution",
                 "IP data: DB-IP.com (IP to ASN/Country Lite) and RouteViews, CC BY 4.0"},
                {"allowed", 0},
                {"denied", 0}});
    emit settings(settings_);
    emit rules(rules_);
    QJsonArray hist;
    for (int i = 0; i < 60; ++i) {
        QJsonObject c = randomConnection();
        c["time"] = QDateTime::currentMSecsSinceEpoch() - (60 - i) * 7000;
        hist.append(c);
    }
    emit history(hist);
    timer_.start(1400);
}

QJsonObject DemoBackend::randomConnection() {
    auto* rng = QRandomGenerator::global();
    const DemoApp& a = kApps[rng->bounded(int(std::size(kApps)))];
    const DemoDest& d = kDests[a.dests[rng->bounded(int(a.dests.size()))]];
    QJsonObject c = makeConn(nextId_++, a, d, 1000 + rng->bounded(30000));
    // Very small rule engine, enough for the demo.
    for (const auto& v : rules_) {
        const QJsonObject r = v.toObject();
        if (!r.value("enabled").toBool()) continue;
        if (r.value("exe").toString() != "*" && r.value("exe").toString() != c.value("exe").toString()) continue;
        const QString host = r.value("host").toString();
        if (!host.isEmpty()) {
            const QString h = c.value("host").toString();
            const bool wild = host.startsWith("*.");
            if (wild ? !(h == host.mid(2) || h.endsWith(host.mid(1))) : h != host) continue;
        }
        c["verdict"] = r.value("action").toString();
        c["reason"] = "rule";
        c["rule_id"] = r.value("id");
        return c;
    }
    const bool allow = !c.value("category").toString().isEmpty() ? false : rng->bounded(10) < 8;
    c["verdict"] = allow ? "allow" : "deny";
    c["reason"] = allow ? "user (once)" : "rule";
    return c;
}

void DemoBackend::tick() {
    auto* rng = QRandomGenerator::global();
    if (pending_.size() < 2 && rng->bounded(6) == 0) {
        QJsonObject a = sampleAsk(rng->bounded(3));
        a["id"] = nextId_++;
        a["deadline"] = QDateTime::currentMSecsSinceEpoch() + 30000;
        pending_.insert(a.value("id").toInteger(), a);
        emit ask(a);
        return;
    }
    QJsonObject c = randomConnection();
    c["type"] = "event";
    emit event(c);
}

void DemoBackend::send(const QJsonObject& msg) {
    const QString t = msg.value("type").toString();
    if (t == "verdict") {
        const qint64 id = msg.value("id").toInteger();
        if (!pending_.contains(id)) return;
        QJsonObject c = pending_.take(id);
        const bool allow = msg.value("action").toString() == "allow";
        c["verdict"] = allow ? "allow" : "deny";
        c["reason"] = msg.value("scope").toString() == "once" ? "user (once)" : "user (new rule)";
        c.remove("deadline");
        if (msg.value("scope").toString() != "once") {
            const qint64 rid = rules_.size() + 1;
            rules_.append(QJsonObject{{"id", rid}, {"enabled", true}, {"action", c["verdict"]},
                                      {"duration", msg.value("duration")}, {"exe", c["exe"]},
                                      {"direction", c["dir"]}, {"host", c["host"]}, {"ip", ""},
                                      {"port", 0}, {"proto", ""}, {"note", "created from prompt"},
                                      {"created", QDateTime::currentSecsSinceEpoch()}, {"hits", 1}});
            c["rule_id"] = rid;
            emit rules(rules_);
        }
        emit event(c);
        emit askDone(id);
    } else if (t == "set_setting") {
        const QString key = msg.value("key").toString(), value = msg.value("value").toString();
        if (key == "prompt_timeout" || key == "history") settings_[key] = value.toInt();
        else if (key == "ask_inbound" || key == "auto_allow_dns") settings_[key] = value == "on";
        else settings_[key] = value;
        emit settings(settings_);
    } else if (t == "rule_delete") {
        for (int i = 0; i < rules_.size(); ++i)
            if (rules_[i].toObject().value("id").toInteger() == msg.value("id").toInteger()) {
                rules_.removeAt(i);
                break;
            }
        emit rules(rules_);
    } else if (t == "rule_update") {
        for (int i = 0; i < rules_.size(); ++i) {
            QJsonObject r = rules_[i].toObject();
            if (r.value("id").toInteger() != msg.value("id").toInteger()) continue;
            const QJsonObject f = msg.value("rule").toObject();
            for (auto it = f.begin(); it != f.end(); ++it) r[it.key()] = it.value();
            rules_[i] = r;
        }
        emit rules(rules_);
    } else if (t == "rule_add") {
        QJsonObject r = msg.value("rule").toObject();
        r["id"] = rules_.size() + 100;
        r["hits"] = 0;
        r["created"] = QDateTime::currentSecsSinceEpoch();
        rules_.append(r);
        emit rules(rules_);
    } else if (t == "clear_history") {
        emit history({});
    }
}

QJsonObject DemoBackend::sampleAsk(int which) {
    QJsonObject a;
    switch (which % 3) {
        case 0:
            a = makeConn(1, kApps[1], kDests[1], 48213);  // VS Code -> telemetry
            a["cmdline"] = "/usr/share/code/code --type=utility --utility-sub-type=network.mojom.NetworkService";
            break;
        case 1:
            a = makeConn(2, kApps[6], kDests[9], 51877);  // python, no host name known
            a["cmdline"] = "python3 /home/master/projects/scraper/main.py --all";
            break;
        default:
            a = makeConn(3, kApps[4], kDests[7], 3301);  // steam, store
            a["cmdline"] = "/home/master/.local/share/Steam/ubuntu12_32/steam -srt-logger-opened";
            break;
    }
    a["type"] = "ask";
    a["timeout"] = 30;
    a["timeout_action"] = "deny";
    a["deadline"] = QDateTime::currentMSecsSinceEpoch() + 30000;
    a.remove("verdict");
    return a;
}
