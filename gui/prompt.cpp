#include "prompt.hpp"

#include <QCloseEvent>
#include <QComboBox>
#include <QDateTime>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QDnsLookup>
#include <QHostAddress>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

#include "style.hpp"

// "1.2.3.4" -> "4.3.2.1.in-addr.arpa", IPv6 -> nibble format under ip6.arpa.
static QString reverseName(const QString& ip) {
    QHostAddress a(ip);
    if (a.protocol() == QAbstractSocket::IPv4Protocol) {
        const quint32 v = a.toIPv4Address();
        return QString("%1.%2.%3.%4.in-addr.arpa").arg(v & 0xff).arg((v >> 8) & 0xff).arg((v >> 16) & 0xff).arg(v >> 24);
    }
    if (a.protocol() == QAbstractSocket::IPv6Protocol) {
        const Q_IPV6ADDR b = a.toIPv6Address();
        QString out;
        for (int i = 15; i >= 0; --i)
            out += QString("%1.%2.").arg(b[i] & 0xf, 0, 16).arg(b[i] >> 4, 0, 16);
        return out + "ip6.arpa";
    }
    return {};
}

static QLabel* fieldLabel(const QString& text) {
    auto* l = new QLabel(text);
    l->setObjectName("muted");
    return l;
}

static QLabel* valueLabel() {
    auto* l = new QLabel;
    l->setTextInteractionFlags(Qt::TextSelectableByMouse);
    l->setWordWrap(true);
    return l;
}

PromptDialog::PromptDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle(tr("Varta - new connection"));
    setWindowFlags(Qt::Dialog | Qt::WindowStaysOnTopHint | Qt::WindowTitleHint | Qt::CustomizeWindowHint);
    setWindowIcon(style::shieldIcon(style::Shield::Warn));
    setMinimumWidth(560);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 14);
    root->setSpacing(0);

    // ---- coloured header
    auto* header = new QFrame;
    header->setObjectName("headerBar");
    auto* hl = new QHBoxLayout(header);
    hl->setContentsMargins(18, 14, 18, 14);
    headerIcon_ = new QLabel;
    headerTitle_ = new QLabel;
    headerTitle_->setObjectName("title");
    headerSub_ = new QLabel;
    headerSub_->setObjectName("muted");
    headerSub_->setWordWrap(true);
    auto* titles = new QVBoxLayout;
    titles->setSpacing(2);
    titles->addWidget(headerTitle_);
    titles->addWidget(headerSub_);
    countdown_ = new QLabel;
    countdown_->setObjectName("chip");
    hl->addWidget(headerIcon_);
    hl->addSpacing(10);
    hl->addLayout(titles, 1);
    hl->addWidget(countdown_, 0, Qt::AlignTop);
    root->addWidget(header);

    auto* body = new QVBoxLayout;
    body->setContentsMargins(18, 14, 18, 0);
    body->setSpacing(12);
    root->addLayout(body);

    // ---- program card
    auto* appCard = new QFrame;
    appCard->setObjectName("card");
    auto* al = new QHBoxLayout(appCard);
    al->setContentsMargins(14, 12, 14, 12);
    appIcon_ = new QLabel;
    appIcon_->setFixedSize(48, 48);
    appName_ = new QLabel;
    appName_->setObjectName("bigName");
    appPath_ = valueLabel();
    appPath_->setObjectName("muted");
    appMeta_ = new QLabel;
    appMeta_->setObjectName("muted");
    appCmd_ = new QLabel;
    appCmd_->setObjectName("muted");
    auto* appText = new QVBoxLayout;
    appText->setSpacing(1);
    appText->addWidget(appName_);
    appText->addWidget(appPath_);
    appText->addWidget(appMeta_);
    appText->addWidget(appCmd_);
    al->addWidget(appIcon_, 0, Qt::AlignTop);
    al->addSpacing(8);
    al->addLayout(appText, 1);
    body->addWidget(appCard);

    // ---- destination card
    auto* dstCard = new QFrame;
    dstCard->setObjectName("card");
    auto* grid = new QGridLayout(dstCard);
    grid->setContentsMargins(14, 12, 14, 12);
    grid->setHorizontalSpacing(14);
    grid->setVerticalSpacing(6);
    host_ = valueLabel();
    QFont hf = host_->font();
    hf.setBold(true);
    hf.setPointSizeF(hf.pointSizeF() * 1.1);
    host_->setFont(hf);
    rdns_ = valueLabel();
    rdns_->setObjectName("muted");
    address_ = valueLabel();
    owner_ = valueLabel();
    country_ = valueLabel();
    grid->addWidget(fieldLabel(tr("Host")), 0, 0);
    grid->addWidget(host_, 0, 1);
    grid->addWidget(rdns_, 1, 1);
    grid->addWidget(fieldLabel(tr("Address")), 2, 0);
    grid->addWidget(address_, 2, 1);
    grid->addWidget(fieldLabel(tr("Owner")), 3, 0);
    grid->addWidget(owner_, 3, 1);
    grid->addWidget(fieldLabel(tr("Country")), 4, 0);
    grid->addWidget(country_, 4, 1);
    grid->setColumnStretch(1, 1);
    body->addWidget(dstCard);

    warning_ = new QLabel;
    warning_->setWordWrap(true);
    warning_->setObjectName("card");
    warning_->setContentsMargins(12, 8, 12, 8);
    body->addWidget(warning_);

    platformNote_ = new QLabel(tr("macOS: the connection has already started. \"Deny\" cuts it and blocks this "
                                  "address for every program."));
    platformNote_->setWordWrap(true);
    platformNote_->setObjectName("muted");
    platformNote_->setVisible(false);
    body->addWidget(platformNote_);

    // ---- what the answer applies to
    auto* opts = new QGridLayout;
    opts->setHorizontalSpacing(10);
    scope_ = new QComboBox;
    duration_ = new QComboBox;
    duration_->addItem(tr("Forever"), "forever");
    duration_->addItem(tr("Until vartad restarts"), "session");
    opts->addWidget(fieldLabel(tr("Apply to")), 0, 0);
    opts->addWidget(scope_, 0, 1);
    opts->addWidget(fieldLabel(tr("Remember")), 1, 0);
    opts->addWidget(duration_, 1, 1);
    opts->setColumnStretch(1, 1);
    body->addLayout(opts);
    connect(scope_, &QComboBox::currentIndexChanged, this,
            [this] { duration_->setEnabled(scope_->currentData().toString() != "once"); });

    auto* buttons = new QHBoxLayout;
    deny_ = new QPushButton(tr("Deny"));
    deny_->setObjectName("denyButton");
    allow_ = new QPushButton(tr("Allow"));
    allow_->setObjectName("allowButton");
    for (auto* b : {deny_, allow_}) {
        b->setAutoDefault(false);  // Enter must not answer by accident
        b->setMinimumHeight(34);
        b->setMinimumWidth(130);
    }
    queued_ = new QLabel;
    queued_->setObjectName("muted");
    buttons->addWidget(deny_);
    buttons->addStretch(1);
    buttons->addWidget(queued_);
    buttons->addStretch(1);
    buttons->addWidget(allow_);
    body->addSpacing(4);
    body->addLayout(buttons);

    connect(allow_, &QPushButton::clicked, this, [this] { finish(true); });
    connect(deny_, &QPushButton::clicked, this, [this] { finish(false); });

    timer_ = new QTimer(this);
    timer_->setInterval(250);
    connect(timer_, &QTimer::timeout, this, &PromptDialog::updateCountdown);
}

void PromptDialog::fillScopes(const QJsonObject& c) {
    const QString prog = style::programName(c);
    const QString host = c.value("host").toString();
    const QString ip = c.value("remote").toString();
    const bool inbound = c.value("dir").toString() == "in";
    const int port = inbound ? c.value("local_port").toInt() : c.value("remote_port").toInt();
    const bool knownExe = !c.value("exe").toString().isEmpty();

    scope_->clear();
    scope_->addItem(tr("Only this connection (once)"), "once");
    if (knownExe) {
        if (!host.isEmpty()) {
            scope_->addItem(tr("%1 → %2").arg(prog, host), "exe_host");
            const int dots = host.count('.');
            if (dots >= 2) scope_->addItem(tr("%1 → *.%2 (whole domain)").arg(prog, host.section('.', -2)), "exe_domain");
        }
        scope_->addItem(tr("%1 → %2 (this IP)").arg(prog, ip), "exe_ip");
        scope_->addItem(tr("%1 → port %2 anywhere").arg(prog).arg(port), "exe_port");
        scope_->addItem(inbound ? tr("%1 - all incoming connections").arg(prog)
                                : tr("%1 - any destination").arg(prog),
                        "exe");
        scope_->setCurrentIndex(1);
    } else {
        scope_->addItem(tr("Any program → %1").arg(host.isEmpty() ? ip : host), host.isEmpty() ? "exe_ip" : "exe_host");
    }
}

void PromptDialog::showConnection(const QJsonObject& c, int queued) {
    id_ = c.value("id").toInteger();
    deadline_ = c.value("deadline").toInteger();
    timeoutAction_ = c.value("timeout_action").toString("deny");

    const bool inbound = c.value("dir").toString() == "in";
    const QString category = c.value("category").toString();
    const QString prog = style::programName(c);

    style::Shield level = category.isEmpty() ? style::Shield::Warn : style::Shield::Danger;
    headerIcon_->setPixmap(style::shieldPixmap(level, 40));
    headerTitle_->setText(inbound ? tr("Incoming connection") : tr("Outgoing connection"));
    headerSub_->setText(inbound ? tr("Someone on the network wants to connect to %1").arg(prog)
                                : tr("%1 wants to connect to the network").arg(prog));

    appIcon_->setPixmap(style::appPixmap(c.value("name").toString(), 48, c.value("exe").toString()));
    appName_->setText(prog);
    const QString exe = c.value("exe").toString();
    appPath_->setText(exe.isEmpty() ? tr("Program could not be identified (it may have exited already)") : exe);
    QStringList meta;
    if (c.value("pid").toInt() > 0) meta << tr("PID %1").arg(c.value("pid").toInt());
    if (!c.value("user").toString().isEmpty()) meta << tr("user %1").arg(c.value("user").toString());
    appMeta_->setText(meta.join("  ·  "));
    const QString cmd = c.value("cmdline").toString();
    appCmd_->setText(fontMetrics().elidedText(cmd, Qt::ElideMiddle, 430));
    appCmd_->setToolTip(cmd);
    appCmd_->setVisible(!cmd.isEmpty() && cmd != exe);

    const QString host = c.value("host").toString();
    const QString ip = c.value("remote").toString();
    const QString special = c.value("special").toString();
    host_->setText(host.isEmpty() ? (special.isEmpty() ? tr("(no name seen in DNS)") : special) : host);
    rdns_->clear();
    rdns_->setVisible(false);
    if (host.isEmpty() && special.isEmpty()) {
        // Reverse DNS as a hint; done by the GUI so the daemon never blocks on it.
        // A plain PTR query (QDnsLookup) - NOT QHostInfo/getnameinfo: on Windows that falls
        // back to a NetBIOS node-status query (UDP 137) sent straight to the remote IP.
        const QString ptr = reverseName(ip);
        if (!ptr.isEmpty()) {
            const qint64 forId = id_;
            auto* dns = new QDnsLookup(QDnsLookup::PTR, ptr, this);
            connect(dns, &QDnsLookup::finished, this, [this, dns, forId] {
                dns->deleteLater();
                if (forId != id_ || dns->error() != QDnsLookup::NoError || dns->pointerRecords().isEmpty()) return;
                QString name = dns->pointerRecords().first().value();
                if (name.endsWith('.')) name.chop(1);
                rdns_->setText(tr("reverse DNS: %1").arg(name));
                rdns_->setVisible(true);
            });
            dns->lookup();
        }
    }

    const QString proto = c.value("proto").toString();
    const int port = c.value("remote_port").toInt();
    const int lport = c.value("local_port").toInt();
    QString svc = style::portName(inbound ? lport : port, proto);
    QString addr = inbound ? tr("%1 → local port %2").arg(ip).arg(lport) : QString("%1 : %2").arg(ip).arg(port);
    addr += "  /  " + proto.toUpper();
    if (!svc.isEmpty()) addr += " (" + svc + ")";
    address_->setText(addr);

    const QString org = c.value("org").toString();
    const int asn = c.value("asn").toInt();
    if (!special.isEmpty()) owner_->setText(special);
    else if (org.isEmpty()) owner_->setText(tr("unknown (IP database has no entry)"));
    else owner_->setText(asn ? QString("%1  ·  AS%2").arg(org).arg(asn) : org);
    const QString cc = c.value("country").toString();
    country_->setText(cc.isEmpty() ? tr("unknown") : QString("%1 (%2)").arg(style::countryName(cc), cc));

    if (!category.isEmpty()) {
        warning_->setText(tr("⚠  Known tracker / telemetry endpoint: %1").arg(c.value("category_title").toString()));
        warning_->setStyleSheet(QString("QLabel { color: %1; font-weight: 600; }").arg(style::deny().name()));
        warning_->setVisible(true);
    } else if (exe.isEmpty()) {
        warning_->setText(tr("The program is unknown, so a rule can only be made for the destination."));
        warning_->setStyleSheet(QString("QLabel { color: %1; }").arg(style::warn().name()));
        warning_->setVisible(true);
    } else {
        warning_->setVisible(false);
    }

    fillScopes(c);
    duration_->setCurrentIndex(0);
    setQueued(queued);
    updateCountdown();
    timer_->start();
    adjustSize();
    show();
    raise();
    activateWindow();
}

void PromptDialog::setQueued(int queued) {
    queued_->setText(queued > 0 ? tr("%n more waiting", nullptr, queued) : QString());
}

void PromptDialog::updateCountdown() {
    const qint64 left = deadline_ ? (deadline_ - QDateTime::currentMSecsSinceEpoch()) / 1000 : -1;
    if (left < 0 && deadline_) {
        countdown_->setText(tr("timed out"));
        return;
    }
    const bool deny = timeoutAction_ != "allow";
    countdown_->setText(deny ? tr("auto-deny in %1 s").arg(left) : tr("auto-allow in %1 s").arg(left));
    const QColor c = left <= 5 ? style::deny() : style::muted();
    countdown_->setStyleSheet(QString("QLabel#chip { background: %1; color: white; }").arg(c.name()));
}

void PromptDialog::finish(bool allow) {
    if (id_ < 0) return;
    const qint64 id = id_;
    id_ = -1;
    timer_->stop();
    const QString scope = scope_->currentData().toString();
    emit answered(id, allow, scope, duration_->currentData().toString());
}

void PromptDialog::reject() { finish(false); }

void PromptDialog::closeEvent(QCloseEvent* e) {
    e->ignore();
    finish(false);
}

void PromptDialog::setPlatform(const QString& platform) { platformNote_->setVisible(platform == "macos"); }
