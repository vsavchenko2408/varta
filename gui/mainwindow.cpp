#include "mainwindow.hpp"

#include "updater.hpp"

#include <QAction>
#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QClipboard>
#include <QCloseEvent>
#include <QComboBox>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QFrame>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableView>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>

#include "prompt.hpp"
#include "style.hpp"

// ---------------------------------------------------------------------------- RuleDialog

RuleDialog::RuleDialog(const QJsonObject& r, QWidget* parent) : QDialog(parent) {
    setWindowTitle(r.contains("id") ? tr("Edit rule") : tr("New rule"));
    setMinimumWidth(480);
    auto* form = new QFormLayout;
    action_ = new QComboBox;
    action_->addItem(tr("Allow"), "allow");
    action_->addItem(tr("Deny"), "deny");
    action_->setCurrentIndex(r.value("action").toString() == "deny" ? 1 : 0);

    exe_ = new QLineEdit(r.value("exe").toString("*"));
#ifdef Q_OS_WIN
    exe_->setPlaceholderText(tr("C:\\Program Files\\App\\app.exe or * for any program"));
#else
    exe_->setPlaceholderText(tr("/usr/bin/program or * for any program"));
#endif
    auto* browse = new QPushButton(tr("Browse…"));
    connect(browse, &QPushButton::clicked, this, [this] {
#ifdef Q_OS_WIN
        const QString f = QFileDialog::getOpenFileName(this, tr("Choose program"), "C:/Program Files",
                                                       tr("Programs (*.exe)"));
        if (!f.isEmpty()) exe_->setText(QDir::toNativeSeparators(QFileInfo(f).canonicalFilePath()));
#else
        const QString f = QFileDialog::getOpenFileName(this, tr("Choose program"), "/usr/bin");
        if (!f.isEmpty()) exe_->setText(QFileInfo(f).canonicalFilePath());
#endif
    });
    auto* exeRow = new QHBoxLayout;
    exeRow->addWidget(exe_, 1);
    exeRow->addWidget(browse);

    direction_ = new QComboBox;
    direction_->addItem(tr("Outgoing"), "out");
    direction_->addItem(tr("Incoming"), "in");
    direction_->addItem(tr("Both"), "");
    const QString d = r.value("direction").toString("out");
    direction_->setCurrentIndex(d == "out" ? 0 : d == "in" ? 1 : 2);

    host_ = new QLineEdit(r.value("host").toString());
    host_->setPlaceholderText(tr("any - or example.com, *.example.com"));
    ip_ = new QLineEdit(r.value("ip").toString());
    ip_->setPlaceholderText(tr("any - or 1.2.3.4, 10.0.0.0/8, 2001:db8::/32"));
    port_ = new QSpinBox;
    port_->setRange(0, 65535);
    port_->setSpecialValueText(tr("any"));
    port_->setValue(r.value("port").toInt());
    proto_ = new QComboBox;
    proto_->addItem(tr("any"), "");
    proto_->addItem("TCP", "tcp");
    proto_->addItem("UDP", "udp");
    proto_->setCurrentIndex(qMax(0, proto_->findData(r.value("proto").toString())));
    duration_ = new QComboBox;
    duration_->addItem(tr("Forever"), "forever");
    duration_->addItem(tr("Until vartad restarts"), "session");
    duration_->setCurrentIndex(r.value("duration").toString() == "session" ? 1 : 0);
    note_ = new QLineEdit(r.value("note").toString());

    form->addRow(tr("Action"), action_);
    form->addRow(tr("Program"), exeRow);
    form->addRow(tr("Direction"), direction_);
    form->addRow(tr("Host"), host_);
    form->addRow(tr("IP / range"), ip_);
    form->addRow(tr("Port"), port_);
    form->addRow(tr("Protocol"), proto_);
    form->addRow(tr("Remember"), duration_);
    form->addRow(tr("Note"), note_);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    auto* root = new QVBoxLayout(this);
    root->addLayout(form);
    root->addWidget(buttons);
}

QJsonObject RuleDialog::rule() const {
    QString exe = exe_->text().trimmed();
    if (exe.isEmpty()) exe = "*";
    return {{"action", action_->currentData().toString()},
            {"exe", exe},
            {"direction", direction_->currentData().toString()},
            {"host", host_->text().trimmed().toLower()},
            {"ip", ip_->text().trimmed()},
            {"port", port_->value()},
            {"proto", proto_->currentData().toString()},
            {"duration", duration_->currentData().toString()},
            {"note", note_->text().trimmed()},
            {"enabled", true}};
}

// ---------------------------------------------------------------------------- MainWindow

MainWindow::MainWindow(Backend* backend, QWidget* parent) : QMainWindow(parent), backend_(backend) {
    setWindowTitle(tr("Varta Firewall"));
    setWindowIcon(style::shieldIcon(style::Shield::Ok));
    resize(1180, 720);

    conns_ = new ConnectionsModel(this);
    filter_ = new ConnectionsFilter(this);
    filter_->setSourceModel(conns_);
    rulesModel_ = new RulesModel(this);

    auto* central = new QWidget;
    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);
    root->addWidget(buildHeader());

    updates_ = new UpdateChecker(this);
    tabs_ = new QTabWidget;
    tabs_->setDocumentMode(true);
    tabs_->addTab(buildConnectionsTab(), tr("Connections"));
    tabs_->addTab(buildAppsTab(), tr("Programs"));
    tabs_->addTab(buildRulesTab(), tr("Rules"));
    tabs_->addTab(buildSettingsTab(), tr("Settings"));
    tabs_->addTab(buildAboutTab(), tr("About"));
    auto* tabsWrap = new QWidget;
    auto* tw = new QVBoxLayout(tabsWrap);
    tw->setContentsMargins(10, 8, 10, 6);
    tw->addWidget(tabs_);
    root->addWidget(tabsWrap, 1);
    setCentralWidget(central);

    status_ = new QLabel;
    statusBar()->addWidget(status_, 1);

    prompt_ = new PromptDialog(nullptr);
    connect(prompt_, &PromptDialog::answered, this, &MainWindow::onAnswered);

    buildTray();

    connect(backend_, &Backend::connectedChanged, this, &MainWindow::onConnected);
    connect(backend_, &Backend::hello, this, &MainWindow::onHello);
    connect(backend_, &Backend::history, this, [this](const QJsonArray& ev) {
        conns_->reset(ev);
        appStats_.clear();
        for (const auto& e : ev) updateApps(e.toObject());
    });
    connect(backend_, &Backend::event, this, &MainWindow::onEvent);
    connect(backend_, &Backend::ask, this, &MainWindow::onAsk);
    connect(backend_, &Backend::askDone, this, &MainWindow::onAskDone);
    connect(backend_, &Backend::rules, this, &MainWindow::onRules);
    connect(backend_, &Backend::settings, this, &MainWindow::onSettings);
    connect(backend_, &Backend::error, this, [this](const QString& m) {
        statusBar()->showMessage(tr("vartad: %1").arg(m), 8000);
    });

    QSettings qs;
    restoreGeometry(qs.value("window/geometry").toByteArray());
    updateStatus();
}

void MainWindow::startUpdateCheck() { updates_->checkOnStartup(); }

void MainWindow::showTab(int index) { tabs_->setCurrentIndex(index); }

QWidget* MainWindow::buildHeader() {
    auto* bar = new QFrame;
    bar->setObjectName("headerBar");
    auto* l = new QHBoxLayout(bar);
    l->setContentsMargins(16, 10, 16, 10);

    stateIcon_ = new QLabel;
    stateIcon_->setPixmap(style::shieldPixmap(style::Shield::Off, 34));
    auto* title = new QLabel("Varta");
    title->setObjectName("title");
    auto* sub = new QLabel(tr("application firewall"));
    sub->setObjectName("muted");
    auto* tbox = new QVBoxLayout;
    tbox->setSpacing(0);
    tbox->addWidget(title);
    tbox->addWidget(sub);
    l->addWidget(stateIcon_);
    l->addSpacing(6);
    l->addLayout(tbox);
    l->addSpacing(30);

    // Segmented mode switch.
    auto* modeLabel = new QLabel(tr("Mode:"));
    modeLabel->setObjectName("muted");
    l->addWidget(modeLabel);
    modeGroup_ = new QButtonGroup(this);
    modeGroup_->setExclusive(true);
    const struct {
        const char* id;
        QString text;
        QString tip;
    } modes[] = {
        {"ask", tr("Ask"), tr("Ask about every new program / destination")},
        {"allow", tr("Allow & log"), tr("Allow everything without a rule, but log it (learning mode)")},
        {"deny", tr("Block unknown"), tr("Block everything that has no allow rule, without asking")},
    };
    auto* seg = new QHBoxLayout;
    seg->setSpacing(0);
    for (const auto& m : modes) {
        auto* b = new QPushButton(m.text);
        b->setObjectName("modeButton");
        b->setCheckable(true);
        b->setToolTip(m.tip);
        b->setProperty("mode", m.id);
        modeGroup_->addButton(b);
        seg->addWidget(b);
        if (QString(m.id) == "ask") b->setChecked(true);
    }
    connect(modeGroup_, &QButtonGroup::buttonClicked, this, [this](QAbstractButton* b) {
        backend_->setSetting("mode", b->property("mode").toString());
    });
    l->addLayout(seg);
    l->addStretch(1);

    counters_ = new QLabel;
    l->addWidget(counters_);
    return bar;
}

QWidget* MainWindow::buildConnectionsTab() {
    auto* w = new QWidget;
    auto* l = new QVBoxLayout(w);
    l->setContentsMargins(0, 8, 0, 0);
    auto* tools = new QHBoxLayout;
    auto* search = new QLineEdit;
    search->setPlaceholderText(tr("Search program, host, IP, owner, country…"));
    search->setClearButtonEnabled(true);
    auto* kind = new QComboBox;
    kind->addItem(tr("All"), ConnectionsFilter::All);
    kind->addItem(tr("Allowed"), ConnectionsFilter::Allowed);
    kind->addItem(tr("Blocked"), ConnectionsFilter::Denied);
    kind->addItem(tr("Outgoing"), ConnectionsFilter::Outgoing);
    kind->addItem(tr("Incoming"), ConnectionsFilter::Incoming);
    kind->addItem(tr("Trackers only"), ConnectionsFilter::Trackers);
    pause_ = new QCheckBox(tr("Pause"));
    pause_->setToolTip(tr("Stop adding new rows while you look at the log"));
    auto* clear = new QPushButton(tr("Clear"));
    tools->addWidget(search, 1);
    tools->addWidget(kind);
    tools->addWidget(pause_);
    tools->addWidget(clear);
    l->addLayout(tools);

    connect(search, &QLineEdit::textChanged, filter_, &ConnectionsFilter::setText);
    connect(kind, &QComboBox::currentIndexChanged, this,
            [this, kind] { filter_->setKind(ConnectionsFilter::Kind(kind->currentData().toInt())); });
    connect(clear, &QPushButton::clicked, this, [this] { backend_->clearHistory(); });

    connView_ = new QTableView;
    connView_->setModel(filter_);
    connView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    connView_->setSelectionMode(QAbstractItemView::SingleSelection);
    connView_->setAlternatingRowColors(true);
    connView_->setShowGrid(false);
    connView_->verticalHeader()->hide();
    connView_->verticalHeader()->setDefaultSectionSize(26);
    connView_->setWordWrap(false);
    connView_->setContextMenuPolicy(Qt::CustomContextMenu);
    auto* h = connView_->horizontalHeader();
    h->setStretchLastSection(true);
    h->setSectionResizeMode(QHeaderView::Interactive);
    const int widths[] = {72, 160, 64, 250, 125, 90, 180, 62, 110, 120};
    for (int i = 0; i < ConnectionsModel::ColumnCount; ++i) connView_->setColumnWidth(i, widths[i]);
    connect(connView_, &QTableView::customContextMenuRequested, this, &MainWindow::connectionMenu);
    l->addWidget(connView_, 1);
    return w;
}

QWidget* MainWindow::buildAppsTab() {
    auto* w = new QWidget;
    auto* l = new QVBoxLayout(w);
    l->setContentsMargins(0, 8, 0, 0);
    auto* hint = new QLabel(tr("Every program seen on the network since the GUI started, with its most frequent destinations."));
    hint->setObjectName("muted");
    l->addWidget(hint);
    apps_ = new QTreeWidget;
    apps_->setColumnCount(5);
    apps_->setHeaderLabels({tr("Program / destination"), tr("Connections"), tr("Allowed"), tr("Blocked"), tr("Last seen")});
    apps_->setAlternatingRowColors(true);
    apps_->setRootIsDecorated(true);
    apps_->setSortingEnabled(true);
    apps_->sortByColumn(1, Qt::DescendingOrder);
    apps_->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    for (int i = 1; i < 5; ++i) apps_->header()->setSectionResizeMode(i, QHeaderView::ResizeToContents);
    l->addWidget(apps_, 1);
    return w;
}

QWidget* MainWindow::buildRulesTab() {
    auto* w = new QWidget;
    auto* l = new QVBoxLayout(w);
    l->setContentsMargins(0, 8, 0, 0);
    auto* tools = new QHBoxLayout;
    auto* add = new QPushButton(tr("Add rule…"));
    auto* edit = new QPushButton(tr("Edit…"));
    auto* del = new QPushButton(tr("Delete"));
    auto* hint = new QLabel(tr("The most specific matching rule wins; on a tie, deny wins."));
    hint->setObjectName("muted");
    tools->addWidget(add);
    tools->addWidget(edit);
    tools->addWidget(del);
    tools->addStretch(1);
    tools->addWidget(hint);
    l->addLayout(tools);

    rulesView_ = new QTableView;
    rulesView_->setModel(rulesModel_);
    rulesView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    rulesView_->setSelectionMode(QAbstractItemView::SingleSelection);
    rulesView_->setAlternatingRowColors(true);
    rulesView_->setShowGrid(false);
    rulesView_->verticalHeader()->hide();
    rulesView_->verticalHeader()->setDefaultSectionSize(26);
    auto* rh = rulesView_->horizontalHeader();
    rh->setStretchLastSection(true);
    rh->setSectionResizeMode(QHeaderView::ResizeToContents);
    rh->setSectionResizeMode(RulesModel::Host, QHeaderView::Stretch);
    l->addWidget(rulesView_, 1);

    connect(rulesModel_, &RulesModel::toggleRequested, this,
            [this](qint64 id, bool on) { backend_->updateRule(id, {{"enabled", on}}); });
    connect(add, &QPushButton::clicked, this, [this] {
        RuleDialog d(QJsonObject{{"action", "allow"}, {"exe", "*"}, {"direction", "out"}}, this);
        if (d.exec() == QDialog::Accepted) backend_->addRule(d.rule());
    });
    connect(edit, &QPushButton::clicked, this, [this] {
        const auto sel = rulesView_->selectionModel()->selectedRows();
        if (!sel.isEmpty()) editRule(sel.first().row());
    });
    connect(rulesView_, &QTableView::doubleClicked, this, [this](const QModelIndex& i) { editRule(i.row()); });
    connect(del, &QPushButton::clicked, this, [this] {
        const auto sel = rulesView_->selectionModel()->selectedRows();
        if (sel.isEmpty()) return;
        const QJsonObject r = rulesModel_->at(sel.first().row());
        if (QMessageBox::question(this, tr("Delete rule"),
                                  tr("Delete the rule for %1?").arg(r.value("exe").toString())) ==
            QMessageBox::Yes)
            backend_->deleteRule(r.value("id").toInteger());
    });
    return w;
}

void MainWindow::editRule(int row) {
    const QJsonObject r = rulesModel_->at(row);
    RuleDialog d(r, this);
    if (d.exec() == QDialog::Accepted) backend_->updateRule(r.value("id").toInteger(), d.rule());
}

QWidget* MainWindow::buildSettingsTab() {
    auto* w = new QWidget;
    auto* outer = new QHBoxLayout(w);
    auto* inner = new QWidget;
    inner->setMaximumWidth(820);
    outer->addWidget(inner, 1);
    outer->addStretch(0);
    auto* l = new QVBoxLayout(inner);
    l->setContentsMargins(4, 12, 4, 4);

    auto* daemonBox = new QGroupBox(tr("Firewall (vartad)"));
    auto* f = new QFormLayout(daemonBox);
    timeout_ = new QSpinBox;
    timeout_->setRange(5, 600);
    timeout_->setSuffix(tr(" s"));
    timeoutAction_ = new QComboBox;
    timeoutAction_->addItem(tr("Deny"), "deny");
    timeoutAction_->addItem(tr("Allow"), "allow");
    noGuiAction_ = new QComboBox;
    noGuiAction_->addItem(tr("Allow (recommended - the system keeps working before login)"), "allow");
    noGuiAction_->addItem(tr("Deny (strict)"), "deny");
    askInbound_ = new QCheckBox(tr("Also ask about new incoming connections"));
    autoDns_ = new QCheckBox(tr("Let DNS queries (port 53) through without asking"));
    f->addRow(tr("Prompt timeout"), timeout_);
    f->addRow(tr("When there is no answer"), timeoutAction_);
    f->addRow(tr("When no GUI is running"), noGuiAction_);
    f->addRow(QString(), askInbound_);
    f->addRow(QString(), autoDns_);
    l->addWidget(daemonBox);

    auto send = [this](const QString& key, const QString& value) {
        if (!applyingSettings_) backend_->setSetting(key, value);
    };
    connect(timeout_, &QSpinBox::editingFinished, this, [=] { send("prompt_timeout", QString::number(timeout_->value())); });
    connect(timeoutAction_, &QComboBox::currentIndexChanged, this, [=] { send("timeout_action", timeoutAction_->currentData().toString()); });
    connect(noGuiAction_, &QComboBox::currentIndexChanged, this, [=] { send("no_gui_action", noGuiAction_->currentData().toString()); });
    connect(askInbound_, &QCheckBox::toggled, this, [=](bool on) { send("ask_inbound", on ? "on" : "off"); });
    connect(autoDns_, &QCheckBox::toggled, this, [=](bool on) { send("auto_allow_dns", on ? "on" : "off"); });

    auto* guiBox = new QGroupBox(tr("This window"));
    auto* g = new QFormLayout(guiBox);
    QSettings qs;
    theme_ = new QComboBox;
    theme_->addItem(tr("Follow system"), "system");
    theme_->addItem(tr("Dark"), "dark");
    theme_->addItem(tr("Light"), "light");
    theme_->setCurrentIndex(qMax(0, theme_->findData(qs.value("theme", "dark").toString())));
    notifyBlocked_ = new QCheckBox(tr("Show a notification when a rule blocks a program"));
    notifyBlocked_->setChecked(qs.value("notifyBlocked", false).toBool());
    auto* lang = new QComboBox;
    lang->addItem(tr("System language"), "");
    lang->addItem("English", "en");
    lang->addItem("Українська", "uk");
    lang->setCurrentIndex(qMax(0, lang->findData(qs.value("language", "").toString())));
    g->addRow(tr("Theme"), theme_);
    g->addRow(tr("Language"), lang);
    g->addRow(QString(), notifyBlocked_);
    auto* autoUpdate = new QCheckBox(tr("Check for updates once a day"));
    autoUpdate->setChecked(UpdateChecker::checkAtStartupEnabled());
    autoUpdate->setToolTip(tr("One anonymous request to api.github.com. Nothing about you or your rules is sent."));
    auto* checkNow = new QPushButton(tr("Check now"));
    auto* updRow = new QHBoxLayout;
    updRow->addWidget(autoUpdate);
    updRow->addWidget(checkNow);
    updRow->addStretch(1);
    g->addRow(tr("Updates"), updRow);
    connect(autoUpdate, &QCheckBox::toggled, this, [](bool on) { UpdateChecker::setCheckAtStartupEnabled(on); });
    connect(checkNow, &QPushButton::clicked, this, [this] { updates_->checkNow(); });
    auto* restartHint = new QLabel(tr("Theme and language changes apply after restarting the GUI."));
    restartHint->setObjectName("muted");
    g->addRow(QString(), restartHint);
    l->addWidget(guiBox);
    connect(theme_, &QComboBox::currentIndexChanged, this, [this] { QSettings().setValue("theme", theme_->currentData()); });
    connect(lang, &QComboBox::currentIndexChanged, this, [lang] { QSettings().setValue("language", lang->currentData()); });
    connect(notifyBlocked_, &QCheckBox::toggled, this, [](bool on) { QSettings().setValue("notifyBlocked", on); });

    ipdbInfo_ = new QLabel;
    ipdbInfo_->setObjectName("muted");
    ipdbInfo_->setWordWrap(true);
    l->addWidget(ipdbInfo_);
    l->addStretch(1);
    return w;
}

QWidget* MainWindow::buildAboutTab() {
    auto* w = new QWidget;
    auto* l = new QVBoxLayout(w);
    l->setContentsMargins(20, 20, 20, 20);
    auto* icon = new QLabel;
    icon->setPixmap(style::shieldPixmap(style::Shield::Ok, 72));
    auto* text = new QLabel(
        tr("<h2>Varta %1</h2>"
           "<p>An open-source application firewall: it asks before a program talks to the network, "
           "shows who owns every address and blocks known trackers and telemetry.</p>"
           "<p><b>How it works:</b> the <code>vartad</code> service holds the first packet of every new "
           "connection (Linux: NFQUEUE, Windows: WinDivert), finds the program that owns the socket, looks up the host name "
           "from DNS answers and the owner/country in an offline IP database, then applies your rules "
           "or asks you here.</p>"
           "<p>IP data: <a href='https://db-ip.com'>IP Geolocation by DB-IP</a> and "
           "<a href='https://www.routeviews.org'>RouteViews</a> (CC BY 4.0), packaged by "
           "<a href='https://github.com/sapics/ip-location-db'>ip-location-db</a>.</p>"
           "<p>Windows packet capture: <a href='https://reqrypt.org/windivert.html'>WinDivert</a> (LGPL v3).</p>"
           "<p>Licence: MIT.</p>").arg(QApplication::applicationVersion()));
    text->setWordWrap(true);
    text->setOpenExternalLinks(true);
    text->setTextFormat(Qt::RichText);
    auto* row = new QHBoxLayout;
    row->addWidget(icon, 0, Qt::AlignTop);
    row->addSpacing(16);
    row->addWidget(text, 1);
    l->addLayout(row);
    l->addStretch(1);
    return w;
}

void MainWindow::buildTray() {
    if (!QSystemTrayIcon::isSystemTrayAvailable()) return;
    tray_ = new QSystemTrayIcon(style::shieldIcon(style::Shield::Off), this);
    auto* menu = new QMenu(this);
    menu->addAction(tr("Open Varta"), this, [this] {
        showNormal();
        raise();
        activateWindow();
    });
    menu->addSeparator();
    auto* modeMenu = menu->addMenu(tr("Mode"));
    for (auto* b : modeGroup_->buttons()) {
        QAction* a = modeMenu->addAction(b->text());
        connect(a, &QAction::triggered, this, [this, b] { backend_->setSetting("mode", b->property("mode").toString()); });
    }
    menu->addSeparator();
    menu->addAction(tr("Quit"), this, [this] {
        quitting_ = true;
        qApp->quit();
    });
    tray_->setContextMenu(menu);
    connect(tray_, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason r) {
        if (r == QSystemTrayIcon::Trigger) {
            if (isVisible() && !isMinimized()) hide();
            else {
                showNormal();
                raise();
                activateWindow();
            }
        }
    });
    tray_->show();
}

void MainWindow::closeEvent(QCloseEvent* e) {
    QSettings().setValue("window/geometry", saveGeometry());
    if (tray_ && !quitting_) {
        hide();  // keep running in the tray so prompts still appear
        e->ignore();
        return;
    }
    QMainWindow::closeEvent(e);
}

// --------------------------------------------------------------------------- backend

void MainWindow::onConnected(bool on) {
    if (!on) {
        // Prompts can no longer be answered; the daemon settles them itself.
        queue_.clear();
        prompt_->hide();
    }
    updateStatus();
}

void MainWindow::onHello(const QJsonObject& m) {
    allowed_ = m.value("allowed").toInteger();
    denied_ = m.value("denied").toInteger();
    attribution_ = m.value("ipdb_attribution").toString();
    prompt_->setPlatform(m.value("platform").toString());
    const qint64 ranges = m.value("ipdb_ranges").toInteger();
#if defined(Q_OS_WIN)
    const QString updateCmd = "vartad --update-db";
#elif defined(Q_OS_MACOS)
    const QString updateCmd = "sudo /Applications/Varta.app/Contents/MacOS/vartad --update-db";
#else
    const QString updateCmd = "sudo vartad --update-db";
#endif
    ipdbInfo_->setText(ranges ? tr("IP database: %L1 address ranges loaded. %2").arg(ranges).arg(attribution_)
                              : tr("IP database not installed - run: %1").arg(updateCmd));
    updateStatus();
}

void MainWindow::onEvent(const QJsonObject& e) {
    (e.value("verdict").toString() == "deny" ? denied_ : allowed_)++;
    if (!pause_->isChecked()) conns_->add(e);
    updateApps(e);
    if (tray_ && notifyBlocked_->isChecked() && e.value("verdict").toString() == "deny" &&
        e.value("reason").toString() == "rule") {
        tray_->showMessage(tr("Blocked %1").arg(style::programName(e)), style::destination(e),
                           QSystemTrayIcon::Warning, 4000);
    }
    updateStatus();
}

void MainWindow::updateApps(const QJsonObject& e) {
    const QString exe = e.value("exe").toString();
    const QString key = exe.isEmpty() ? QStringLiteral("?") : exe;
    AppStats& s = appStats_[key];
    s.exe = exe;
    s.name = style::programName(e);
    ++s.total;
    (e.value("verdict").toString() == "deny" ? s.denied : s.allowed)++;
    s.last = qMax(s.last, e.value("time").toInteger());
    s.dests[style::destination(e)]++;

    // Rebuild only this program's row (cheap even with many programs).
    QTreeWidgetItem* item = nullptr;
    for (int i = 0; i < apps_->topLevelItemCount(); ++i)
        if (apps_->topLevelItem(i)->data(0, Qt::UserRole).toString() == key) item = apps_->topLevelItem(i);
    apps_->setSortingEnabled(false);
    if (!item) {
        item = new QTreeWidgetItem(apps_);
        item->setData(0, Qt::UserRole, key);
        item->setIcon(0, style::appPixmap(e.value("name").toString(), 20, e.value("exe").toString()));
    }
    item->setText(0, exe.isEmpty() ? s.name : QString("%1   %2").arg(s.name, exe));
    item->setData(1, Qt::DisplayRole, s.total);
    item->setData(2, Qt::DisplayRole, s.allowed);
    item->setData(3, Qt::DisplayRole, s.denied);
    item->setText(4, style::timeOfDay(s.last));
    item->setForeground(3, s.denied ? style::deny() : style::muted());
    qDeleteAll(item->takeChildren());
    QList<QPair<int, QString>> top;
    for (auto it = s.dests.begin(); it != s.dests.end(); ++it) top.append({it.value(), it.key()});
    std::sort(top.begin(), top.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
    for (int i = 0; i < qMin(10, int(top.size())); ++i) {
        auto* child = new QTreeWidgetItem(item);
        child->setText(0, top[i].second);
        child->setData(1, Qt::DisplayRole, top[i].first);
    }
    apps_->setSortingEnabled(true);
}

void MainWindow::onAsk(const QJsonObject& a) {
    const qint64 id = a.value("id").toInteger();
    for (const auto& q : queue_)
        if (q.value("id").toInteger() == id) return;
    if (prompt_->isVisible() && prompt_->currentId() == id) return;
    queue_.append(a);
    if (!prompt_->isVisible() || prompt_->currentId() < 0) showNextPrompt();
    else prompt_->setQueued(int(queue_.size()));
    if (tray_) tray_->setIcon(style::shieldIcon(style::Shield::Warn));
}

void MainWindow::onAskDone(qint64 id) {
    for (int i = 0; i < queue_.size(); ++i)
        if (queue_[i].value("id").toInteger() == id) {
            queue_.removeAt(i);
            break;
        }
    // Answered elsewhere (timeout, another GUI, or a new rule covered it).
    if (prompt_->isVisible() && prompt_->currentId() == id) showNextPrompt();
    else if (prompt_->isVisible()) prompt_->setQueued(int(queue_.size()));
    updateStatus();
}

void MainWindow::showNextPrompt() {
    if (queue_.isEmpty()) {
        prompt_->hide();
        updateStatus();
        return;
    }
    const QJsonObject next = queue_.takeFirst();
    prompt_->showConnection(next, int(queue_.size()));
}

void MainWindow::onAnswered(qint64 id, bool allow, const QString& scope, const QString& duration) {
    backend_->answer(id, allow, scope, duration);
    showNextPrompt();
}

void MainWindow::onSettings(const QJsonObject& s) {
    applyingSettings_ = true;
    mode_ = s.value("mode").toString("ask");
    for (auto* b : modeGroup_->buttons()) b->setChecked(b->property("mode").toString() == mode_);
    timeout_->setValue(s.value("prompt_timeout").toInt(30));
    timeoutAction_->setCurrentIndex(qMax(0, timeoutAction_->findData(s.value("timeout_action").toString())));
    noGuiAction_->setCurrentIndex(qMax(0, noGuiAction_->findData(s.value("no_gui_action").toString())));
    askInbound_->setChecked(s.value("ask_inbound").toBool());
    autoDns_->setChecked(s.value("auto_allow_dns").toBool());
    applyingSettings_ = false;
    updateStatus();
}

void MainWindow::onRules(const QJsonArray& r) {
    rulesModel_->reset(r);
    tabs_->setTabText(2, tr("Rules (%1)").arg(r.size()));
}

void MainWindow::updateStatus() {
    const bool on = backend_->isConnected();
    style::Shield s = !on ? style::Shield::Off
                    : mode_ == "allow" ? style::Shield::Warn
                    : style::Shield::Ok;
    if (on && (!queue_.isEmpty() || (prompt_ && prompt_->isVisible()))) s = style::Shield::Warn;
    stateIcon_->setPixmap(style::shieldPixmap(s, 34));
    if (tray_) {
        tray_->setIcon(style::shieldIcon(s));
        tray_->setToolTip(on ? tr("Varta: %1 allowed, %2 blocked").arg(allowed_).arg(denied_)
                             : tr("Varta: not connected to vartad"));
    }
    counters_->setText(QString("<span style='color:%1'>●</span> %2 &nbsp;&nbsp; "
                               "<span style='color:%3'>●</span> %4")
                           .arg(style::allow().name(), tr("%L1 allowed").arg(allowed_),
                                style::deny().name(), tr("%L1 blocked").arg(denied_)));
    if (on) {
        status_->setText(tr("Connected: %1").arg(backend_->description()));
    } else {
        QString why;
        if (auto* sb = qobject_cast<SocketBackend*>(backend_)) why = sb->lastError();
        status_->setText(tr("Not connected to vartad. %1").arg(why));
    }
}

// --------------------------------------------------------------------- context menu

void MainWindow::connectionMenu(const QPoint& pos) {
    const QModelIndex idx = connView_->indexAt(pos);
    if (!idx.isValid()) return;
    const QJsonObject c = idx.data(ConnectionsModel::RawRole).toJsonObject();
    const QString prog = style::programName(c);
    const QString dest = style::destination(c);
    QMenu menu(this);
    if (!c.value("exe").toString().isEmpty()) {
        menu.addAction(tr("Always allow %1 → %2").arg(prog, dest), this, [=] { quickRule(c, true, true); });
        menu.addAction(tr("Always block %1 → %2").arg(prog, dest), this, [=] { quickRule(c, false, true); });
        menu.addAction(tr("Always block %1 (everything)").arg(prog), this, [=] { quickRule(c, false, false); });
        menu.addSeparator();
    }
    menu.addAction(tr("Copy IP address"), this, [=] { QApplication::clipboard()->setText(c.value("remote").toString()); });
    if (!c.value("host").toString().isEmpty())
        menu.addAction(tr("Copy host name"), this, [=] { QApplication::clipboard()->setText(c.value("host").toString()); });
    menu.addAction(tr("Copy program path"), this, [=] { QApplication::clipboard()->setText(c.value("exe").toString()); });
    menu.exec(connView_->viewport()->mapToGlobal(pos));
}

void MainWindow::quickRule(const QJsonObject& c, bool allow, bool withDest) {
    QJsonObject r{{"action", allow ? "allow" : "deny"},
                  {"exe", c.value("exe").toString()},
                  {"direction", c.value("dir").toString()},
                  {"duration", "forever"},
                  {"enabled", true},
                  {"note", "added from log"}};
    if (withDest) {
        if (!c.value("host").toString().isEmpty()) r["host"] = c.value("host").toString();
        else r["ip"] = c.value("remote").toString();
    }
    backend_->addRule(r);
    statusBar()->showMessage(tr("Rule added."), 4000);
}
