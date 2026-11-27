#include "updater.hpp"

#include <QApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QProcess>
#include <QProgressBar>
#include <QPushButton>
#include <QSaveFile>
#include <QSettings>
#include <QStandardPaths>
#include <QTextBrowser>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>

namespace {
const char* kKeyEnabled = "updates/checkAtStartup";
const char* kKeyLastCheck = "updates/lastCheck";
const char* kKeySkip = "updates/skipVersion";
constexpr qint64 kMinSecondsBetweenChecks = 24 * 60 * 60;

QString userAgent() { return QStringLiteral("Varta/%1").arg(QApplication::applicationVersion()); }
}  // namespace

// ------------------------------------------------------------------------- UpdateChecker

UpdateChecker::UpdateChecker(QWidget* window)
    : QObject(window), window_(window), network_(new QNetworkAccessManager(this)) {}

bool UpdateChecker::checkAtStartupEnabled() { return QSettings().value(kKeyEnabled, true).toBool(); }

void UpdateChecker::setCheckAtStartupEnabled(bool enabled) { QSettings().setValue(kKeyEnabled, enabled); }

void UpdateChecker::checkOnStartup() {
    if (!checkAtStartupEnabled()) return;
    const qint64 last = QSettings().value(kKeyLastCheck, 0).toLongLong();
    if (QDateTime::currentSecsSinceEpoch() - last < kMinSecondsBetweenChecks) return;
    // A little after start: the window (or tray icon) is up and the connection to vartad too.
    QTimer::singleShot(15000, this, [this] { check(false); });
}

void UpdateChecker::checkNow() { check(true); }

void UpdateChecker::check(bool manual) {
    if (busy_) return;
    busy_ = true;
    // VARTA_UPDATE_API lets developers test against a local server.
    const QString api = qEnvironmentVariableIsSet("VARTA_UPDATE_API")
                            ? qEnvironmentVariable("VARTA_UPDATE_API")
                            : QString::fromLatin1(update::kLatestReleaseApi);
    QNetworkRequest request{QUrl(api)};
    request.setHeader(QNetworkRequest::UserAgentHeader, userAgent());
    request.setRawHeader("Accept", "application/vnd.github+json");
    request.setTransferTimeout(20000);

    QNetworkReply* reply = network_->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply, manual] {
        reply->deleteLater();
        busy_ = false;
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (reply->error() != QNetworkReply::NoError) {
            if (!manual) return;
            // 404: the repository has no published release yet.
            const QString why = status == 404 ? tr("No release has been published yet.") : reply->errorString();
            QMessageBox::warning(window_, tr("Check for updates"), tr("Could not check for updates:\n%1").arg(why));
            return;
        }
        QSettings().setValue(kKeyLastCheck, QDateTime::currentSecsSinceEpoch());
        // VARTA_UPDATE_ASSET_SUFFIX: developer override for testing downloads on any OS.
        const QString suffix = qEnvironmentVariableIsSet("VARTA_UPDATE_ASSET_SUFFIX")
                                   ? qEnvironmentVariable("VARTA_UPDATE_ASSET_SUFFIX")
                                   : update::platformAssetSuffix();
        showResult(update::parseLatestRelease(reply->readAll(), suffix), manual);
    });
}

void UpdateChecker::showResult(const update::ReleaseInfo& info, bool manual) {
    const QString current = QApplication::applicationVersion();
    if (!info.valid || !update::isNewerVersion(info.version, current)) {
        if (manual)
            QMessageBox::information(window_, tr("Check for updates"),
                                     tr("You have the latest version of Varta (%1).").arg(current));
        return;
    }
    // Automatic checks stay quiet about a version the user chose to skip.
    if (!manual && QSettings().value(kKeySkip).toString() == info.version) return;

    UpdateDialog dialog(info, window_);
    if (dialog.exec() == UpdateDialog::SkipVersion) QSettings().setValue(kKeySkip, info.version);
}

// -------------------------------------------------------------------------- UpdateDialog

UpdateDialog::UpdateDialog(const update::ReleaseInfo& info, QWidget* parent)
    : QDialog(parent), info_(info), network_(new QNetworkAccessManager(this)) {
    setWindowTitle(tr("Varta update"));
    resize(560, 460);

    auto* title = new QLabel(tr("<span style='font-size:17px; font-weight:600'>Varta %1 is available</span>")
                                 .arg(info.version));
    auto* current = new QLabel(tr("You have version %1.").arg(QApplication::applicationVersion()));
    current->setObjectName("muted");

    auto* notes = new QTextBrowser;
    notes->setOpenExternalLinks(true);
    notes->setMarkdown(info.notes.isEmpty() ? tr("No release notes.") : info.notes);

    progress_ = new QProgressBar;
    progress_->setVisible(false);
    status_ = new QLabel;
    status_->setWordWrap(true);
    status_->setObjectName("muted");

    auto* skip = new QPushButton(tr("Skip this version"));
    auto* later = new QPushButton(tr("Later"));
    auto* page = new QPushButton(tr("Open release page"));
    mainButton_ = new QPushButton(tr("Download and install"));
    const bool canDownload = !info.assetUrl.isEmpty();
    mainButton_->setVisible(canDownload);
    (canDownload ? mainButton_ : page)->setDefault(true);
    if (!canDownload)
        status_->setText(tr("Download the new version from the release page and install it the same way as before."));

    auto* buttons = new QHBoxLayout;
    buttons->addWidget(skip);
    buttons->addStretch();
    buttons->addWidget(later);
    buttons->addWidget(page);
    buttons->addWidget(mainButton_);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(title);
    layout->addWidget(current);
    layout->addWidget(notes, 1);
    layout->addWidget(progress_);
    layout->addWidget(status_);
    layout->addLayout(buttons);

    connect(skip, &QPushButton::clicked, this, [this] { done(SkipVersion); });
    connect(later, &QPushButton::clicked, this, &QDialog::reject);
    connect(page, &QPushButton::clicked, this, [this] { QDesktopServices::openUrl(QUrl(info_.pageUrl)); });
    connect(mainButton_, &QPushButton::clicked, this, &UpdateDialog::startDownload);
}

void UpdateDialog::startDownload() {
    if (info_.assetUrl.isEmpty()) return;
    QString dir = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    if (dir.isEmpty()) dir = QDir::tempPath();
    QDir().mkpath(dir);
    QString target = QDir(dir).filePath(info_.assetName);
    const QFileInfo fi(target);
    for (int n = 2; QFileInfo::exists(target); ++n)
        target = QDir(dir).filePath(QStringLiteral("%1 (%2).%3").arg(fi.completeBaseName()).arg(n).arg(fi.suffix()));

    QNetworkRequest request{QUrl(info_.assetUrl)};
    request.setHeader(QNetworkRequest::UserAgentHeader, userAgent());
    // GitHub redirects asset downloads to its file servers (HTTPS -> HTTPS only).
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);

    auto* file = new QSaveFile(target, this);
    if (!file->open(QIODevice::WriteOnly)) {
        status_->setText(tr("Cannot write to %1").arg(QDir::toNativeSeparators(target)));
        file->deleteLater();
        return;
    }
    auto* hash = new QCryptographicHash(QCryptographicHash::Sha256);

    mainButton_->setEnabled(false);
    progress_->setVisible(true);
    progress_->setRange(0, 0);
    status_->setText(tr("Downloading %1…").arg(info_.assetName));

    QNetworkReply* reply = network_->get(request);
    connect(reply, &QNetworkReply::readyRead, this, [reply, file, hash] {
        const QByteArray chunk = reply->readAll();
        hash->addData(chunk);
        file->write(chunk);
    });
    connect(reply, &QNetworkReply::downloadProgress, this, [this](qint64 received, qint64 total) {
        if (total > 0) {
            progress_->setRange(0, 1000);
            progress_->setValue(int(received * 1000 / total));
        }
    });
    connect(reply, &QNetworkReply::finished, this, [this, reply, file, hash, target] {
        reply->deleteLater();
        file->deleteLater();
        const QByteArray rest = reply->readAll();
        hash->addData(rest);
        file->write(rest);
        const QString sha = QString::fromLatin1(hash->result().toHex());
        delete hash;

        auto fail = [this](const QString& msg) {
            status_->setText(msg);
            progress_->setVisible(false);
            mainButton_->setEnabled(true);
        };
        if (reply->error() != QNetworkReply::NoError) {
            file->cancelWriting();
            file->commit();
            fail(tr("Download failed: %1").arg(reply->errorString()));
            return;
        }
        // GitHub publishes the SHA-256 of every release file: a corrupted or swapped
        // download is never run.
        if (!info_.assetSha256.isEmpty() && sha != info_.assetSha256) {
            file->cancelWriting();
            file->commit();
            fail(tr("The downloaded file is damaged (checksum mismatch). Please try again."));
            return;
        }
        if (!file->commit()) {
            fail(tr("Cannot save %1").arg(QDir::toNativeSeparators(target)));
            return;
        }
        downloadFinished(target);
    });
}

void UpdateDialog::downloadFinished(const QString& path) {
    progress_->setRange(0, 1);
    progress_->setValue(1);
    status_->setText(tr("Downloaded to %1.\nThe installer asks for administrator rights, closes this window, "
                        "replaces the program files and restarts the service. Your rules and settings are kept.")
                         .arg(QDir::toNativeSeparators(path)));
    mainButton_->setText(tr("Install now"));
    mainButton_->setEnabled(true);
    disconnect(mainButton_, nullptr, this, nullptr);
    connect(mainButton_, &QPushButton::clicked, this, [this, path] { launchInstaller(path); });
}

void UpdateDialog::launchInstaller(const QString& zip) {
#ifdef Q_OS_WIN
    // Unpack into a fresh temp folder and start the same install.cmd as a manual install
    // (it elevates itself). Paths go through environment variables, so spaces, quotes or
    // brackets in them cannot break the command.
    const QString dest = QDir(QDir::tempPath()).filePath(
        QStringLiteral("varta-update-%1").arg(QDateTime::currentMSecsSinceEpoch()));
    const QString script = QStringLiteral(
        "$ErrorActionPreference = 'Stop'; "
        "Expand-Archive -LiteralPath $env:VARTA_UPDATE_ZIP -DestinationPath $env:VARTA_UPDATE_DIR -Force; "
        "$i = Get-ChildItem -LiteralPath $env:VARTA_UPDATE_DIR -Recurse -Filter install.cmd | Select-Object -First 1; "
        "if (-not $i) { throw 'install.cmd not found in the update package' }; "
        "Start-Process -FilePath $i.FullName -WorkingDirectory $i.DirectoryName");
    QProcess proc;
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("VARTA_UPDATE_ZIP", QDir::toNativeSeparators(zip));
    env.insert("VARTA_UPDATE_DIR", QDir::toNativeSeparators(dest));
    proc.setProcessEnvironment(env);
    proc.setProgram("powershell.exe");
    proc.setArguments({"-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", script});
    if (!proc.startDetached()) {
        status_->setText(tr("Could not start the installer. Unpack %1 and run install.cmd.")
                             .arg(QDir::toNativeSeparators(zip)));
        QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(zip).absolutePath()));
        return;
    }
    // install.ps1 closes the GUI itself before replacing files; nothing else to do here.
    accept();
#elif defined(Q_OS_MACOS)
    // A small script unpacks the ZIP with ditto and runs the package's install.sh; macOS asks
    // for an administrator password through its own dialog (osascript ... with administrator
    // privileges). Paths are single-quoted for the shell, so spaces cannot break them.
    auto sq = [](QString s) { return "'" + s.replace("'", "'\\''") + "'"; };
    const QString dest = QDir(QDir::tempPath()).filePath(
        QStringLiteral("varta-update-%1").arg(QDateTime::currentMSecsSinceEpoch()));
    const QString scriptPath = dest + ".sh";
    QFile f(scriptPath);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        status_->setText(tr("Could not start the installer. Unpack %1 and run install.sh.").arg(zip));
        return;
    }
    f.write(QStringLiteral("#!/bin/sh\nset -e\n"
                           "/usr/bin/ditto -x -k %1 %2\n"
                           "inst=$(/usr/bin/find %2 -maxdepth 2 -name install.sh | /usr/bin/head -n 1)\n"
                           "[ -n \"$inst\" ] || { echo 'install.sh not found'; exit 1; }\n"
                           "/bin/sh \"$inst\" >/tmp/varta-update.log 2>&1 &\n")
                .arg(sq(zip), sq(dest))
                .toUtf8());
    f.close();
    const QString apple = QStringLiteral("do shell script \"/bin/sh %1\" with administrator privileges")
                              .arg(sq(scriptPath).replace("\\", "\\\\").replace("\"", "\\\""));
    if (!QProcess::startDetached("/usr/bin/osascript", {"-e", apple})) {
        status_->setText(tr("Could not start the installer. Unpack %1 and run install.sh.").arg(zip));
        return;
    }
    accept();
#else
    QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(zip).absolutePath()));
    accept();
#endif
}
