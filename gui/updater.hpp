// varta-gui - checks GitHub for a newer Varta release and helps install it.
//
// Only one anonymous request goes to api.github.com; nothing about the user, the rules or the
// connection log is sent. vartad lets exactly this request through without a prompt
// (see Engine::is_self_update_check). Automatic checks run at most once a day and can be
// switched off in Settings.
#pragma once

#include <QDialog>
#include <QObject>

#include "updateinfo.hpp"

class QLabel;
class QNetworkAccessManager;
class QProgressBar;
class QPushButton;
class QWidget;

class UpdateChecker : public QObject {
    Q_OBJECT
public:
    explicit UpdateChecker(QWidget* window);

    static bool checkAtStartupEnabled();
    static void setCheckAtStartupEnabled(bool enabled);

    void checkOnStartup();  // if enabled and the last check is older than a day
    void checkNow();        // Settings -> "Check now": always reports the result

private:
    void check(bool manual);
    void showResult(const update::ReleaseInfo& info, bool manual);

    QWidget* window_;
    QNetworkAccessManager* network_;
    bool busy_ = false;
};

// Shows the new release. On Windows it downloads the package, checks its SHA-256 and starts
// the normal installer (install.cmd asks for administrator rights, replaces the files and
// restarts the service; rules and settings in %ProgramData%\Varta are kept).
// Elsewhere it opens the release page.
class UpdateDialog : public QDialog {
    Q_OBJECT
public:
    enum Result { Later = QDialog::Rejected, Done = QDialog::Accepted, SkipVersion = 2 };
    UpdateDialog(const update::ReleaseInfo& info, QWidget* parent = nullptr);

private:
    void startDownload();
    void downloadFinished(const QString& path);
    void launchInstaller(const QString& zip);

    update::ReleaseInfo info_;
    QNetworkAccessManager* network_;
    QProgressBar* progress_;
    QLabel* status_;
    QPushButton* mainButton_;
};
