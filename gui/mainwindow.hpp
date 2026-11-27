// varta-gui - main window: header with mode switch, connection log, apps, rules, settings.
#pragma once

#include <QDialog>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QMainWindow>
#include <QSystemTrayIcon>

#include "backend.hpp"
#include "models.hpp"

class QButtonGroup;
class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QSpinBox;
class QTableView;
class QTreeWidget;
class QTabWidget;
class PromptDialog;
class UpdateChecker;

// Add / edit a rule by hand.
class RuleDialog : public QDialog {
    Q_OBJECT
public:
    explicit RuleDialog(const QJsonObject& rule, QWidget* parent = nullptr);
    QJsonObject rule() const;

private:
    QComboBox* action_;
    QLineEdit* exe_;
    QComboBox* direction_;
    QLineEdit* host_;
    QLineEdit* ip_;
    QSpinBox* port_;
    QComboBox* proto_;
    QComboBox* duration_;
    QLineEdit* note_;
};

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(Backend* backend, QWidget* parent = nullptr);
    PromptDialog* prompt() const { return prompt_; }
    void showTab(int index);
    void startUpdateCheck();  // daily check for a new release (if enabled)

protected:
    void closeEvent(QCloseEvent* e) override;

private:
    // backend events
    void onConnected(bool on);
    void onHello(const QJsonObject& m);
    void onEvent(const QJsonObject& e);
    void onAsk(const QJsonObject& a);
    void onAskDone(qint64 id);
    void onSettings(const QJsonObject& s);
    void onRules(const QJsonArray& r);

    // prompts
    void showNextPrompt();
    void onAnswered(qint64 id, bool allow, const QString& scope, const QString& duration);

    QWidget* buildHeader();
    QWidget* buildConnectionsTab();
    QWidget* buildAppsTab();
    QWidget* buildRulesTab();
    QWidget* buildSettingsTab();
    QWidget* buildAboutTab();
    void buildTray();
    void updateStatus();
    void updateApps(const QJsonObject& e);
    void connectionMenu(const QPoint& pos);
    void quickRule(const QJsonObject& c, bool allow, bool hostOnly);
    void editRule(int row);

    Backend* backend_;
    PromptDialog* prompt_;
    QList<QJsonObject> queue_;  // asks waiting for the dialog
    QSystemTrayIcon* tray_ = nullptr;
    bool quitting_ = false;

    ConnectionsModel* conns_;
    ConnectionsFilter* filter_;
    RulesModel* rulesModel_;
    QTableView* connView_;
    QTableView* rulesView_;
    QTreeWidget* apps_;
    QTabWidget* tabs_;
    QLabel* status_;
    QLabel* counters_;
    QLabel* stateIcon_;
    QButtonGroup* modeGroup_;
    QCheckBox* pause_;

    // settings widgets
    QSpinBox* timeout_;
    QComboBox* timeoutAction_;
    QComboBox* noGuiAction_;
    QCheckBox* askInbound_;
    QCheckBox* autoDns_;
    QComboBox* theme_;
    QCheckBox* notifyBlocked_;
    QLabel* ipdbInfo_;
    UpdateChecker* updates_ = nullptr;
    bool applyingSettings_ = false;

    QString mode_ = "ask";
    qint64 allowed_ = 0, denied_ = 0;
    QString attribution_;
    struct AppStats {
        QString name, exe;
        qint64 total = 0, allowed = 0, denied = 0, last = 0;
        QHash<QString, int> dests;
    };
    QHash<QString, AppStats> appStats_;
};
