// varta-gui - the "allow this connection?" dialog.
#pragma once

#include <QDialog>
#include <QJsonObject>

class QComboBox;
class QLabel;
class QPushButton;
class QTimer;

class PromptDialog : public QDialog {
    Q_OBJECT
public:
    explicit PromptDialog(QWidget* parent = nullptr);

    void showConnection(const QJsonObject& ask, int queued);
    void setQueued(int queued);
    qint64 currentId() const { return id_; }

signals:
    // scope: once | exe | exe_host | exe_domain | exe_ip | exe_port ; duration: session | forever
    void answered(qint64 id, bool allow, const QString& scope, const QString& duration);

protected:
    void reject() override;  // Esc / window close = deny once
    void closeEvent(QCloseEvent* e) override;

private:
    void finish(bool allow);
    void updateCountdown();
    void fillScopes(const QJsonObject& c);

    qint64 id_ = -1;
    qint64 deadline_ = 0;
    QString timeoutAction_;

    QLabel* headerIcon_;
    QLabel* headerTitle_;
    QLabel* headerSub_;
    QLabel* countdown_;
    QLabel* appIcon_;
    QLabel* appName_;
    QLabel* appPath_;
    QLabel* appMeta_;
    QLabel* appCmd_;
    QLabel* host_;
    QLabel* address_;
    QLabel* owner_;
    QLabel* country_;
    QLabel* rdns_;
    QLabel* warning_;
    QComboBox* scope_;
    QComboBox* duration_;
    QPushButton* allow_;
    QPushButton* deny_;
    QLabel* queued_;
    QTimer* timer_;
};
