// varta-gui - connection to vartad (real Unix socket) or a demo backend with fake data.
#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QLocalSocket>
#include <QObject>
#include <QTimer>

class Backend : public QObject {
    Q_OBJECT
public:
    using QObject::QObject;
    virtual void send(const QJsonObject& msg) = 0;
    virtual bool isConnected() const = 0;
    virtual QString description() const = 0;

    // Convenience wrappers for the protocol.
    void answer(qint64 id, bool allow, const QString& scope, const QString& duration);
    void setSetting(const QString& key, const QString& value);
    void addRule(const QJsonObject& rule);
    void updateRule(qint64 id, const QJsonObject& fields);
    void deleteRule(qint64 id);
    void clearHistory();

signals:
    void connectedChanged(bool connected);
    void hello(const QJsonObject& msg);
    void history(const QJsonArray& events);
    void event(const QJsonObject& conn);
    void ask(const QJsonObject& conn);
    void askDone(qint64 id);
    void rules(const QJsonArray& rules);
    void settings(const QJsonObject& settings);
    void error(const QString& message);

protected:
    void dispatch(const QJsonObject& msg);
};

// Talks newline-delimited JSON to vartad over /run/varta/vartad.sock and reconnects forever.
class SocketBackend : public Backend {
    Q_OBJECT
public:
    explicit SocketBackend(const QString& path, QObject* parent = nullptr);
    void send(const QJsonObject& msg) override;
    bool isConnected() const override;
    QString description() const override { return path_; }
    QString lastError() const { return lastError_; }

private:
    void tryConnect();
    void onReadyRead();
    QString path_;
    QLocalSocket socket_;
    QTimer reconnect_;
    QByteArray buffer_;
    QString lastError_;
};

// Generates realistic-looking traffic so the GUI can be explored (and screenshotted)
// without the daemon or root rights: `varta-gui --demo`.
class DemoBackend : public Backend {
    Q_OBJECT
public:
    explicit DemoBackend(QObject* parent = nullptr);
    void send(const QJsonObject& msg) override;
    bool isConnected() const override { return true; }
    QString description() const override { return tr("demo mode"); }
    void start();
    // Returns a sample "ask" (used for screenshots).
    static QJsonObject sampleAsk(int which);

private:
    void tick();
    QJsonObject randomConnection();
    QTimer timer_;
    qint64 nextId_ = 1000;
    QJsonArray rules_;
    QJsonObject settings_;
    QHash<qint64, QJsonObject> pending_;
};
