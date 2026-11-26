// varta-gui - table models for the connection log and the rules list.
#pragma once

#include <QAbstractTableModel>
#include <QJsonArray>
#include <QJsonObject>
#include <QSortFilterProxyModel>
#include <QVector>

class ConnectionsModel : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column { Time, Program, Dir, Destination, Address, Port, Owner, Country, Verdict, Reason, ColumnCount };
    static constexpr int RawRole = Qt::UserRole + 1;

    explicit ConnectionsModel(QObject* parent = nullptr);
    int rowCount(const QModelIndex& = {}) const override { return int(rows_.size()); }
    int columnCount(const QModelIndex& = {}) const override { return ColumnCount; }
    QVariant data(const QModelIndex& idx, int role) const override;
    QVariant headerData(int section, Qt::Orientation o, int role) const override;

    void reset(const QJsonArray& events);
    void add(const QJsonObject& event);
    QJsonObject at(int row) const { return rows_.value(row); }
    void setLimit(int n) { limit_ = n; }

private:
    QVector<QJsonObject> rows_;  // newest last
    int limit_ = 5000;
};

// Text search + verdict/direction filter on top of ConnectionsModel.
class ConnectionsFilter : public QSortFilterProxyModel {
    Q_OBJECT
public:
    enum Kind { All, Allowed, Denied, Incoming, Outgoing, Trackers };
    using QSortFilterProxyModel::QSortFilterProxyModel;
    void setKind(Kind k);
    void setText(const QString& t);

protected:
    bool filterAcceptsRow(int row, const QModelIndex& parent) const override;

private:
    Kind kind_ = All;
    QString text_;
};

class RulesModel : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column { Enabled, Action, Program, Direction, Host, Ip, Port, Proto, Duration, Hits, Note, ColumnCount };
    explicit RulesModel(QObject* parent = nullptr);
    int rowCount(const QModelIndex& = {}) const override { return int(rules_.size()); }
    int columnCount(const QModelIndex& = {}) const override { return ColumnCount; }
    QVariant data(const QModelIndex& idx, int role) const override;
    QVariant headerData(int section, Qt::Orientation o, int role) const override;
    Qt::ItemFlags flags(const QModelIndex& idx) const override;
    bool setData(const QModelIndex& idx, const QVariant& v, int role) override;

    void reset(const QJsonArray& rules);
    QJsonObject at(int row) const { return rules_.value(row); }
    int count() const { return int(rules_.size()); }

signals:
    void toggleRequested(qint64 id, bool enabled);

private:
    QVector<QJsonObject> rules_;
};
