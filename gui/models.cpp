#include "models.hpp"

#include <QFileInfo>
#include <QFont>

#include "style.hpp"

// ---------------------------------------------------------------------- ConnectionsModel

ConnectionsModel::ConnectionsModel(QObject* parent) : QAbstractTableModel(parent) {}

QVariant ConnectionsModel::headerData(int s, Qt::Orientation o, int role) const {
    if (o != Qt::Horizontal || role != Qt::DisplayRole) return {};
    switch (s) {
        case Time: return tr("Time");
        case Program: return tr("Program");
        case Dir: return tr("Dir");
        case Destination: return tr("Destination");
        case Address: return tr("IP address");
        case Port: return tr("Port");
        case Owner: return tr("Owner");
        case Country: return tr("Country");
        case Verdict: return tr("Verdict");
        case Reason: return tr("Reason");
    }
    return {};
}

static QString reasonText(const QString& r) {
    if (r == "rule") return QObject::tr("rule");
    if (r == "user (once)") return QObject::tr("you, once");
    if (r == "user (new rule)") return QObject::tr("you, new rule");
    if (r == "timeout") return QObject::tr("no answer (timeout)");
    if (r == "no GUI connected") return QObject::tr("no GUI connected");
    if (r == "GUI disconnected") return QObject::tr("GUI disconnected");
    if (r.startsWith("mode")) return QObject::tr("mode");
    return r;
}

QVariant ConnectionsModel::data(const QModelIndex& idx, int role) const {
    if (!idx.isValid() || idx.row() >= rows_.size()) return {};
    // Newest first in the view.
    const QJsonObject& c = rows_[rows_.size() - 1 - idx.row()];
    if (role == RawRole) return c;
    const bool deny = c.value("verdict").toString() == "deny";
    const bool inbound = c.value("dir").toString() == "in";
    const bool tracker = !c.value("category").toString().isEmpty();

    if (role == Qt::DisplayRole) {
        switch (idx.column()) {
            case Time: return style::timeOfDay(c.value("time").toInteger());
            case Program: return style::programName(c);
            case Dir: return inbound ? tr("↓ in") : tr("↑ out");
            case Destination: return style::destination(c);
            case Address: return c.value("remote").toString();
            case Port: {
                const int p = inbound ? c.value("local_port").toInt() : c.value("remote_port").toInt();
                const QString n = style::portName(p, c.value("proto").toString());
                return n.isEmpty() ? QString("%1/%2").arg(p).arg(c.value("proto").toString())
                                   : QString("%1 %2").arg(p).arg(n);
            }
            case Owner: {
                const QString s = c.value("special").toString();
                return s.isEmpty() ? c.value("org").toString() : s;
            }
            case Country: {
                return c.value("country").toString();
            }
            case Verdict: return deny ? tr("blocked") : tr("allowed");
            case Reason: return reasonText(c.value("reason").toString());
        }
    } else if (role == Qt::ForegroundRole) {
        if (idx.column() == Verdict) return deny ? style::deny() : style::allow();
        if (idx.column() == Destination && tracker) return style::warn();
        if (idx.column() == Time || idx.column() == Reason) return style::muted();
    } else if (role == Qt::FontRole && idx.column() == Verdict) {
        QFont f;
        f.setBold(true);
        return f;
    } else if (role == Qt::ToolTipRole) {
        QString tip = QString("<b>%1</b><br>%2<br>PID %3, %4<br><br>%5 → %6:%7 (%8)<br>%9 %10")
                          .arg(style::programName(c).toHtmlEscaped(),
                               c.value("exe").toString().toHtmlEscaped())
                          .arg(c.value("pid").toInt())
                          .arg(c.value("user").toString().toHtmlEscaped(),
                               c.value("dir").toString(), c.value("remote").toString())
                          .arg(c.value("remote_port").toInt())
                          .arg(c.value("proto").toString(), c.value("org").toString().toHtmlEscaped(),
                               style::countryName(c.value("country").toString()));
        if (tracker) tip += "<br><br>⚠ " + c.value("category_title").toString().toHtmlEscaped();
        return tip;
    } else if (role == Qt::DecorationRole && idx.column() == Program) {
        return style::appPixmap(c.value("name").toString(), 16, c.value("exe").toString());
    }
    return {};
}

void ConnectionsModel::reset(const QJsonArray& events) {
    beginResetModel();
    rows_.clear();
    const int start = qMax(0, int(events.size()) - limit_);
    for (int i = start; i < events.size(); ++i) rows_.push_back(events[i].toObject());
    endResetModel();
}

void ConnectionsModel::add(const QJsonObject& e) {
    // New rows appear at the top (row 0) because the view shows newest first.
    beginInsertRows({}, 0, 0);
    rows_.push_back(e);
    endInsertRows();
    if (rows_.size() > limit_) {
        const int last = int(rows_.size()) - 1;
        beginRemoveRows({}, last, last);
        rows_.pop_front();
        endRemoveRows();
    }
}

// --------------------------------------------------------------------- ConnectionsFilter

void ConnectionsFilter::setKind(Kind k) {
    kind_ = k;
    invalidateFilter();
}

void ConnectionsFilter::setText(const QString& t) {
    text_ = t.trimmed();
    invalidateFilter();
}

bool ConnectionsFilter::filterAcceptsRow(int row, const QModelIndex& parent) const {
    const QModelIndex idx = sourceModel()->index(row, 0, parent);
    const QJsonObject c = idx.data(ConnectionsModel::RawRole).toJsonObject();
    switch (kind_) {
        case All: break;
        case Allowed: if (c.value("verdict").toString() != "allow") return false; break;
        case Denied: if (c.value("verdict").toString() != "deny") return false; break;
        case Incoming: if (c.value("dir").toString() != "in") return false; break;
        case Outgoing: if (c.value("dir").toString() != "out") return false; break;
        case Trackers: if (c.value("category").toString().isEmpty()) return false; break;
    }
    if (text_.isEmpty()) return true;
    for (const char* key : {"name", "exe", "host", "remote", "org", "country", "user", "cmdline"})
        if (c.value(key).toString().contains(text_, Qt::CaseInsensitive)) return true;
    return QString::number(c.value("remote_port").toInt()) == text_;
}

// ---------------------------------------------------------------------------- RulesModel

RulesModel::RulesModel(QObject* parent) : QAbstractTableModel(parent) {}

QVariant RulesModel::headerData(int s, Qt::Orientation o, int role) const {
    if (o != Qt::Horizontal || role != Qt::DisplayRole) return {};
    switch (s) {
        case Enabled: return tr("On");
        case Action: return tr("Action");
        case Program: return tr("Program");
        case Direction: return tr("Dir");
        case Host: return tr("Host");
        case Ip: return tr("IP / range");
        case Port: return tr("Port");
        case Proto: return tr("Proto");
        case Duration: return tr("Kept");
        case Hits: return tr("Hits");
        case Note: return tr("Note");
    }
    return {};
}

QVariant RulesModel::data(const QModelIndex& idx, int role) const {
    if (!idx.isValid() || idx.row() >= rules_.size()) return {};
    const QJsonObject& r = rules_[idx.row()];
    const bool deny = r.value("action").toString() == "deny";
    auto any = [](const QString& s) { return s.isEmpty() ? QObject::tr("any") : s; };
    if (role == Qt::CheckStateRole && idx.column() == Enabled)
        return r.value("enabled").toBool() ? Qt::Checked : Qt::Unchecked;
    if (role == Qt::DisplayRole) {
        switch (idx.column()) {
            case Action: return deny ? tr("deny") : tr("allow");
            case Program: {
                const QString exe = r.value("exe").toString();
                return exe == "*" ? tr("any program") : QFileInfo(exe).fileName();
            }
            case Direction: {
                const QString d = r.value("direction").toString();
                return d == "in" ? tr("in") : d == "out" ? tr("out") : tr("both");
            }
            case Host: return any(r.value("host").toString());
            case Ip: return any(r.value("ip").toString());
            case Port: return r.value("port").toInt() ? QString::number(r.value("port").toInt()) : tr("any");
            case Proto: return any(r.value("proto").toString());
            case Duration: return r.value("duration").toString() == "session" ? tr("until restart") : tr("forever");
            case Hits: return r.value("hits").toInteger();
            case Note: {
                const QString n = r.value("note").toString();
                if (n == "default: system service") return tr("system service (default)");
                if (n == "created from prompt") return tr("answered in a prompt");
                if (n == "added in GUI") return tr("added by hand");
                if (n == "added from log") return tr("added from the log");
                return n;
            }
        }
    }
    if (role == Qt::ToolTipRole && idx.column() == Program) return r.value("exe").toString();
    if (role == Qt::ForegroundRole) {
        if (idx.column() == Action) return deny ? style::deny() : style::allow();
        if (!r.value("enabled").toBool()) return style::muted();
        if (idx.column() == Note || idx.column() == Hits) return style::muted();
    }
    if (role == Qt::FontRole && idx.column() == Action) {
        QFont f;
        f.setBold(true);
        return f;
    }
    return {};
}

Qt::ItemFlags RulesModel::flags(const QModelIndex& idx) const {
    Qt::ItemFlags f = QAbstractTableModel::flags(idx);
    if (idx.column() == Enabled) f |= Qt::ItemIsUserCheckable;
    return f;
}

bool RulesModel::setData(const QModelIndex& idx, const QVariant& v, int role) {
    if (role != Qt::CheckStateRole || idx.column() != Enabled) return false;
    const bool on = v.toInt() == Qt::Checked;
    emit toggleRequested(rules_[idx.row()].value("id").toInteger(), on);
    return true;
}

void RulesModel::reset(const QJsonArray& rules) {
    beginResetModel();
    rules_.clear();
    for (const auto& r : rules) rules_.push_back(r.toObject());
    endResetModel();
}
