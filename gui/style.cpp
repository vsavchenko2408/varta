#include "style.hpp"

#include <QApplication>
#include <QDateTime>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QLocale>
#include <QPainter>
#include <QPainterPath>
#include <QPalette>
#include <QStyleFactory>

namespace style {

static bool g_dark = true;

QColor allow() { return g_dark ? QColor("#3fb97f") : QColor("#1f8f5a"); }
QColor deny() { return g_dark ? QColor("#ef5f5f") : QColor("#c93838"); }
QColor warn() { return g_dark ? QColor("#f0b43c") : QColor("#b97a00"); }
QColor accent() { return g_dark ? QColor("#4ea1ff") : QColor("#1f6fd1"); }
QColor muted() { return g_dark ? QColor("#8b95a5") : QColor("#69717d"); }
bool isDark() { return g_dark; }

void apply(const QString& theme) {
    QApplication::setStyle(QStyleFactory::create("Fusion"));
    const QPalette sys = QApplication::palette();
    if (theme == "dark") g_dark = true;
    else if (theme == "light") g_dark = false;
    else g_dark = sys.color(QPalette::Window).lightness() < 128;

    QPalette p;
    if (g_dark) {
        const QColor bg("#161a20"), base("#1d222a"), alt("#222832"), text("#e6e9ee");
        p.setColor(QPalette::Window, bg);
        p.setColor(QPalette::WindowText, text);
        p.setColor(QPalette::Base, base);
        p.setColor(QPalette::AlternateBase, alt);
        p.setColor(QPalette::ToolTipBase, alt);
        p.setColor(QPalette::ToolTipText, text);
        p.setColor(QPalette::Text, text);
        p.setColor(QPalette::Button, QColor("#252b35"));
        p.setColor(QPalette::ButtonText, text);
        p.setColor(QPalette::BrightText, Qt::white);
        p.setColor(QPalette::Highlight, QColor("#2f5f9e"));
        p.setColor(QPalette::HighlightedText, Qt::white);
        p.setColor(QPalette::PlaceholderText, QColor("#6d7684"));
        p.setColor(QPalette::Link, accent());
        p.setColor(QPalette::Mid, QColor("#2c333e"));
        p.setColor(QPalette::Dark, QColor("#0f1216"));
        p.setColor(QPalette::Disabled, QPalette::Text, QColor("#5d6570"));
        p.setColor(QPalette::Disabled, QPalette::ButtonText, QColor("#5d6570"));
        p.setColor(QPalette::Disabled, QPalette::WindowText, QColor("#5d6570"));
    } else {
        const QColor bg("#f4f6f9"), base("#ffffff"), alt("#f0f3f7"), text("#1c2330");
        p.setColor(QPalette::Window, bg);
        p.setColor(QPalette::WindowText, text);
        p.setColor(QPalette::Base, base);
        p.setColor(QPalette::AlternateBase, alt);
        p.setColor(QPalette::ToolTipBase, base);
        p.setColor(QPalette::ToolTipText, text);
        p.setColor(QPalette::Text, text);
        p.setColor(QPalette::Button, QColor("#e9edf2"));
        p.setColor(QPalette::ButtonText, text);
        p.setColor(QPalette::Highlight, QColor("#cfe1fb"));
        p.setColor(QPalette::HighlightedText, text);
        p.setColor(QPalette::PlaceholderText, QColor("#9aa2ad"));
        p.setColor(QPalette::Link, accent());
        p.setColor(QPalette::Mid, QColor("#d5dbe3"));
    }
    QApplication::setPalette(p);

    const QString border = g_dark ? "#2c333e" : "#d5dbe3";
    const QString card = g_dark ? "#1d222a" : "#ffffff";
    const QString header = g_dark ? "#11151a" : "#e9eef5";
    qApp->setStyleSheet(QString(R"(
        QToolTip { border: 1px solid %1; padding: 4px; }
        QTabWidget::pane { border: 1px solid %1; border-radius: 6px; top: -1px; }
        QTabBar::tab { padding: 7px 16px; border: none; margin-right: 2px; }
        QTabBar::tab:selected { border-bottom: 2px solid %4; font-weight: 600; }
        QTableView, QTreeView { border: none; gridline-color: %1; selection-background-color: palette(highlight); }
        QHeaderView::section { background: %3; border: none; border-bottom: 1px solid %1; padding: 5px 6px; font-weight: 600; }
        QLineEdit, QComboBox, QSpinBox { padding: 4px 6px; border: 1px solid %1; border-radius: 5px; background: %2; }
        QPushButton { padding: 6px 14px; border: 1px solid %1; border-radius: 6px; }
        QPushButton:hover { border-color: %4; }
        QPushButton#allowButton { background: %5; color: white; border: none; font-weight: 600; }
        QPushButton#allowButton:hover { background: %6; }
        QPushButton#denyButton { background: %7; color: white; border: none; font-weight: 600; }
        QPushButton#denyButton:hover { background: %8; }
        QPushButton#modeButton { border-radius: 0; padding: 5px 12px; }
        QPushButton#modeButton:checked { background: %4; color: white; border-color: %4; }
        QFrame#card { background: %2; border: 1px solid %1; border-radius: 8px; }
        QFrame#headerBar { background: %3; border-bottom: 1px solid %1; }
        QLabel#muted { color: %9; }
        QLabel#title { font-size: 15pt; font-weight: 700; }
        QLabel#bigName { font-size: 14pt; font-weight: 700; }
        QLabel#chip { border-radius: 9px; padding: 2px 9px; font-weight: 600; }
        QCheckBox::indicator, QTableView::indicator { width: 14px; height: 14px; border: 1px solid %10; border-radius: 4px; background: %2; }
        QCheckBox::indicator:checked, QTableView::indicator:checked { background: %4; border-color: %4; }
        QGroupBox { font-weight: 600; border: 1px solid %1; border-radius: 8px; margin-top: 14px; padding: 12px 8px 8px 8px; }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
    )")
                            .arg(border, card, header, accent().name(), allow().name(),
                                 allow().lighter(115).name(), deny().name(), deny().lighter(115).name(),
                                 muted().name(), muted().name()));
}

QPixmap shieldPixmap(Shield s, int size) {
    const qreal dpr = qApp ? qApp->devicePixelRatio() : 1.0;
    QPixmap pm(QSize(size, size) * dpr);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    QColor c;
    switch (s) {
        case Shield::Ok: c = allow(); break;
        case Shield::Warn: c = warn(); break;
        case Shield::Danger: c = deny(); break;
        case Shield::Off: c = muted(); break;
    }
    const qreal w = size, h = size;
    QPainterPath path;
    path.moveTo(w * 0.5, h * 0.06);
    path.cubicTo(w * 0.66, h * 0.16, w * 0.80, h * 0.18, w * 0.90, h * 0.18);
    path.cubicTo(w * 0.90, h * 0.55, w * 0.78, h * 0.80, w * 0.5, h * 0.95);
    path.cubicTo(w * 0.22, h * 0.80, w * 0.10, h * 0.55, w * 0.10, h * 0.18);
    path.cubicTo(w * 0.20, h * 0.18, w * 0.34, h * 0.16, w * 0.5, h * 0.06);
    QLinearGradient g(0, 0, 0, h);
    g.setColorAt(0, c.lighter(125));
    g.setColorAt(1, c.darker(115));
    p.fillPath(path, g);
    // Inner mark: a "V" for Varta, or a slash when off.
    QPen pen(Qt::white, qMax(1.5, size * 0.09), Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
    p.setPen(pen);
    if (s == Shield::Off) {
        p.drawLine(QPointF(w * 0.32, h * 0.66), QPointF(w * 0.68, h * 0.34));
    } else if (s == Shield::Danger) {
        p.drawLine(QPointF(w * 0.5, h * 0.28), QPointF(w * 0.5, h * 0.56));
        p.drawPoint(QPointF(w * 0.5, h * 0.72));
    } else {
        QPainterPath v;
        v.moveTo(w * 0.32, h * 0.36);
        v.lineTo(w * 0.5, h * 0.70);
        v.lineTo(w * 0.68, h * 0.36);
        p.drawPath(v);
    }
    return pm;
}

QIcon shieldIcon(Shield s) {
    QIcon icon;
    for (int sz : {16, 22, 24, 32, 48, 64, 128}) icon.addPixmap(shieldPixmap(s, sz));
    return icon;
}

QPixmap appPixmap(const QString& name, int size, const QString& exe) {
#ifdef Q_OS_WIN
    if (!exe.isEmpty() && QFileInfo::exists(exe)) {
        static QFileIconProvider provider;
        const QIcon icon = provider.icon(QFileInfo(exe));
        if (!icon.isNull()) return icon.pixmap(size, size);
    }
#else
    Q_UNUSED(exe);
#endif
    QIcon themed;
    if (!name.isEmpty()) {
        themed = QIcon::fromTheme(name);
        if (themed.isNull()) themed = QIcon::fromTheme(name.section('-', 0, 0));
    }
    if (!themed.isNull()) return themed.pixmap(size, size);

    const qreal dpr = qApp ? qApp->devicePixelRatio() : 1.0;
    QPixmap pm(QSize(size, size) * dpr);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    const uint hash = qHash(name);
    const QColor bg = QColor::fromHsl(int(hash % 360), 120, g_dark ? 95 : 120);
    p.setBrush(bg);
    p.setPen(Qt::NoPen);
    p.drawRoundedRect(QRectF(0, 0, size, size), size * 0.22, size * 0.22);
    p.setPen(Qt::white);
    QFont f = p.font();
    f.setBold(true);
    f.setPixelSize(int(size * 0.5));
    p.setFont(f);
    p.drawText(QRectF(0, 0, size, size), Qt::AlignCenter, name.isEmpty() ? "?" : name.left(1).toUpper());
    return pm;
}

QString flag(const QString& cc) {
    if (cc.size() != 2) return {};
    QString out;
    for (QChar ch : cc.toUpper()) {
        const char32_t cp = 0x1F1E6 + (ch.unicode() - 'A');
        out += QString::fromUcs4(&cp, 1);
    }
    return out;
}

QString countryName(const QString& cc) {
    if (cc.size() != 2) return {};
    const QLocale::Territory t = QLocale::codeToTerritory(cc);
    if (t == QLocale::AnyTerritory) return cc;
    return QLocale::territoryToString(t);
}

QString portName(int port, const QString& proto) {
    switch (port) {
        case 20: case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: case 587: return "smtp";
        case 53: return "dns";
        case 67: case 68: return "dhcp";
        case 80: return "http";
        case 110: return "pop3";
        case 123: return "ntp";
        case 143: return "imap";
        case 443: return proto == "udp" ? "quic" : "https";
        case 445: return "smb";
        case 465: return "smtps";
        case 853: return "dns-over-tls";
        case 993: return "imaps";
        case 995: return "pop3s";
        case 1194: return "openvpn";
        case 1900: return "ssdp";
        case 3389: return "rdp";
        case 3478: case 19302: return "stun";
        case 5222: case 5223: return "xmpp";
        case 5353: return "mdns";
        case 8080: return "http-alt";
        case 27015: case 27036: return "steam";
        case 51820: return "wireguard";
        default: return {};
    }
}

QString timeOfDay(qint64 ms) {
    return QDateTime::fromMSecsSinceEpoch(ms).toString("HH:mm:ss");
}

QString destination(const QJsonObject& c) {
    const QString host = c.value("host").toString();
    if (!host.isEmpty()) return host;
    const QString special = c.value("special").toString();
    const QString ip = c.value("remote").toString();
    return special.isEmpty() ? ip : ip + " (" + special + ")";
}

QString programName(const QJsonObject& c) {
    QString n = c.value("name").toString();
    if (n.isEmpty()) n = QFileInfo(c.value("exe").toString()).fileName();
    if (n.isEmpty()) n = QObject::tr("unknown program");
    return n;
}

}  // namespace style
