// varta-gui - colours, programmatically drawn icons and small formatting helpers.
#pragma once

#include <QColor>
#include <QIcon>
#include <QJsonObject>
#include <QPixmap>
#include <QString>

namespace style {

enum class Shield { Ok, Warn, Danger, Off };

QColor allow();
QColor deny();
QColor warn();
QColor accent();
QColor muted();

// Applies the Fusion style, a dark or light palette and the app-wide stylesheet.
// theme: "system", "dark", "light"
void apply(const QString& theme);
bool isDark();

QIcon shieldIcon(Shield s);
QPixmap shieldPixmap(Shield s, int size);
// Windows: the icon embedded in the .exe. Linux: theme icon (firefox, code...).
// Fallback: a coloured letter avatar.
QPixmap appPixmap(const QString& name, int size, const QString& exe = QString());

QString flag(const QString& countryCode);         // 🇩🇰
QString countryName(const QString& countryCode);  // Denmark
QString portName(int port, const QString& proto); // https, dns, ssh...
QString timeOfDay(qint64 ms);

// "pypi.org" / "151.101.64.223" / "Local network" for a connection object.
QString destination(const QJsonObject& c);
QString programName(const QJsonObject& c);

}  // namespace style
