// varta-gui - desktop front end for vartad.
#include <QApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QLibraryInfo>
#include <QLocale>
#include <QSettings>
#include <QTabWidget>
#include <QTimer>
#include <QTranslator>

#include "backend.hpp"
#include "mainwindow.hpp"
#include "prompt.hpp"
#include "style.hpp"

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setApplicationName("varta-gui");
    QApplication::setOrganizationName("Varta");
    QApplication::setApplicationVersion(VARTA_VERSION);
    QApplication::setQuitOnLastWindowClosed(false);  // lives in the tray

    QCommandLineParser cli;
    cli.setApplicationDescription("Varta application firewall - GUI");
    cli.addHelpOption();
    cli.addVersionOption();
    QCommandLineOption demo("demo", "Run with generated sample traffic (no daemon needed).");
#ifdef Q_OS_WIN
    // QLocalSocket maps a plain name to the named pipe \\.\pipe\vartad.
    QCommandLineOption socket("socket", "vartad pipe name.", "name", "vartad");
#elif defined(Q_OS_MACOS)
    QCommandLineOption socket("socket", "vartad socket path.", "path", "/var/run/varta/vartad.sock");
#else
    QCommandLineOption socket("socket", "vartad socket path.", "path", "/run/varta/vartad.sock");
#endif
    QCommandLineOption lang("lang", "UI language: en or uk.", "code");
    QCommandLineOption theme("theme", "system, dark or light.", "name");
    QCommandLineOption hidden("hidden", "Start in the tray (for autostart).");
    QCommandLineOption shots("screenshots", "Demo: save screenshots to DIR and exit.", "dir");
    cli.addOptions({demo, socket, lang, theme, hidden, shots});
    cli.process(app);

    QSettings settings;
    // Translations are compiled into the binary (see gui/CMakeLists.txt).
    QString language = cli.isSet(lang) ? cli.value(lang) : settings.value("language").toString();
    if (language.isEmpty()) language = QLocale::system().name().left(2);
    QTranslator translator, qtTranslator;
    if (language == "uk") {
        if (translator.load(":/i18n/varta_uk.qm")) app.installTranslator(&translator);
        if (qtTranslator.load("qtbase_uk", QLibraryInfo::path(QLibraryInfo::TranslationsPath)))
            app.installTranslator(&qtTranslator);
    }

    style::apply(cli.isSet(theme) ? cli.value(theme) : settings.value("theme", "dark").toString());

    const bool isDemo = cli.isSet(demo) || cli.isSet(shots);
    Backend* backend = nullptr;
    if (isDemo) backend = new DemoBackend(&app);
    else backend = new SocketBackend(cli.value(socket), &app);

    MainWindow w(backend);
    if (isDemo) w.setWindowTitle(w.windowTitle() + " - " + QObject::tr("demo"));
    if (!cli.isSet(hidden) || !QSystemTrayIcon::isSystemTrayAvailable()) w.show();
    if (auto* d = qobject_cast<DemoBackend*>(backend)) d->start();
    if (!isDemo) w.startUpdateCheck();

    if (cli.isSet(shots)) {
        // Render every screen to PNG - handy for the README and for checking the design.
        const QString dir = cli.value(shots);
        QDir().mkpath(dir);
        QTimer::singleShot(6000, &app, [&] {
            const char* names[] = {"connections", "programs", "rules", "settings", "about"};
            for (int i = 0; i < 5; ++i) {
                w.showTab(i);
                QApplication::processEvents();
                w.grab().save(dir + "/main-" + names[i] + ".png");
            }
            for (int k = 0; k < 3; ++k) {
                QJsonObject a = DemoBackend::sampleAsk(k);
                a["id"] = 9000 + k;
                w.prompt()->showConnection(a, k);
                QApplication::processEvents();
                w.prompt()->grab().save(dir + QString("/prompt-%1.png").arg(k + 1));
            }
            app.quit();
        });
    }
    return app.exec();
}
