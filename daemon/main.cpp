// vartad - Varta interactive application firewall daemon (Linux and Windows).
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

#include "engine.hpp"
#include "ipdb.hpp"

#ifdef _WIN32
#include "windows_daemon.hpp"
#else
#include "linux_daemon.hpp"
#endif

namespace fs = std::filesystem;
using namespace vartad;

static const char* kVersion = "0.3.0";

static void usage() {
    std::cout << "vartad " << kVersion << " - Varta interactive application firewall\n\n"
                 "Usage: vartad [options]\n"
#ifdef _WIN32
                 "  --install-service   install and start the Windows service (as Administrator)\n"
                 "  --uninstall-service stop and remove the Windows service\n"
                 "  --console           run in this console instead of as a service (Ctrl+C stops)\n"
                 "  --service           (used by the Service Control Manager)\n"
#else
                 "  (no options)        run the daemon (as root; normally started by systemd)\n"
                 "  --print-nft         print the nftables rules vartad installs\n"
#endif
                 "  --update-db         download the offline IP owner/country database\n"
                 "  --lookup <ip>       show what the IP database knows about an address\n"
                 "  --config-dir DIR    where settings and rules live\n"
                 "  --data-dir DIR      where the IP database lives\n"
                 "  -h, --help\n";
}

static std::string quote(const std::string& s) {
#ifdef _WIN32
    return "\"" + s + "\"";
#else
    return "'" + s + "'";
#endif
}

static int update_db(const Paths& p) {
    std::error_code ec;
    fs::create_directories(p.ipdb(), ec);
    int rc = 0;
    for (const auto& [url, file] : IpDb::download_files()) {
        const std::string dst = (fs::path(p.ipdb()) / file).string();
        const std::string tmp = dst + ".download";
        std::cout << "downloading " << url << std::endl;
        // curl ships with Windows 10 1803+ and every Linux desktop.
        const std::string cmd = "curl -fSL --max-time 300 --progress-bar -o " + quote(tmp) + " " + quote(url);
        if (std::system(cmd.c_str()) != 0) {
            std::cerr << "  failed\n";
            fs::remove(tmp, ec);
            rc = 1;
            continue;
        }
        fs::rename(tmp, dst, ec);
        if (ec) {
            fs::copy_file(tmp, dst, fs::copy_options::overwrite_existing, ec);
            fs::remove(tmp, ec);
        }
    }
    IpDb db;
    std::cout << "IP database now has " << db.load(p.ipdb()) << " ranges.\n" << IpDb::attribution() << "\n";
#ifdef _WIN32
    std::cout << "Restart the service to load it:  sc stop vartad && sc start vartad\n";
#else
    // Ask a running daemon to reload.
    if (std::system("pkill -HUP -x vartad 2>/dev/null") == 0) std::cout << "vartad reloaded.\n";
#endif
    return rc;
}

static int lookup(const Paths& paths, const std::string& addr) {
    IpAddr ip;
    if (!IpAddr::parse(addr, ip)) {
        std::cerr << "not an IP address\n";
        return 2;
    }
    const std::string special = special_range(ip);
    if (!special.empty()) {
        std::cout << addr << ": " << special << "\n";
        return 0;
    }
    IpDb db;
    if (!db.load(paths.ipdb())) {
        std::cerr << "IP database not found in " << paths.ipdb() << " - run vartad --update-db\n";
        return 1;
    }
    const IpInfo info = db.lookup(ip);
    std::cout << addr << ": AS" << info.asn << " " << (info.org.empty() ? "?" : info.org) << ", country "
              << (info.country.empty() ? "?" : info.country) << "\n";
    return 0;
}

int main(int argc, char** argv) {
    Paths paths;
    std::string lookup_ip;
    bool do_update = false, print_nft = false;
    bool install_svc = false, uninstall_svc = false, console = false, service = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto value = [&](std::string& dst) {
            if (i + 1 >= argc) {
                std::cerr << a << " needs a value\n";
                std::exit(2);
            }
            dst = argv[++i];
        };
        if (a == "-h" || a == "--help") { usage(); return 0; }
        else if (a == "--version") { std::cout << "vartad " << kVersion << "\n"; return 0; }
        else if (a == "--update-db") do_update = true;
        else if (a == "--print-nft") print_nft = true;
        else if (a == "--lookup") value(lookup_ip);
        else if (a == "--config-dir") value(paths.config_dir);
        else if (a == "--data-dir") value(paths.data_dir);
        else if (a == "--run-dir") value(paths.run_dir);
        else if (a == "--install-service") install_svc = true;
        else if (a == "--uninstall-service") uninstall_svc = true;
        else if (a == "--console") console = true;
        else if (a == "--service") service = true;
        else if (a == "--foreground") {}
        else { std::cerr << "unknown option " << a << "\n"; usage(); return 2; }
    }

    if (do_update) return update_db(paths);
    if (!lookup_ip.empty()) return lookup(paths, lookup_ip);

#ifdef _WIN32
    (void)print_nft;
    if (install_svc) return WindowsDaemon::install_service();
    if (uninstall_svc) return WindowsDaemon::uninstall_service();
    if (service) return WindowsDaemon::run_as_service(paths);
    (void)console;  // console is the default when started by hand
    WindowsDaemon d(paths);
    return d.run_console();
#else
    (void)install_svc; (void)uninstall_svc; (void)console; (void)service;
    if (print_nft) {
        Settings s;
        s.load(paths.settings());
        std::cout << LinuxDaemon::nft_script(s);
        return 0;
    }
    LinuxDaemon d(paths);
    return d.run();
#endif
}
