// Varta - cross-platform tracking & telemetry blocker.
// Entry point: command line parsing and dispatch.
#include <iostream>
#include <string>
#include <vector>

#include "app.hpp"
#include "blocklists.hpp"
#include "net.hpp"
#include "util.hpp"

using namespace varta;

static const char* kVersion = "0.1.0";

static void usage() {
    std::cout <<
R"(Varta )" << kVersion << R"( - cross-platform tracking & telemetry blocker

Usage: varta [options] <command> [args]

Everyday commands:
  menu                      interactive settings menu (easiest way to start)
  apply                     apply the current configuration
  disable                   remove every rule Varta added (hosts + firewall)
  status [-v]               show what is active (-v: full firewall listing)

Configuration:
  list [category]           show categories, or the domains in one category
  category <id|all> on|off  enable/disable a blocking category
  preset basic|strict|paranoid
  set <key> on|off          e.g. set security.block_ping on  (see `varta keys`)
  keys                      list all settings
  allow <domain>            never block this domain (and its subdomains)
  unallow <domain>
  block <domain|ip|cidr>    block an extra domain or IP range
  unblock <domain|ip|cidr>
  open-port <port[/tcp|udp]>   keep an inbound port open, e.g. 8080/tcp
  close-port <port[/tcp|udp]>
  source-add <https-url>    add an external hosts list (then `varta update`)
  source-remove <https-url>
  update                    download external lists
  config                    print the configuration file
  preview [linux|macos|windows]  print generated rules for any OS
  autostart on|off          re-apply firewall rules at boot (Linux/macOS)

Options:
  --dry-run        show what would happen, change nothing
  --home DIR       use DIR for config/state instead of the system location
  --hosts FILE     edit FILE instead of the system hosts file (testing)
  --no-firewall    skip the firewall backend for this run
  --no-hosts       skip the hosts backend for this run
  --quiet          less output
  -h, --help       this help
  --version
)";
}

static bool save_and_hint(App& app) {
    if (!app.save()) return false;
    if (!app.opt.quiet) ui::info(ui::dim("Saved. Run `varta apply` to activate."));
    return true;
}

static bool remove_item(std::vector<std::string>& v, const std::string& item) {
    for (auto it = v.begin(); it != v.end(); ++it) {
        if (*it == item) {
            v.erase(it);
            return true;
        }
    }
    return false;
}

static void print_categories(const App& app) {
    for (const auto& c : builtin_categories()) {
        const auto it = app.cfg.categories.find(c.id);
        const bool on = it != app.cfg.categories.end() && it->second;
        std::cout << (on ? ui::green(" on  ") : ui::dim(" off ")) << ui::bold(c.id) << " - " << c.title
                  << ui::dim(" (" + std::to_string(c.domains.size()) + ")") << "\n";
        if (!c.note.empty()) std::cout << "      " << ui::yellow(c.note) << "\n";
    }
}

int main(int argc, char** argv) {
    init_console();
    ui::init();

    std::vector<std::string> args;
    Options opt;
    std::string home, hosts;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto need_value = [&](std::string& dst) {
            if (i + 1 >= argc) {
                ui::error(a + " needs a value");
                std::exit(2);
            }
            dst = argv[++i];
        };
        if (a == "--dry-run") opt.dry_run = true;
        else if (a == "--quiet") opt.quiet = true;
        else if (a == "--no-firewall") opt.no_firewall = true;
        else if (a == "--no-hosts") opt.no_hosts = true;
        else if (a == "--home") need_value(home);
        else if (a == "--hosts") need_value(hosts);
        else if (a == "-h" || a == "--help" || a == "help") { usage(); return 0; }
        else if (a == "--version" || a == "version") { std::cout << "varta " << kVersion << "\n"; return 0; }
        else args.push_back(a);
    }

    App app;
    const Paths def = default_paths();
    app.paths = paths_for_home(home.empty() ? def.home : home, hosts.empty() ? def.hosts : hosts);
    opt.custom_hosts = !hosts.empty();
    app.opt = opt;
    if (!app.load()) return 1;

    if (args.empty()) {
        usage();
        return 0;
    }
    const std::string cmd = args[0];
    auto arg = [&](size_t i) { return i < args.size() ? args[i] : std::string(); };
    auto need_args = [&](size_t n) {
        if (args.size() < n + 1) {
            ui::error("'" + cmd + "' needs " + std::to_string(n) + " argument(s); see `varta --help`");
            return false;
        }
        return true;
    };

    if (cmd == "menu") return run_menu(app);
    if (cmd == "apply") return app.apply();
    if (cmd == "disable" || cmd == "off") return app.disable();
    if (cmd == "status") return app.status(arg(1) == "-v" || arg(1) == "--verbose");
    if (cmd == "update") return app.update();
    if (cmd == "config") {
        std::cout << serialize_config(app.cfg);
        return 0;
    }

    if (cmd == "preview") {
        Os os = current_os();
        if (!arg(1).empty() && !parse_os(arg(1), os)) {
            ui::error("unknown OS '" + arg(1) + "' (linux, macos, windows)");
            return 2;
        }
        return app.preview(os);
    }

    if (cmd == "list") {
        if (arg(1).empty()) {
            print_categories(app);
            return 0;
        }
        const Category* c = find_category(arg(1));
        if (!c) {
            ui::error("unknown category '" + arg(1) + "'");
            return 2;
        }
        std::cout << ui::bold(c->title) << "\n";
        for (const auto& d : c->domains) std::cout << "  " << d << "\n";
        return 0;
    }

    if (cmd == "keys") {
        std::cout << ui::bold("General") << "\n";
        for (const auto& o : general_options()) {
            bool v = false;
            get_option(app.cfg, o.key, v);
            std::cout << "  " << o.key << " = " << (v ? "on" : "off") << "\n      " << ui::dim(o.description) << "\n";
        }
        std::cout << ui::bold("Security") << "\n";
        for (const auto& o : security_options()) {
            bool v = false;
            get_option(app.cfg, o.key, v);
            std::cout << "  " << o.key << " = " << (v ? "on" : "off") << "\n      " << ui::dim(o.description) << "\n";
        }
        std::cout << ui::dim("Categories: categories.<id> (see `varta list`)") << "\n";
        return 0;
    }

    if (cmd == "category") {
        if (!need_args(2)) return 2;
        const auto b = parse_bool(arg(2));
        if (!b) {
            ui::error("expected on/off");
            return 2;
        }
        if (arg(1) == "all") {
            for (const auto& c : builtin_categories()) app.cfg.categories[c.id] = *b;
        } else {
            std::string err;
            if (!set_option(app.cfg, "categories." + arg(1), arg(2), err)) {
                ui::error(err);
                return 2;
            }
        }
        return save_and_hint(app) ? 0 : 1;
    }

    if (cmd == "preset") {
        if (!need_args(1)) return 2;
        if (!apply_preset(app.cfg, arg(1))) {
            ui::error("unknown preset (basic, strict, paranoid)");
            return 2;
        }
        return save_and_hint(app) ? 0 : 1;
    }

    if (cmd == "set") {
        if (!need_args(2)) return 2;
        std::string key = arg(1);
        if (key.find('.') == std::string::npos) key = "security." + key;  // convenience
        std::string err;
        if (!set_option(app.cfg, key, arg(2), err)) {
            ui::error(err);
            return 2;
        }
        return save_and_hint(app) ? 0 : 1;
    }

    if (cmd == "allow" || cmd == "unallow") {
        if (!need_args(1)) return 2;
        const std::string d = to_lower(arg(1));
        if (!is_valid_domain(d)) {
            ui::error("invalid domain '" + d + "'");
            return 2;
        }
        if (cmd == "allow") {
            remove_item(app.cfg.allow_domains, d);
            app.cfg.allow_domains.push_back(d);
        } else if (!remove_item(app.cfg.allow_domains, d)) {
            ui::warn(d + " was not in the allow list");
        }
        return save_and_hint(app) ? 0 : 1;
    }

    if (cmd == "block" || cmd == "unblock") {
        if (!need_args(1)) return 2;
        const std::string v = to_lower(arg(1));
        const bool is_ip = ip_family(v) != IpFamily::None;
        if (!is_ip && !is_valid_domain(v)) {
            ui::error("not a domain, IP or CIDR: '" + v + "'");
            return 2;
        }
        auto& list = is_ip ? app.cfg.block_ips : app.cfg.block_domains;
        if (cmd == "block") {
            remove_item(list, v);
            list.push_back(v);
        } else if (!remove_item(list, v)) {
            ui::warn(v + " was not in your block list (built-in categories are toggled with `category`)");
        }
        return save_and_hint(app) ? 0 : 1;
    }

    if (cmd == "open-port" || cmd == "close-port") {
        if (!need_args(1)) return 2;
        PortRule r;
        if (!parse_port_rule(arg(1), r)) {
            ui::error("invalid port, use 8080, 8080/tcp or 53/udp");
            return 2;
        }
        auto& v = app.cfg.sec.allow_in;
        for (auto it = v.begin(); it != v.end();) {
            if (it->port == r.port && it->proto == r.proto) it = v.erase(it);
            else ++it;
        }
        if (cmd == "open-port") v.push_back(r);
        return save_and_hint(app) ? 0 : 1;
    }

    if (cmd == "source-add" || cmd == "source-remove") {
        if (!need_args(1)) return 2;
        if (!starts_with(arg(1), "https://")) {
            ui::error("only https:// URLs are accepted");
            return 2;
        }
        remove_item(app.cfg.sources, arg(1));
        if (cmd == "source-add") app.cfg.sources.push_back(arg(1));
        if (!app.save()) return 1;
        ui::info(ui::dim("Saved. Run `varta update` then `varta apply`."));
        return 0;
    }

    if (cmd == "autostart") {
        if (!need_args(1)) return 2;
        const auto b = parse_bool(arg(1));
        if (!b) {
            ui::error("expected on/off");
            return 2;
        }
        if (!is_admin()) {
            ui::error(std::string("administrator rights are required - ") + admin_hint() + ".");
            return 1;
        }
        std::string msg;
        const bool okay = *b ? autostart_enable(msg) : autostart_disable(msg);
        okay ? ui::ok(msg) : ui::error(msg);
        return okay ? 0 : 1;
    }

    ui::error("unknown command '" + cmd + "'");
    usage();
    return 2;
}
