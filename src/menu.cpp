// Varta - interactive text menu (`varta menu`).
#include <iostream>
#include <string>

#include "app.hpp"
#include "blocklists.hpp"
#include "net.hpp"
#include "util.hpp"

namespace varta {

namespace {

bool g_dirty = false;
bool g_eof = false;  // stdin closed: leave without prompting

std::string ask(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) {
        g_eof = true;
        return "q";  // EOF behaves like quit
    }
    return trim(line);
}

int to_index(const std::string& s) {
    if (s.empty() || s.size() > 3) return -1;
    for (char c : s)
        if (!std::isdigit(static_cast<unsigned char>(c))) return -1;
    return std::stoi(s);
}

std::string mark(bool on) { return on ? ui::green("[x]") : ui::dim("[ ]"); }

void header(const std::string& title) {
    std::cout << "\n" << ui::bold("=== " + title + " ===") << "\n";
}

void categories_menu(App& app) {
    for (;;) {
        header("Blocking categories");
        const auto& cats = builtin_categories();
        for (size_t i = 0; i < cats.size(); ++i) {
            const auto& c = cats[i];
            std::cout << "  " << (i + 1) << ") " << mark(app.cfg.categories[c.id]) << " "
                      << ui::bold(c.id) << " - " << c.title << "  " << ui::dim("(" + std::to_string(c.domains.size()) + " domains)") << "\n";
            if (!c.note.empty()) std::cout << "        " << ui::yellow("note: " + c.note) << "\n";
        }
        std::cout << "  a) enable all   n) disable all   b) back\n";
        const std::string in = to_lower(ask("> "));
        if (in == "b" || in == "q" || in.empty()) return;
        if (in == "a" || in == "n") {
            for (const auto& c : cats) app.cfg.categories[c.id] = in == "a";
            g_dirty = true;
            continue;
        }
        const int idx = to_index(in);
        if (idx >= 1 && idx <= static_cast<int>(cats.size())) {
            bool& v = app.cfg.categories[cats[idx - 1].id];
            v = !v;
            g_dirty = true;
        }
    }
}

void options_menu(App& app, const std::vector<OptionInfo>& opts, const std::string& title) {
    for (;;) {
        header(title);
        for (size_t i = 0; i < opts.size(); ++i) {
            bool v = false;
            get_option(app.cfg, opts[i].key, v);
            const std::string shortkey = opts[i].key.substr(opts[i].key.find('.') + 1);
            std::cout << "  " << (i + 1) << ") " << mark(v) << " " << ui::bold(shortkey) << "\n"
                      << "        " << ui::dim(opts[i].description) << "\n";
        }
        std::cout << "  b) back\n";
        const std::string in = to_lower(ask("> "));
        if (in == "b" || in == "q" || in.empty()) return;
        const int idx = to_index(in);
        if (idx >= 1 && idx <= static_cast<int>(opts.size())) {
            bool v = false;
            get_option(app.cfg, opts[idx - 1].key, v);
            std::string err;
            set_option(app.cfg, opts[idx - 1].key, v ? "off" : "on", err);
            g_dirty = true;
        }
    }
}

void ports_menu(App& app) {
    for (;;) {
        header("Open inbound ports (used when inbound is denied)");
        auto& v = app.cfg.sec.allow_in;
        if (v.empty()) std::cout << "  " << ui::dim("(none)") << "\n";
        for (size_t i = 0; i < v.size(); ++i)
            std::cout << "  " << (i + 1) << ") " << port_rule_to_string(v[i]) << "\n";
        std::cout << "  +) add (e.g. 8080/tcp, 51820/udp)   -N) remove item N   b) back\n";
        const std::string in = to_lower(ask("> "));
        if (in == "b" || in == "q" || in.empty()) return;
        if (in == "+") {
            PortRule r;
            const std::string p = ask("port: ");
            if (parse_port_rule(p, r)) {
                v.push_back(r);
                g_dirty = true;
            } else {
                ui::warn("invalid port, use 8080, 8080/tcp or 53/udp");
            }
        } else if (in.size() > 1 && in[0] == '-') {
            const int idx = to_index(in.substr(1));
            if (idx >= 1 && idx <= static_cast<int>(v.size())) {
                v.erase(v.begin() + idx - 1);
                g_dirty = true;
            }
        }
    }
}

// Generic editor for a list of strings with a validator.
template <typename Valid>
void list_menu(const std::string& title, std::vector<std::string>& v, const std::string& hint,
               Valid valid) {
    for (;;) {
        header(title);
        if (v.empty()) std::cout << "  " << ui::dim("(empty)") << "\n";
        for (size_t i = 0; i < v.size(); ++i) std::cout << "  " << (i + 1) << ") " << v[i] << "\n";
        std::cout << "  +) add   -N) remove item N   b) back\n";
        const std::string in = ask("> ");
        const std::string l = to_lower(in);
        if (l == "b" || l == "q" || l.empty()) return;
        if (l == "+") {
            std::string item = ask(hint);
            if (!starts_with(item, "http")) item = to_lower(item);
            if (valid(item)) {
                bool dup = false;
                for (const auto& x : v) dup |= x == item;
                if (!dup) v.push_back(item);
                g_dirty = true;
            } else {
                ui::warn("invalid value: " + item);
            }
        } else if (l.size() > 1 && l[0] == '-') {
            const int idx = to_index(l.substr(1));
            if (idx >= 1 && idx <= static_cast<int>(v.size())) {
                v.erase(v.begin() + idx - 1);
                g_dirty = true;
            }
        }
    }
}

void custom_menu(App& app) {
    for (;;) {
        header("Custom lists");
        std::cout << "  1) Allowed domains (never blocked)   " << ui::dim(std::to_string(app.cfg.allow_domains.size()) + " items") << "\n"
                  << "  2) Extra blocked domains             " << ui::dim(std::to_string(app.cfg.block_domains.size()) + " items") << "\n"
                  << "  3) Blocked IPs / CIDR ranges         " << ui::dim(std::to_string(app.cfg.block_ips.size()) + " items") << "\n"
                  << "  4) Open inbound ports                " << ui::dim(std::to_string(app.cfg.sec.allow_in.size()) + " items") << "\n"
                  << "  5) External list URLs (varta update) " << ui::dim(std::to_string(app.cfg.sources.size()) + " items") << "\n"
                  << "  b) back\n";
        const std::string in = to_lower(ask("> "));
        if (in == "1") list_menu("Allowed domains", app.cfg.allow_domains, "domain: ", is_valid_domain);
        else if (in == "2") list_menu("Blocked domains", app.cfg.block_domains, "domain: ", is_valid_domain);
        else if (in == "3")
            list_menu("Blocked IPs", app.cfg.block_ips, "IP or CIDR (1.2.3.4, 10.0.0.0/8, 2001:db8::/32): ",
                      [](const std::string& s) { return ip_family(s) != IpFamily::None; });
        else if (in == "4") ports_menu(app);
        else if (in == "5")
            list_menu("External lists", app.cfg.sources, "https URL: ",
                      [](const std::string& s) { return starts_with(s, "https://"); });
        else return;
    }
}

void preset_menu(App& app) {
    header("Security presets");
    std::cout << "  1) basic    - inbound allowed, risky services (SMB, RDP, Telnet...) blocked\n"
                 "  2) strict   - inbound denied by default + everything in basic  (recommended)\n"
                 "  3) paranoid - strict + no ping, no mDNS, public DoH blocked, all categories, logging\n"
                 "  b) back\n"
              << ui::dim("  Your own open ports and the SSH setting are kept.") << "\n";
    const std::string in = ask("> ");
    const char* names[] = {"basic", "strict", "paranoid"};
    const int idx = to_index(in);
    if (idx >= 1 && idx <= 3) {
        apply_preset(app.cfg, names[idx - 1]);
        g_dirty = true;
        ui::ok(std::string("preset '") + names[idx - 1] + "' selected - choose 'Apply' to activate it");
    }
}

}  // namespace

int run_menu(App& app) {
    for (;;) {
        std::cout << "\n";
        app.status(false);
        header("Varta menu");
        std::cout << "  1) Blocking categories\n"
                     "  2) Security settings\n"
                     "  3) Security presets (basic / strict / paranoid)\n"
                     "  4) Custom domains, IPs, ports, external lists\n"
                     "  5) General settings (backends)\n"
                     "  6) " << ui::green("Save & apply now") << "\n"
                     "  7) Preview generated rules\n"
                     "  8) Download external lists (update)\n"
                     "  9) " << ui::red("Disable Varta (remove all rules)") << "\n"
                     "  q) quit" << (g_dirty ? ui::yellow("   * unsaved changes") : "") << "\n";
        const std::string in = to_lower(ask("> "));
        if (in == "1") categories_menu(app);
        else if (in == "2") options_menu(app, security_options(), "Security settings");
        else if (in == "3") preset_menu(app);
        else if (in == "4") custom_menu(app);
        else if (in == "5") options_menu(app, general_options(), "General settings");
        else if (in == "6") {
            if (app.save()) {
                g_dirty = false;
                app.apply();
            }
        } else if (in == "7") {
            app.preview(current_os());
        } else if (in == "8") {
            if (app.save()) g_dirty = false;
            app.update();
        } else if (in == "9") {
            if (to_lower(ask("Remove all Varta rules? [y/N] ")) == "y") app.disable();
        } else if (in == "q") {
            if (g_dirty && !g_eof && to_lower(ask("Save changes before quitting? [Y/n] ")) != "n") app.save();
            return 0;
        }
    }
}

}  // namespace varta
