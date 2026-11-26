#include "app.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <iostream>

#include "hosts.hpp"
#include "rules.hpp"
#include "util.hpp"

#ifdef _WIN32
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace varta {

// ------------------------------------------------------------------------------------ ui

namespace ui {
static bool g_color = false;
void init() { g_color = isatty(fileno(stdout)) != 0; }
static std::string paint(const char* code, const std::string& s) {
    return g_color ? std::string("\033[") + code + "m" + s + "\033[0m" : s;
}
std::string green(const std::string& s) { return paint("32", s); }
std::string red(const std::string& s) { return paint("31", s); }
std::string yellow(const std::string& s) { return paint("33", s); }
std::string bold(const std::string& s) { return paint("1", s); }
std::string dim(const std::string& s) { return paint("2", s); }
void info(const std::string& s) { std::cout << s << "\n"; }
void ok(const std::string& s) { std::cout << green("[ok] ") << s << "\n"; }
void warn(const std::string& s) { std::cout << yellow("[!] ") << s << "\n"; }
void error(const std::string& s) { std::cerr << red("[error] ") << s << "\n"; }
}  // namespace ui

// ----------------------------------------------------------------------------------- App

bool App::load() {
    std::vector<std::string> warnings;
    std::error_code ec;
    if (!fs::exists(paths.config, ec)) {
        cfg = default_config();
        return true;  // saved on first apply / menu save
    }
    if (!load_config(paths.config, cfg, warnings)) {
        ui::error("cannot read " + paths.config);
        return false;
    }
    for (const auto& w : warnings) ui::warn(paths.config + " " + w);
    return true;
}

bool App::save() {
    if (opt.dry_run) return true;
    std::string err;
    if (!save_config(paths.config, cfg, err)) {
        ui::error("cannot save config: " + err + " (" + admin_hint() + ")");
        return false;
    }
    return true;
}

std::string App::diagtrack_marker() const {
    return (fs::path(paths.home) / "diagtrack.applied").string();
}

bool App::require_admin() {
    if (opt.dry_run || is_admin()) return true;
    const bool touches_system = use_firewall() || (use_hosts() && !opt.custom_hosts);
    if (!touches_system) return true;
    ui::error(std::string("administrator rights are required - ") + admin_hint() + ".");
    ui::info("Tip: `varta --dry-run apply` shows what would change without touching anything.");
    return false;
}

int App::apply() {
    if (!require_admin()) return 1;
    const bool resolve = cfg.resolve_domains && use_firewall();

    // Resolving must see real DNS answers, not our own 0.0.0.0 entries.
    if (resolve && !opt.dry_run && use_hosts()) {
        std::string err;
        hosts_remove(paths.hosts, err);
        flush_dns_cache();
        if (!opt.quiet) ui::info("Resolving blocked domains to IPs (this can take a while)...");
    }

    const RuleSet rs = build_ruleset(cfg, paths.lists_dir, resolve);

    if (opt.dry_run) {
        ui::info(ui::bold("Dry run - nothing will be changed."));
        ui::info("Domains to block via hosts: " + std::to_string(rs.domains.size()) +
                 (use_hosts() ? "" : " (hosts backend disabled)"));
        ui::info("IPs to block via firewall: " + std::to_string(rs.ipv4.size()) + " IPv4, " +
                 std::to_string(rs.ipv6.size()) + " IPv6");
        if (use_firewall()) {
            ui::info("\n" + ui::bold(std::string("Firewall script for ") + os_name(current_os()) + ":"));
            std::cout << generate_firewall(current_os(), rs, cfg.win_disable_diagtrack);
        }
        return 0;
    }

    std::error_code ec;
    fs::create_directories(paths.home, ec);
    fs::create_directories(paths.work_dir, ec);
    if (!fs::exists(paths.config, ec) && !save()) return 1;

    int rc = 0;
    if (use_hosts()) {
        std::string err;
        if (hosts_apply(paths.hosts, opt.custom_hosts ? "" : paths.backup, rs.domains,
                        cfg.hosts_ipv6, err)) {
            if (!opt.quiet) ui::ok("hosts: " + std::to_string(rs.domains.size()) + " domains blocked (" + paths.hosts + ")");
            if (!opt.custom_hosts) flush_dns_cache();
        } else {
            ui::error("hosts: " + err);
            if (current_os() == Os::Windows)
                ui::warn("Windows Defender may block edits that touch Microsoft domains. See README.");
            rc = 1;
        }
    } else if (!opt.no_hosts) {
        std::string err;
        hosts_remove(paths.hosts, err);  // backend switched off in config: clean up
    }

    if (use_firewall()) {
        std::string err;
        if (firewall_apply(rs, paths.work_dir, cfg.win_disable_diagtrack, err)) {
            if (!opt.quiet)
                ui::ok(std::string("firewall: rules applied (") + os_name(current_os()) + ", " +
                       std::to_string(rs.ipv4.size() + rs.ipv6.size()) + " IPs blocked)");
            if (current_os() == Os::Windows && cfg.win_disable_diagtrack) {
                std::string e2;
                write_file_atomic(diagtrack_marker(), "1\n", e2);
            }
        } else {
            ui::error("firewall: " + err);
            rc = 1;
        }
    } else if (!opt.no_firewall) {
        std::string err;
        firewall_remove(paths.work_dir, false, err);  // backend switched off in config
    }
    return rc;
}

int App::disable() {
    if (!require_admin()) return 1;
    if (opt.dry_run) {
        ui::info("Dry run: would remove the Varta block from " + paths.hosts +
                 " and delete all Varta firewall rules.");
        return 0;
    }
    int rc = 0;
    std::string err;
    if (!opt.no_hosts) {
        if (hosts_remove(paths.hosts, err)) {
            if (!opt.quiet) ui::ok("hosts: Varta block removed");
            if (!opt.custom_hosts) flush_dns_cache();
        } else {
            ui::error("hosts: " + err);
            rc = 1;
        }
    }
    if (!opt.no_firewall) {
        std::error_code ec;
        const bool restore = fs::exists(diagtrack_marker(), ec);
        if (firewall_remove(paths.work_dir, restore, err)) {
            if (!opt.quiet) ui::ok("firewall: Varta rules removed");
            if (restore) fs::remove(diagtrack_marker(), ec);
        } else {
            ui::error("firewall: " + err);
            rc = 1;
        }
    }
    return rc;
}

int App::status(bool verbose) {
    ui::info(ui::bold("Varta status") + ui::dim("  (" + std::string(os_name(current_os())) + ", config: " + paths.config + ")"));

    const auto hosts = read_file(paths.hosts);
    const size_t n = hosts ? count_hosts_domains(*hosts) : 0;
    if (!hosts)
        ui::warn("hosts: cannot read " + paths.hosts);
    else if (n)
        ui::info("  hosts     " + ui::green("ACTIVE") + "  " + std::to_string(n) + " domains blocked");
    else
        ui::info("  hosts     " + ui::yellow("inactive"));

    if (opt.no_firewall) {
        ui::info("  firewall  " + ui::dim("skipped (--no-firewall)"));
    } else if (!is_admin() && current_os() != Os::Windows) {
        ui::info("  firewall  " + ui::dim(std::string("unknown - ") + admin_hint() + " to query it"));
    } else {
        const auto st = firewall_status(verbose);
        ui::info("  firewall  " + (st.active ? ui::green("ACTIVE") : ui::yellow("inactive")) + "  " + st.details);
    }

    int cats_on = 0;
    for (const auto& [id, on] : cfg.categories) cats_on += on ? 1 : 0;
    const auto& s = cfg.sec;
    ui::info("  categories enabled: " + std::to_string(cats_on) + "/" + std::to_string(cfg.categories.size()));
    ui::info(std::string("  inbound: ") + (s.default_inbound_deny ? "deny by default" : "allow by default") +
             (s.allow_ssh ? ", SSH open" : "") + (s.block_ping ? ", ping blocked" : "") +
             (s.block_public_doh ? ", public DoH blocked" : ""));
    return 0;
}

static bool safe_url(const std::string& u) {
    if (!starts_with(u, "https://")) return false;
    for (char c : u) {
        const bool okc = std::isalnum(static_cast<unsigned char>(c)) ||
                         std::string(":/._~%?&=+-#").find(c) != std::string::npos;
        if (!okc) return false;
    }
    return true;
}

int App::update() {
    if (cfg.sources.empty()) {
        ui::warn("No [sources] in " + paths.config + " - nothing to download.");
        ui::info("Example: varta source-add https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts");
        return 0;
    }
    if (!opt.dry_run && !is_admin() && !opt.custom_hosts) {
        ui::error(std::string("administrator rights are required - ") + admin_hint() + ".");
        return 1;
    }
    std::error_code ec;
    fs::create_directories(paths.lists_dir, ec);
    int rc = 0;
    for (size_t i = 0; i < cfg.sources.size(); ++i) {
        const std::string& url = cfg.sources[i];
        if (!safe_url(url)) {
            ui::error("skipping unsafe or non-https URL: " + url);
            rc = 1;
            continue;
        }
        const std::string dst = (fs::path(paths.lists_dir) / ("source-" + std::to_string(i + 1) + ".txt")).string();
        const std::string tmp = dst + ".download";
        if (opt.dry_run) {
            ui::info("would download " + url + " -> " + dst);
            continue;
        }
        if (!opt.quiet) ui::info("downloading " + url);
        if (run("curl -fsSL --max-time 120 -o " + shell_quote(tmp) + " " + shell_quote(url)) != 0) {
            ui::error("download failed: " + url);
            fs::remove(tmp, ec);
            rc = 1;
            continue;
        }
        const auto text = read_file(tmp);
        const size_t count = text ? parse_domain_list(*text).size() : 0;
        if (count == 0) {
            ui::error("no domains found in " + url + " - keeping previous copy");
            fs::remove(tmp, ec);
            rc = 1;
            continue;
        }
        fs::rename(tmp, dst, ec);
        if (ec) {
            fs::copy_file(tmp, dst, fs::copy_options::overwrite_existing, ec);
            fs::remove(tmp, ec);
        }
        ui::ok(std::to_string(count) + " domains from " + url);
    }
    // Remove lists of sources that were deleted from the config.
    for (size_t i = cfg.sources.size() + 1; i < cfg.sources.size() + 50; ++i) {
        fs::remove(fs::path(paths.lists_dir) / ("source-" + std::to_string(i) + ".txt"), ec);
    }
    if (!opt.quiet && !opt.dry_run) ui::info("Run `varta apply` to activate the updated lists.");
    return rc;
}

int App::preview(Os os) {
    const RuleSet rs = build_ruleset(cfg, paths.lists_dir, false);
    std::cout << "# ---- hosts block (" << rs.domains.size() << " domains, first 20 shown) ----\n";
    std::vector<std::string> head(rs.domains.begin(),
                                  rs.domains.begin() + static_cast<long>(std::min<size_t>(20, rs.domains.size())));
    std::cout << render_hosts_section(head, cfg.hosts_ipv6);
    std::cout << "\n# ---- firewall script for " << os_name(os) << " ----\n";
    std::cout << generate_firewall(os, rs, cfg.win_disable_diagtrack);
    return 0;
}

}  // namespace varta
