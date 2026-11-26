// Varta - high level operations shared by the CLI and the interactive menu.
#pragma once

#include <string>

#include "config.hpp"
#include "firewall.hpp"
#include "platform.hpp"

namespace varta {

struct Options {
    bool dry_run = false;
    bool quiet = false;
    bool no_firewall = false;
    bool no_hosts = false;
    bool custom_hosts = false;  // --hosts given (testing on a copy of the hosts file)
};

// Terminal colours (disabled automatically when stdout is not a terminal).
namespace ui {
void init();
std::string green(const std::string& s);
std::string red(const std::string& s);
std::string yellow(const std::string& s);
std::string bold(const std::string& s);
std::string dim(const std::string& s);
void info(const std::string& s);
void ok(const std::string& s);
void warn(const std::string& s);
void error(const std::string& s);
}  // namespace ui

class App {
public:
    Paths paths;
    Config cfg;
    Options opt;

    // Loads the config, creating a default one when missing. Returns false on hard error.
    bool load();
    bool save();

    int apply();
    int disable();
    int status(bool verbose);
    int update();
    int preview(Os os);

    bool use_hosts() const { return cfg.use_hosts && !opt.no_hosts; }
    bool use_firewall() const { return cfg.use_firewall && !opt.no_firewall; }

private:
    bool require_admin();
    std::string diagtrack_marker() const;
};

int run_menu(App& app);

}  // namespace varta
