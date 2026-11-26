// Varta - small string / file / process helpers shared by all modules.
#pragma once

#include <optional>
#include <string>
#include <vector>

namespace varta {

std::string trim(const std::string& s);
std::string to_lower(std::string s);
bool starts_with(const std::string& s, const std::string& prefix);
bool ends_with(const std::string& s, const std::string& suffix);
std::vector<std::string> split(const std::string& s, char sep);
std::vector<std::string> split_ws(const std::string& s);
std::string join(const std::vector<std::string>& v, const std::string& sep);

// Parses on/off/true/false/yes/no/1/0. Returns nullopt for anything else.
std::optional<bool> parse_bool(const std::string& s);

std::optional<std::string> read_file(const std::string& path);
// Writes via a temporary file + rename so a crash never leaves a half-written file.
bool write_file_atomic(const std::string& path, const std::string& content, std::string& err);

// Runs a command through the system shell. Returns the exit code (-1 on failure to start).
int run(const std::string& cmd, bool quiet = false);
// Runs a command and captures stdout. exit_code receives the process exit code.
std::string run_capture(const std::string& cmd, int& exit_code);

// Quotes a path for use on the shell command line of the current OS.
std::string shell_quote(const std::string& s);

}  // namespace varta
