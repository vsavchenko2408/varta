#include "hosts.hpp"

#include <filesystem>
#include <set>
#include <sstream>

#include "util.hpp"

namespace fs = std::filesystem;

namespace varta {

const char* const kHostsBegin = "# >>> VARTA BEGIN - managed by varta, do not edit by hand >>>";
const char* const kHostsEnd = "# <<< VARTA END <<<";

std::string render_hosts_section(const std::vector<std::string>& domains, bool ipv6) {
    std::ostringstream o;
    o << kHostsBegin << "\n";
    o << "# " << domains.size() << " domains. Run `varta disable` to remove this block.\n";
    for (const auto& d : domains) {
        o << "0.0.0.0 " << d << "\n";
        if (ipv6) o << ":: " << d << "\n";
    }
    o << kHostsEnd << "\n";
    return o.str();
}

// Splits content into lines while remembering whether CRLF was used (Windows hosts).
static std::vector<std::string> lines_of(const std::string& content, bool& crlf) {
    crlf = content.find("\r\n") != std::string::npos;
    std::vector<std::string> lines;
    std::istringstream in(content);
    std::string l;
    while (std::getline(in, l)) {
        if (!l.empty() && l.back() == '\r') l.pop_back();
        lines.push_back(l);
    }
    return lines;
}

static std::string join_lines(const std::vector<std::string>& lines, bool crlf) {
    std::string out;
    const char* nl = crlf ? "\r\n" : "\n";
    for (const auto& l : lines) {
        out += l;
        out += nl;
    }
    return out;
}

std::string strip_hosts_section(const std::string& content) {
    bool crlf = false;
    const auto lines = lines_of(content, crlf);
    std::vector<std::string> kept;
    bool inside = false;
    for (const auto& l : lines) {
        if (trim(l) == kHostsBegin) {
            inside = true;
            continue;
        }
        if (inside && trim(l) == kHostsEnd) {
            inside = false;
            continue;
        }
        if (!inside) kept.push_back(l);
    }
    // Drop trailing empty lines that we may have added before the block.
    while (!kept.empty() && trim(kept.back()).empty()) kept.pop_back();
    return join_lines(kept, crlf);
}

std::string merge_hosts_section(const std::string& content, const std::string& section) {
    const bool crlf = content.find("\r\n") != std::string::npos;
    std::string base = strip_hosts_section(content);
    bool dummy = false;
    const auto sec_lines = lines_of(section, dummy);
    std::string out = base;
    if (!out.empty()) out += crlf ? "\r\n" : "\n";
    out += join_lines(sec_lines, crlf);
    return out;
}

size_t count_hosts_domains(const std::string& content) {
    bool crlf = false;
    std::set<std::string> found;
    bool inside = false;
    for (const auto& l : lines_of(content, crlf)) {
        const std::string t = trim(l);
        if (t == kHostsBegin) {
            inside = true;
            continue;
        }
        if (t == kHostsEnd) break;
        if (!inside || t.empty() || t[0] == '#') continue;
        const auto toks = split_ws(t);
        if (toks.size() >= 2) found.insert(toks[1]);
    }
    return found.size();
}

bool hosts_apply(const std::string& hosts_path, const std::string& backup_path,
                 const std::vector<std::string>& domains, bool ipv6, std::string& err) {
    const auto current = read_file(hosts_path);
    if (!current) {
        err = "cannot read " + hosts_path;
        return false;
    }
    std::error_code ec;
    if (!backup_path.empty() && !fs::exists(backup_path, ec)) {
        // Keep the user's original hosts (without any Varta block) once, forever.
        if (!write_file_atomic(backup_path, strip_hosts_section(*current), err)) return false;
    }
    const std::string updated = merge_hosts_section(*current, render_hosts_section(domains, ipv6));
    return write_file_atomic(hosts_path, updated, err);
}

bool hosts_remove(const std::string& hosts_path, std::string& err) {
    const auto current = read_file(hosts_path);
    if (!current) {
        err = "cannot read " + hosts_path;
        return false;
    }
    if (current->find(kHostsBegin) == std::string::npos) return true;
    return write_file_atomic(hosts_path, strip_hosts_section(*current), err);
}

}  // namespace varta
