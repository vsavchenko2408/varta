// Varta - manages a clearly marked block inside the system hosts file.
// Everything outside the markers is left exactly as it was.
#pragma once

#include <string>
#include <vector>

namespace varta {

extern const char* const kHostsBegin;
extern const char* const kHostsEnd;

std::string render_hosts_section(const std::vector<std::string>& domains, bool ipv6);
// Removes the Varta block (if any) from hosts file content.
std::string strip_hosts_section(const std::string& content);
// Replaces (or appends) the Varta block.
std::string merge_hosts_section(const std::string& content, const std::string& section);
// Number of distinct domains currently blocked by the Varta block.
size_t count_hosts_domains(const std::string& content);

// Applies to a real file. Saves a one-time backup of the original next to `backup_path`.
bool hosts_apply(const std::string& hosts_path, const std::string& backup_path,
                 const std::vector<std::string>& domains, bool ipv6, std::string& err);
bool hosts_remove(const std::string& hosts_path, std::string& err);

}  // namespace varta
