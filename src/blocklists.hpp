// Varta - built-in categories of tracking / telemetry domains.
#pragma once

#include <string>
#include <vector>

namespace varta {

struct Category {
    std::string id;
    std::string title;
    std::string note;  // what may break when enabled
    bool default_on;
    std::vector<std::string> domains;
};

const std::vector<Category>& builtin_categories();
const Category* find_category(const std::string& id);

// Well-known public DNS resolvers that offer DoH/DoT (blocked on ports 443/853 only).
const std::vector<std::string>& public_doh_resolvers();

}  // namespace varta
