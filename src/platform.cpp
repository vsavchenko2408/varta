#include "platform.hpp"

#include <cstdlib>
#include <filesystem>

#include "util.hpp"

#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <unistd.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace varta {

Paths paths_for_home(const std::string& home, const std::string& hosts) {
    Paths p;
    p.home = home;
    p.config = (fs::path(home) / "varta.conf").string();
    p.backup = (fs::path(home) / "hosts.original").string();
    p.lists_dir = (fs::path(home) / "lists").string();
    p.work_dir = (fs::path(home) / "generated").string();
    p.hosts = hosts;
    return p;
}

Paths default_paths() {
#ifdef _WIN32
    const char* pd = std::getenv("ProgramData");
    const char* sr = std::getenv("SystemRoot");
    const std::string home = (fs::path(pd ? pd : "C:\\ProgramData") / "Varta").string();
    const std::string hosts =
        (fs::path(sr ? sr : "C:\\Windows") / "System32" / "drivers" / "etc" / "hosts").string();
    return paths_for_home(home, hosts);
#else
    return paths_for_home("/etc/varta", "/etc/hosts");
#endif
}

bool is_admin() {
#ifdef _WIN32
    BOOL member = FALSE;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admins = nullptr;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0,
                                 0, 0, 0, 0, 0, &admins)) {
        CheckTokenMembership(nullptr, admins, &member);
        FreeSid(admins);
    }
    return member == TRUE;
#else
    return geteuid() == 0;
#endif
}

const char* admin_hint() {
#ifdef _WIN32
    return "run it from a terminal opened with 'Run as administrator'";
#else
    return "run it with sudo";
#endif
}

void flush_dns_cache() {
#ifdef _WIN32
    run("ipconfig /flushdns", true);
#elif defined(__APPLE__)
    run("dscacheutil -flushcache", true);
    run("killall -HUP mDNSResponder", true);
#else
    // Only matters if a caching resolver is running; failures are harmless.
    run("resolvectl flush-caches", true);
    run("nscd -i hosts", true);
#endif
}

std::string executable_path() {
#ifdef _WIN32
    char buf[MAX_PATH];
    const DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return std::string(buf, n);
#elif defined(__APPLE__)
    char buf[4096];
    uint32_t size = sizeof buf;
    if (_NSGetExecutablePath(buf, &size) == 0) {
        std::error_code ec;
        const auto p = fs::canonical(buf, ec);
        return ec ? std::string(buf) : p.string();
    }
    return "varta";
#else
    std::error_code ec;
    const auto p = fs::read_symlink("/proc/self/exe", ec);
    return ec ? "varta" : p.string();
#endif
}

#if defined(__APPLE__)
static const char* kPlist = "/Library/LaunchDaemons/dk.varta.apply.plist";
#elif !defined(_WIN32)
static const char* kUnit = "/etc/systemd/system/varta.service";
#endif

bool autostart_enable(std::string& msg) {
    const std::string exe = executable_path();
#ifdef _WIN32
    (void)exe;
    msg = "Windows Firewall rules and the hosts file survive reboots - nothing to do.";
    return true;
#elif defined(__APPLE__)
    const std::string plist =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n<dict>\n"
        "  <key>Label</key><string>dk.varta.apply</string>\n"
        "  <key>ProgramArguments</key>\n  <array>\n"
        "    <string>" + exe + "</string>\n    <string>apply</string>\n"
        "    <string>--quiet</string>\n  </array>\n"
        "  <key>RunAtLoad</key><true/>\n"
        "</dict>\n</plist>\n";
    std::string err;
    if (!write_file_atomic(kPlist, plist, err)) {
        msg = err;
        return false;
    }
    run("launchctl bootout system " + shell_quote(kPlist), true);
    if (run("launchctl bootstrap system " + shell_quote(kPlist)) != 0) {
        msg = "launchctl bootstrap failed";
        return false;
    }
    msg = std::string("LaunchDaemon installed: ") + kPlist;
    return true;
#else
    const std::string unit =
        "[Unit]\n"
        "Description=Varta tracking and telemetry blocker\n"
        "Wants=network-pre.target\n"
        "Before=network-pre.target\n"
        "After=nftables.service\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=" + exe + " apply --quiet\n"
        "RemainAfterExit=yes\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";
    std::string err;
    if (!write_file_atomic(kUnit, unit, err)) {
        msg = err;
        return false;
    }
    run("systemctl daemon-reload", true);
    if (run("systemctl enable varta.service") != 0) {
        msg = "systemctl enable failed (is this a systemd system?)";
        return false;
    }
    msg = std::string("systemd unit installed and enabled: ") + kUnit;
    return true;
#endif
}

bool autostart_disable(std::string& msg) {
#ifdef _WIN32
    msg = "Nothing to do on Windows.";
    return true;
#elif defined(__APPLE__)
    run("launchctl bootout system " + shell_quote(kPlist), true);
    std::error_code ec;
    fs::remove(kPlist, ec);
    msg = "LaunchDaemon removed.";
    return true;
#else
    run("systemctl disable varta.service", true);
    std::error_code ec;
    fs::remove(kUnit, ec);
    run("systemctl daemon-reload", true);
    msg = "systemd unit removed.";
    return true;
#endif
}

void init_console() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | 0x0004 /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */);
#endif
}

}  // namespace varta
