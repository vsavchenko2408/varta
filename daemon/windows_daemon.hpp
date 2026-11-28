// vartad - Windows front end.
//
//   capture  : WinDivert NETWORK layer - outbound TCP SYN, outbound UDP and (optionally) inbound
//              TCP SYN are diverted to us and *held* in memory until the engine decides; allowed
//              packets are re-injected, denied TCP connections get a RST so programs fail fast.
//   dns      : WinDivert sniff handle on DNS answers -> ip -> host names.
//   sockets  : WinDivert SOCKET layer (sniff) -> which process bound/connected which port.
//   GUI      : named pipe \\.\pipe\vartad (QLocalSocket "vartad"), overlapped I/O.
//   service  : runs as the Windows service "vartad" (LocalSystem), or in a console.
// All engine calls are serialised by one mutex.
#pragma once

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "engine.hpp"
#include "procinfo_win.hpp"

namespace vartad {

struct WinDivertApi;

class WindowsDaemon : public EngineHost {
public:
    explicit WindowsDaemon(Paths p);
    ~WindowsDaemon() override;

    int run_console();
    void stop();  // thread-safe, returns immediately

    static int run_as_service(const Paths& p);
    static int install_service();
    static int uninstall_service();
    // Puts Windows Defender Firewall back the way it was before vartad managed it (uninstall).
    static int restore_windows_firewall(const Paths& p);
    // Runs a PowerShell script hidden and waits; returns its exit code (-1 if it did not start).
    static int run_powershell(const std::string& script, const std::string& work_dir);
    // Builds the capture filter (exposed for tests).
    static std::string capture_filter(const Settings& s);

    // EngineHost (called with engine_mu_ held)
    void verdict(const std::vector<uint64_t>& tickets, bool allow, const Connection& c) override;
    void send(uint64_t client, const std::string& line) override;
    void reinstall_capture() override;

    int run(const std::function<void()>& started);

private:
    struct Held {
        std::vector<uint8_t> packet;
        std::vector<uint8_t> addr;  // raw WINDIVERT_ADDRESS bytes
        void* handle = nullptr;
    };
    struct Client {
        uint64_t id = 0;
        void* pipe = nullptr;
        std::mutex m;
        std::condition_variable cv;
        std::deque<std::string> out;
        size_t queued = 0;
        bool closed = false;
    };
    struct Flow {
        bool allow = true;
        int64_t expires = 0;
    };

    bool open_divert(std::string& err);
    void capture_loop();
    void dns_loop();
    void socket_loop();
    void pipe_loop();
    void tick_loop();
    void client_session(std::shared_ptr<Client> c);
    void writer_loop(const std::shared_ptr<Client>& c);
    void handle_packet(void* handle, const uint8_t* data, unsigned len, const void* addr);
    void inject_rst(const Held& h);
    // Windows Defender Firewall management (block_inbound). PowerShell is slow (about a
    // second), so a worker thread applies the latest wanted state in the background.
    void firewall_loop();
    void update_firewall_wanted(bool force);  // engine_mu_ held
    static std::string flow_key(uint8_t proto, uint16_t local_port, const IpAddr& remote, uint16_t remote_port);

    Paths paths_;
    Engine engine_;
    std::mutex engine_mu_;
    ProcResolver procs_;
    std::unique_ptr<WinDivertApi> api_;

    std::atomic<void*> main_{nullptr};
    void* dns_ = nullptr;
    void* sock_ = nullptr;
    std::vector<void*> retired_;  // old capture handles kept until exit (held packets use them)
    void* stop_event_ = nullptr;
    std::atomic<bool> running_{true};

    // guarded by engine_mu_
    std::unordered_map<uint64_t, Held> held_;
    std::unordered_map<std::string, Flow> flows_;
    uint64_t next_ticket_ = 1;
    std::set<std::string> inbound_once_;  // programs allowed inbound "once"/this session
    std::string fw_sig_;
    int64_t fw_checked_ms_ = 0;

    // handed to firewall_loop
    std::mutex fw_mu_;
    std::condition_variable fw_cv_;
    bool fw_dirty_ = false;
    bool fw_enable_ = false;
    std::set<std::string> fw_programs_;

    std::mutex clients_mu_;
    std::map<uint64_t, std::shared_ptr<Client>> clients_;
    std::atomic<uint64_t> next_client_{1};
    std::atomic<int> sessions_{0};
    std::vector<std::thread> threads_;
};

}  // namespace vartad
