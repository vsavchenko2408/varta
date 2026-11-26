#include "windows_daemon.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sddl.h>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <type_traits>

// windivert.h defines __in/__out/... as empty macros for MinGW, which clash with parameter
// names inside libstdc++ - so it comes after every standard header and the macros are dropped.
#include <windivert.h>
#undef __in
#undef __in_opt
#undef __out
#undef __out_opt
#undef __inout
#undef __inout_opt

#include "platform.hpp"  // varta::is_admin

namespace fs = std::filesystem;

namespace vartad {

static constexpr const wchar_t* kPipeName = L"\\\\.\\pipe\\vartad";
static constexpr const wchar_t* kServiceName = L"vartad";
static constexpr size_t kMaxClientQueue = 8 * 1024 * 1024;
static constexpr int64_t kUdpFlowMs = 120 * 1000;  // remember UDP decisions this long after last packet

// ------------------------------------------------------------------------------ logging

static std::mutex g_log_mu;
static std::string g_log_path;

static void log(const std::string& s) {
    std::lock_guard<std::mutex> lock(g_log_mu);
    std::time_t t = std::time(nullptr);
    char ts[32];
    std::strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    std::cerr << "vartad: " << s << std::endl;
    if (g_log_path.empty()) return;
    std::error_code ec;
    if (fs::exists(g_log_path, ec) && fs::file_size(g_log_path, ec) > 1024 * 1024)
        fs::rename(g_log_path, g_log_path + ".1", ec);
    std::ofstream out(g_log_path, std::ios::app);
    out << ts << "  " << s << "\n";
}

static std::string win_error(DWORD e) {
    wchar_t* msg = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, e, 0, reinterpret_cast<LPWSTR>(&msg), 0, nullptr);
    std::string s = msg ? ProcResolver::utf8(msg) : std::string();
    if (msg) LocalFree(msg);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
    return s + " (" + std::to_string(e) + ")";
}

static std::wstring exe_dir() {
    wchar_t path[MAX_PATH];
    const DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring p(path, n);
    return p.substr(0, p.find_last_of(L"\\/"));
}

// --------------------------------------------------------------------- WinDivert loader

// WinDivert.dll is loaded at run time from vartad.exe's own folder (never from PATH), so the
// build needs only the header and a missing DLL gives a clear message instead of a crash.
struct WinDivertApi {
    HMODULE dll = nullptr;
    decltype(&::WinDivertOpen) Open = nullptr;
    decltype(&::WinDivertRecv) Recv = nullptr;
    decltype(&::WinDivertSend) Send = nullptr;
    decltype(&::WinDivertShutdown) Shutdown = nullptr;
    decltype(&::WinDivertClose) Close = nullptr;
    decltype(&::WinDivertSetParam) SetParam = nullptr;
    decltype(&::WinDivertHelperCalcChecksums) CalcChecksums = nullptr;

    bool load(std::string& err) {
        const std::wstring path = exe_dir() + L"\\WinDivert.dll";
        dll = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!dll) {
            err = "cannot load " + ProcResolver::utf8(path.c_str()) + ": " + win_error(GetLastError()) +
                  " - WinDivert.dll and WinDivert64.sys must be next to vartad.exe";
            return false;
        }
        auto get = [&](auto& fn, const char* name) {
            fn = reinterpret_cast<std::remove_reference_t<decltype(fn)>>(reinterpret_cast<void*>(GetProcAddress(dll, name)));
            if (!fn) err = std::string("WinDivert.dll has no ") + name;
            return fn != nullptr;
        };
        return get(Open, "WinDivertOpen") && get(Recv, "WinDivertRecv") && get(Send, "WinDivertSend") &&
               get(Shutdown, "WinDivertShutdown") && get(Close, "WinDivertClose") &&
               get(SetParam, "WinDivertSetParam") && get(CalcChecksums, "WinDivertHelperCalcChecksums");
    }
    ~WinDivertApi() {
        if (dll) FreeLibrary(dll);
    }
};

static std::string open_error(DWORD e) {
    switch (e) {
        case ERROR_FILE_NOT_FOUND: return "WinDivert64.sys not found next to vartad.exe";
        case ERROR_ACCESS_DENIED: return "access denied - run as Administrator / as the service";
        case ERROR_INVALID_IMAGE_HASH: return "Windows refused the WinDivert driver signature (ERROR_INVALID_IMAGE_HASH)";
        case ERROR_DRIVER_BLOCKED: return "the WinDivert driver was blocked (antivirus / Memory Integrity?)";
        case ERROR_INVALID_PARAMETER: return "invalid WinDivert filter";
        case 654: return "an incompatible WinDivert driver is already loaded (another program uses an older WinDivert)";
        default: return win_error(e);
    }
}

// ---------------------------------------------------------------------------- daemon

WindowsDaemon::WindowsDaemon(Paths p) : paths_(p), engine_(p, *this), api_(std::make_unique<WinDivertApi>()) {
    engine_.platform = "windows";
    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::error_code ec;
    fs::create_directories(paths_.config_dir, ec);
    g_log_path = (fs::path(paths_.config_dir) / "vartad.log").string();
}

WindowsDaemon::~WindowsDaemon() {
    for (auto& t : threads_)
        if (t.joinable()) t.join();
    auto close = [&](void* h) {
        if (h && api_->Close) api_->Close(h);
    };
    close(main_.load());
    close(dns_);
    close(sock_);
    for (void* h : retired_) close(h);
    if (stop_event_) CloseHandle(stop_event_);
}

std::string WindowsDaemon::capture_filter(const Settings& s) {
    // Only the *first* packet of a TCP connection (SYN) is diverted, so established TCP traffic
    // never leaves the kernel. UDP has no handshake, so outbound UDP is diverted and a flow cache
    // answers repeat packets immediately.
    std::string udp = "(outbound and udp and udp.DstPort != 67 and udp.DstPort != 547";
    if (s.auto_allow_dns) udp += " and udp.DstPort != 53";
    udp += ")";
    std::string f = "not loopback and not impostor and ((outbound and tcp and tcp.Syn and not tcp.Ack) or " + udp;
    if (s.ask_inbound) f += " or (inbound and tcp and tcp.Syn and not tcp.Ack)";
    return f + ")";
}

bool WindowsDaemon::open_divert(std::string& err) {
    if (!api_->dll && !api_->load(err)) return false;
    const std::string filter = capture_filter(engine_.settings);
    HANDLE h = api_->Open(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (h == INVALID_HANDLE_VALUE) {
        err = "WinDivertOpen (capture) failed: " + open_error(GetLastError());
        return false;
    }
    api_->SetParam(h, WINDIVERT_PARAM_QUEUE_LENGTH, WINDIVERT_PARAM_QUEUE_LENGTH_MAX);
    api_->SetParam(h, WINDIVERT_PARAM_QUEUE_SIZE, WINDIVERT_PARAM_QUEUE_SIZE_MAX);
    main_.store(h);

    dns_ = api_->Open("inbound and udp and udp.SrcPort == 53", WINDIVERT_LAYER_NETWORK, 0,
                      WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (dns_ == INVALID_HANDLE_VALUE) {
        dns_ = nullptr;
        log("warning: DNS sniffing unavailable: " + open_error(GetLastError()));
    }
    sock_ = api_->Open("event == BIND or event == CONNECT or event == ACCEPT", WINDIVERT_LAYER_SOCKET, 0,
                       WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (sock_ == INVALID_HANDLE_VALUE) {
        sock_ = nullptr;
        log("warning: socket events unavailable (process lookup falls back to IP Helper): " +
            open_error(GetLastError()));
    }
    return true;
}

void WindowsDaemon::reinstall_capture() {
    // Called with engine_mu_ held, from a GUI settings change.
    const std::string filter = capture_filter(engine_.settings);
    HANDLE h = api_->Open(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (h == INVALID_HANDLE_VALUE) {
        log("cannot reopen capture with new settings: " + open_error(GetLastError()));
        return;
    }
    api_->SetParam(h, WINDIVERT_PARAM_QUEUE_LENGTH, WINDIVERT_PARAM_QUEUE_LENGTH_MAX);
    void* old = main_.exchange(h);
    // Held packets still reference the old handle: stop receiving on it but keep it for sending.
    api_->Shutdown(old, WINDIVERT_SHUTDOWN_RECV);
    retired_.push_back(old);
    log("capture filter updated: " + filter);
}

std::string WindowsDaemon::flow_key(uint8_t proto, uint16_t local_port, const IpAddr& remote, uint16_t remote_port) {
    return std::to_string(proto) + "|" + std::to_string(local_port) + "|" + remote.unmapped().str() + "|" +
           std::to_string(remote_port);
}

void WindowsDaemon::handle_packet(void* handle, const uint8_t* data, unsigned len, const void* addr_raw) {
    const auto* addr = static_cast<const WINDIVERT_ADDRESS*>(addr_raw);
    PacketInfo p;
    if (!parse_packet(data, len, p)) {
        api_->Send(handle, data, len, nullptr, addr);
        return;
    }
    const bool inbound = !addr->Outbound;
    Connection c;
    c.inbound = inbound;
    c.proto = p.proto;
    if (inbound) {
        c.local = p.dst; c.local_port = p.dport;
        c.remote = p.src; c.remote_port = p.sport;
    } else {
        c.local = p.src; c.local_port = p.sport;
        c.remote = p.dst; c.remote_port = p.dport;
    }

    if (p.proto == kProtoUdp) {
        // Fast path for UDP flows that were already decided.
        std::lock_guard<std::mutex> lock(engine_mu_);
        const auto it = flows_.find(flow_key(c.proto, c.local_port, c.remote, c.remote_port));
        if (it != flows_.end() && it->second.expires > now_ms()) {
            it->second.expires = now_ms() + kUdpFlowMs;
            if (it->second.allow) api_->Send(handle, data, len, nullptr, addr);
            return;  // denied: drop
        }
    }

    c.proc = procs_.find(c.proto, c.local, c.local_port, c.remote, c.remote_port, inbound);
    Held h;
    h.packet.assign(data, data + len);
    h.addr.assign(static_cast<const uint8_t*>(addr_raw), static_cast<const uint8_t*>(addr_raw) + sizeof(WINDIVERT_ADDRESS));
    h.handle = handle;

    std::lock_guard<std::mutex> lock(engine_mu_);
    const uint64_t ticket = next_ticket_++;
    held_.emplace(ticket, std::move(h));
    engine_.on_connection(std::move(c), ticket);
}

static uint32_t be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
static void put16(uint8_t* p, uint16_t v) { p[0] = uint8_t(v >> 8); p[1] = uint8_t(v); }
static void put32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}

void WindowsDaemon::inject_rst(const Held& h) {
    // Answer a denied outgoing SYN with a TCP RST "from" the server, so the program gets
    // "connection refused" at once instead of waiting ~20 s for a timeout.
    const uint8_t* d = h.packet.data();
    const size_t len = h.packet.size();
    if (len < 1) return;
    const bool v6 = (d[0] >> 4) == 6;
    const size_t iphl = v6 ? 40 : static_cast<size_t>(d[0] & 0x0f) * 4;
    if (len < iphl + 20 || (!v6 && d[9] != kProtoTcp) || (v6 && d[6] != kProtoTcp)) return;
    const uint8_t* tcp = d + iphl;

    std::vector<uint8_t> out(v6 ? 60 : 40, 0);
    uint8_t* t;
    if (v6) {
        out[0] = 0x60;
        put16(&out[4], 20);
        out[6] = kProtoTcp;
        out[7] = 64;
        std::memcpy(&out[8], d + 24, 16);   // src = original dst
        std::memcpy(&out[24], d + 8, 16);   // dst = original src
        t = &out[40];
    } else {
        out[0] = 0x45;
        put16(&out[2], 40);
        out[8] = 64;
        out[9] = kProtoTcp;
        std::memcpy(&out[12], d + 16, 4);
        std::memcpy(&out[16], d + 12, 4);
        t = &out[20];
    }
    std::memcpy(t, tcp + 2, 2);      // sport = original dport
    std::memcpy(t + 2, tcp, 2);      // dport = original sport
    put32(t + 4, 0);                 // seq
    put32(t + 8, be32(tcp + 4) + 1); // ack = their seq + 1
    t[12] = 5 << 4;
    t[13] = 0x14;                    // RST + ACK

    WINDIVERT_ADDRESS addr;
    std::memcpy(&addr, h.addr.data(), sizeof addr);
    addr.Outbound = 0;  // deliver to the local program
    addr.Impostor = 0;
    api_->CalcChecksums(out.data(), static_cast<UINT>(out.size()), &addr, 0);
    api_->Send(h.handle, out.data(), static_cast<UINT>(out.size()), nullptr, &addr);
}

void WindowsDaemon::verdict(const std::vector<uint64_t>& tickets, bool allow, const Connection& c) {
    for (uint64_t t : tickets) {
        auto it = held_.find(t);
        if (it == held_.end()) continue;
        Held h = std::move(it->second);
        held_.erase(it);
        WINDIVERT_ADDRESS addr;
        std::memcpy(&addr, h.addr.data(), sizeof addr);
        if (allow) {
            if (!api_->Send(h.handle, h.packet.data(), static_cast<UINT>(h.packet.size()), nullptr, &addr))
                log("re-inject failed: " + win_error(GetLastError()));
        } else if (c.proto == kProtoTcp && addr.Outbound) {
            inject_rst(h);
        }
        // denied inbound / UDP: simply dropped
    }
    if (c.proto == kProtoUdp)
        flows_[flow_key(c.proto, c.local_port, c.remote, c.remote_port)] = {allow, now_ms() + kUdpFlowMs};
}

// ------------------------------------------------------------------------ threads

void WindowsDaemon::capture_loop() {
    std::vector<uint8_t> buf(WINDIVERT_MTU_MAX);
    WINDIVERT_ADDRESS addr;
    while (running_) {
        HANDLE h = main_.load();
        UINT len = 0;
        if (!api_->Recv(h, buf.data(), static_cast<UINT>(buf.size()), &len, &addr)) {
            const DWORD e = GetLastError();
            if (!running_) break;
            if (e != ERROR_NO_DATA && e != ERROR_INSUFFICIENT_BUFFER) log("capture: " + win_error(e));
            if (e != ERROR_INSUFFICIENT_BUFFER) Sleep(5);  // handle was swapped or shut down
            continue;
        }
        handle_packet(h, buf.data(), len, &addr);
    }
}

void WindowsDaemon::dns_loop() {
    std::vector<uint8_t> buf(WINDIVERT_MTU_MAX);
    WINDIVERT_ADDRESS addr;
    while (running_ && dns_) {
        UINT len = 0;
        if (!api_->Recv(dns_, buf.data(), static_cast<UINT>(buf.size()), &len, &addr)) {
            if (GetLastError() == ERROR_NO_DATA) break;
            continue;
        }
        PacketInfo p;
        if (!parse_packet(buf.data(), len, p) || p.proto != kProtoUdp) continue;
        std::lock_guard<std::mutex> lock(engine_mu_);
        engine_.on_dns(p.payload, p.payload_len);
    }
}

void WindowsDaemon::socket_loop() {
    WINDIVERT_ADDRESS addr;
    while (running_ && sock_) {
        UINT len = 0;
        if (!api_->Recv(sock_, nullptr, 0, &len, &addr)) {
            if (GetLastError() == ERROR_NO_DATA) break;
            continue;
        }
        procs_.note_socket(addr.Socket.Protocol, addr.Socket.LocalPort, addr.Socket.ProcessId);
    }
}

void WindowsDaemon::tick_loop() {
    while (WaitForSingleObject(stop_event_, 250) == WAIT_TIMEOUT) {
        std::lock_guard<std::mutex> lock(engine_mu_);
        engine_.tick();
        if (flows_.size() > 20000) {
            const int64_t now = now_ms();
            for (auto it = flows_.begin(); it != flows_.end();)
                it = it->second.expires < now ? flows_.erase(it) : std::next(it);
        }
    }
}

// --------------------------------------------------------------- named pipe for the GUI

void WindowsDaemon::pipe_loop() {
    // SYSTEM and Administrators: full access. Interactive users (whoever sits at the PC):
    // read/write, so the GUI works without elevation. Remote clients are rejected.
    PSECURITY_DESCRIPTOR sd = nullptr;
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)",
                                                         SDDL_REVISION_1, &sd, nullptr);
    SECURITY_ATTRIBUTES sa{sizeof sa, sd, FALSE};
    while (running_) {
        HANDLE pipe = CreateNamedPipeW(kPipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                       PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                       PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, sd ? &sa : nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            log("CreateNamedPipe failed: " + win_error(GetLastError()));
            if (WaitForSingleObject(stop_event_, 1000) == WAIT_OBJECT_0) break;
            continue;
        }
        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        bool connected = false;
        if (ConnectNamedPipe(pipe, &ov)) {
            connected = true;
        } else {
            const DWORD e = GetLastError();
            if (e == ERROR_PIPE_CONNECTED) {
                connected = true;
            } else if (e == ERROR_IO_PENDING) {
                HANDLE waits[2] = {ov.hEvent, stop_event_};
                if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) == WAIT_OBJECT_0) {
                    DWORD n = 0;
                    connected = GetOverlappedResult(pipe, &ov, &n, FALSE) != FALSE;
                } else {
                    CancelIoEx(pipe, &ov);
                    DWORD n = 0;
                    GetOverlappedResult(pipe, &ov, &n, TRUE);
                }
            }
        }
        CloseHandle(ov.hEvent);
        if (!connected) {
            CloseHandle(pipe);
            continue;
        }
        auto c = std::make_shared<Client>();
        c->id = next_client_++;
        c->pipe = pipe;
        ULONG pid = 0;
        GetNamedPipeClientProcessId(pipe, &pid);
        log("GUI connected (pid " + std::to_string(pid) + ")");
        {
            std::lock_guard<std::mutex> lock(clients_mu_);
            clients_[c->id] = c;
        }
        ++sessions_;
        std::thread(&WindowsDaemon::client_session, this, c).detach();
    }
    if (sd) LocalFree(sd);
}

void WindowsDaemon::send(uint64_t client, const std::string& line) {
    std::shared_ptr<Client> c;
    {
        std::lock_guard<std::mutex> lock(clients_mu_);
        const auto it = clients_.find(client);
        if (it == clients_.end()) return;
        c = it->second;
    }
    {
        std::lock_guard<std::mutex> lock(c->m);
        if (c->closed) return;
        if (c->queued + line.size() > kMaxClientQueue) {
            log("GUI client is not reading - disconnecting it");
            c->closed = true;
            CancelIoEx(c->pipe, nullptr);
        } else {
            c->out.push_back(line);
            c->queued += line.size();
        }
    }
    c->cv.notify_one();
}

void WindowsDaemon::writer_loop(const std::shared_ptr<Client>& c) {
    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    for (;;) {
        std::string chunk;
        {
            std::unique_lock<std::mutex> lock(c->m);
            c->cv.wait(lock, [&] { return c->closed || !c->out.empty(); });
            if (c->closed) break;
            while (!c->out.empty() && chunk.size() < 256 * 1024) {
                chunk += c->out.front();
                c->queued -= c->out.front().size();
                c->out.pop_front();
            }
        }
        size_t off = 0;
        bool ok = true;
        while (ok && off < chunk.size()) {
            ResetEvent(ov.hEvent);
            DWORD n = 0;
            BOOL r = WriteFile(c->pipe, chunk.data() + off, static_cast<DWORD>(chunk.size() - off), &n, &ov);
            if (!r && GetLastError() == ERROR_IO_PENDING) {
                HANDLE waits[2] = {ov.hEvent, stop_event_};
                if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0) {
                    CancelIoEx(c->pipe, &ov);
                    GetOverlappedResult(c->pipe, &ov, &n, TRUE);
                    ok = false;
                    break;
                }
                r = GetOverlappedResult(c->pipe, &ov, &n, FALSE);
            }
            if (!r) ok = false;
            off += n;
        }
        if (!ok) {
            std::lock_guard<std::mutex> lock(c->m);
            c->closed = true;
            CancelIoEx(c->pipe, nullptr);  // wakes the reader
            break;
        }
    }
    CloseHandle(ov.hEvent);
}

void WindowsDaemon::client_session(std::shared_ptr<Client> c) {
    {
        std::lock_guard<std::mutex> lock(engine_mu_);
        engine_.client_connected(c->id);
    }
    std::thread writer(&WindowsDaemon::writer_loop, this, c);

    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::string in;
    char buf[16384];
    while (running_) {
        {
            std::lock_guard<std::mutex> lock(c->m);
            if (c->closed) break;
        }
        ResetEvent(ov.hEvent);
        DWORD n = 0;
        BOOL r = ReadFile(c->pipe, buf, sizeof buf, &n, &ov);
        if (!r && GetLastError() == ERROR_IO_PENDING) {
            HANDLE waits[2] = {ov.hEvent, stop_event_};
            if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0) {
                CancelIoEx(c->pipe, &ov);
                GetOverlappedResult(c->pipe, &ov, &n, TRUE);
                break;
            }
            r = GetOverlappedResult(c->pipe, &ov, &n, FALSE);
        }
        if (!r) break;  // client went away (ERROR_BROKEN_PIPE) or I/O was cancelled
        in.append(buf, n);
        if (in.size() > kMaxClientQueue) break;
        size_t nl;
        while ((nl = in.find('\n')) != std::string::npos) {
            const std::string line = in.substr(0, nl);
            in.erase(0, nl + 1);
            if (line.empty()) continue;
            std::lock_guard<std::mutex> lock(engine_mu_);
            engine_.client_message(c->id, line);
        }
    }
    CloseHandle(ov.hEvent);
    {
        std::lock_guard<std::mutex> lock(c->m);
        c->closed = true;
    }
    c->cv.notify_all();
    writer.join();
    {
        std::lock_guard<std::mutex> lock(clients_mu_);
        clients_.erase(c->id);
    }
    {
        std::lock_guard<std::mutex> lock(engine_mu_);
        engine_.client_disconnected(c->id);
    }
    DisconnectNamedPipe(c->pipe);
    CloseHandle(c->pipe);
    log("GUI disconnected");
    --sessions_;
}

// ---------------------------------------------------------------------------- lifecycle

void WindowsDaemon::stop() {
    running_ = false;
    if (stop_event_) SetEvent(stop_event_);
}

int WindowsDaemon::run(const std::function<void()>& started) {
    if (!varta::is_admin()) {
        log("vartad must run as Administrator (or as the 'vartad' service)");
        return 1;
    }
    std::string info;
    {
        std::lock_guard<std::mutex> lock(engine_mu_);
        engine_.load(info);
    }
    std::istringstream lines(info);
    for (std::string l; std::getline(lines, l);) log(l);

    std::string err;
    if (!open_divert(err)) {
        log(err);
        return 1;
    }
    log("capture filter: " + capture_filter(engine_.settings));
    log("running - mode '" + engine_.settings.mode + "', GUI pipe \\\\.\\pipe\\vartad");

    threads_.emplace_back(&WindowsDaemon::capture_loop, this);
    if (dns_) threads_.emplace_back(&WindowsDaemon::dns_loop, this);
    if (sock_) threads_.emplace_back(&WindowsDaemon::socket_loop, this);
    threads_.emplace_back(&WindowsDaemon::pipe_loop, this);
    threads_.emplace_back(&WindowsDaemon::tick_loop, this);
    if (started) started();

    WaitForSingleObject(stop_event_, INFINITE);
    log("shutting down");
    // 1. Stop capturing new packets; the loops end with ERROR_NO_DATA once their queues drain.
    if (void* h = main_.load()) api_->Shutdown(h, WINDIVERT_SHUTDOWN_RECV);
    for (void* h : retired_) api_->Shutdown(h, WINDIVERT_SHUTDOWN_RECV);
    if (dns_) api_->Shutdown(dns_, WINDIVERT_SHUTDOWN_BOTH);
    if (sock_) api_->Shutdown(sock_, WINDIVERT_SHUTDOWN_BOTH);
    for (auto& t : threads_)
        if (t.joinable()) t.join();
    threads_.clear();
    {
        // 2. Never leave packets in limbo: everything still held is re-injected.
        std::lock_guard<std::mutex> lock(engine_mu_);
        engine_.shutdown();
    }
    for (int i = 0; i < 100 && sessions_ > 0; ++i) Sleep(50);  // client threads see stop_event_
    return 0;
}

// ------------------------------------------------------------------- console & service

static WindowsDaemon* g_console = nullptr;

static BOOL WINAPI console_ctrl(DWORD) {
    if (g_console) g_console->stop();
    return TRUE;
}

int WindowsDaemon::run_console() {
    g_console = this;
    SetConsoleCtrlHandler(console_ctrl, TRUE);
    std::cerr << "vartad: running in this console - press Ctrl+C to stop." << std::endl;
    const int rc = run(nullptr);
    g_console = nullptr;
    return rc;
}

static SERVICE_STATUS_HANDLE g_status = nullptr;
static WindowsDaemon* g_service = nullptr;
static Paths g_service_paths;

static void set_status(DWORD state, DWORD exit_code = NO_ERROR) {
    SERVICE_STATUS st{};
    st.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    st.dwCurrentState = state;
    st.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    st.dwWin32ExitCode = exit_code ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR;
    st.dwServiceSpecificExitCode = exit_code;
    st.dwWaitHint = state == SERVICE_RUNNING ? 0 : 10000;
    static DWORD checkpoint = 1;
    st.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;
    SetServiceStatus(g_status, &st);
}

static DWORD WINAPI service_handler(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    switch (ctrl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            set_status(SERVICE_STOP_PENDING);
            if (g_service) g_service->stop();
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static void WINAPI service_main(DWORD, LPWSTR*) {
    g_status = RegisterServiceCtrlHandlerExW(kServiceName, service_handler, nullptr);
    if (!g_status) return;
    set_status(SERVICE_START_PENDING);
    int rc = 0;
    {
        WindowsDaemon d(g_service_paths);
        g_service = &d;
        rc = d.run([] { set_status(SERVICE_RUNNING); });
        g_service = nullptr;
    }
    set_status(SERVICE_STOPPED, static_cast<DWORD>(rc));
}

int WindowsDaemon::run_as_service(const Paths& p) {
    g_service_paths = p;
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(kServiceName), service_main}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) {
        std::cerr << "vartad: --service is for the Service Control Manager. "
                     "Use --install-service, or --console to run it by hand.\n";
        return 1;
    }
    return 0;
}

int WindowsDaemon::install_service() {
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    const std::wstring cmd = L"\"" + std::wstring(exe) + L"\" --service";
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        std::cerr << "OpenSCManager failed: " << win_error(GetLastError()) << " (run as Administrator)\n";
        return 1;
    }
    SC_HANDLE svc = CreateServiceW(scm, kServiceName, L"Varta firewall (vartad)", SERVICE_ALL_ACCESS,
                                   SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                   cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc && GetLastError() == ERROR_SERVICE_EXISTS) {
        svc = OpenServiceW(scm, kServiceName, SERVICE_ALL_ACCESS);
        if (svc)
            ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, cmd.c_str(),
                                 nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    }
    if (!svc) {
        std::cerr << "CreateService failed: " << win_error(GetLastError()) << "\n";
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_DESCRIPTIONW desc{const_cast<LPWSTR>(L"Asks before programs connect to the network and blocks trackers. "
                                                  L"GUI: varta-gui.exe")};
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);
    // Restart automatically if it ever crashes (the capture is fail-open meanwhile).
    SC_ACTION actions[3] = {{SC_ACTION_RESTART, 3000}, {SC_ACTION_RESTART, 10000}, {SC_ACTION_NONE, 0}};
    SERVICE_FAILURE_ACTIONSW fa{};
    fa.dwResetPeriod = 24 * 3600;
    fa.cActions = 3;
    fa.lpsaActions = actions;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    if (!StartServiceW(svc, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        std::cerr << "service installed, but it did not start: " << win_error(GetLastError())
                  << "\nSee %ProgramData%\\Varta\\vartad.log\n";
    } else {
        std::cout << "service 'vartad' installed and started.\n";
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

int WindowsDaemon::uninstall_service() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        std::cerr << "OpenSCManager failed: " << win_error(GetLastError()) << " (run as Administrator)\n";
        return 1;
    }
    SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!svc) {
        std::cerr << "service 'vartad' is not installed\n";
        CloseServiceHandle(scm);
        return 0;
    }
    SERVICE_STATUS st{};
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
        for (int i = 0; i < 100 && QueryServiceStatus(svc, &st) && st.dwCurrentState != SERVICE_STOPPED; ++i) Sleep(100);
    }
    const bool ok = DeleteService(svc) != FALSE;
    std::cout << (ok ? "service 'vartad' removed.\n" : "DeleteService failed\n");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok ? 0 : 1;
}

}  // namespace vartad
