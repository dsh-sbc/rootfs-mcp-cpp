#include "rootfs_mcp/sys_service.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>

namespace rootfs_mcp {

namespace {

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

// Parse "Key:   value  \n" style /proc files into (key, value) pairs.
std::vector<std::pair<std::string, std::string>> parse_colon_file(const std::string& path) {
    std::vector<std::pair<std::string, std::string>> out;
    std::ifstream in(path);
    if (!in) return out; // tolerate missing/unreadable /proc
    std::string line;
    while (std::getline(in, line)) {
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        out.emplace_back(trim(line.substr(0, colon)), trim(line.substr(colon + 1)));
    }
    return out;
}

uint64_t kb_value(const std::string& v) {
    // "16384 kB" -> bytes
    unsigned long long kb = 0;
    if (std::sscanf(v.c_str(), "%llu", &kb) != 1) return 0;
    return static_cast<uint64_t>(kb) * 1024;
}

bool is_numeric(const std::string& s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return std::isdigit(c); });
}

} // namespace

json sys_service::info() {
    json r;
    struct utsname u;
    if (uname(&u) == 0) {
        r["sysname"] = u.sysname;
        r["kernel_release"] = u.release;
        r["kernel_version"] = u.version;
        r["machine"] = u.machine;
        r["nodename"] = u.nodename;
    } else {
        r["error"] = std::string("uname failed: ") + std::strerror(errno);
    }
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n > 0) r["cpus_online"] = static_cast<uint64_t>(n);
    return r;
}

json sys_service::memory() {
    json r;
    auto kv = parse_colon_file("/proc/meminfo");
    if (kv.empty()) {
        r["error"] = "/proc/meminfo unavailable";
        return r;
    }
    json all = json::object();
    for (const auto& p : kv) {
        uint64_t bytes = kb_value(p.second);
        all[p.first] = bytes;
        if (p.first == "MemTotal") r["total_bytes"] = bytes;
        else if (p.first == "MemAvailable") r["available_bytes"] = bytes;
        else if (p.first == "MemFree") r["free_bytes"] = bytes;
        else if (p.first == "Buffers") r["buffers_bytes"] = bytes;
        else if (p.first == "Cached") r["cached_bytes"] = bytes;
        else if (p.first == "SwapTotal") r["swap_total_bytes"] = bytes;
        else if (p.first == "SwapFree") r["swap_free_bytes"] = bytes;
    }
    r["meminfo"] = std::move(all);
    return r;
}

json sys_service::cpu() {
    json r;
    struct utsname u;
    if (uname(&u) == 0) r["architecture"] = u.machine;
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n > 0) r["cores_online"] = static_cast<uint64_t>(n);
    long conf = sysconf(_SC_NPROCESSORS_CONF);
    if (conf > 0) r["cores_configured"] = static_cast<uint64_t>(conf);

    auto kv = parse_colon_file("/proc/cpuinfo");
    if (kv.empty()) {
        r["cpuinfo_available"] = false;
        return r;
    }
    r["cpuinfo_available"] = true;
    uint64_t processor_entries = 0;
    for (const auto& p : kv) {
        // x86: "model name"/"cpu MHz"; RISC-V cpuinfo instead exposes
        // "hart"/"isa"/"uarch"/"mmu" — fields may be absent entirely, which
        // must not fail the call.
        if (p.first == "processor") ++processor_entries;
        else if (p.first == "model name" && !r.contains("model_name")) r["model_name"] = p.second;
        else if (p.first == "cpu MHz" && !r.contains("mhz")) r["mhz"] = p.second;
        else if (p.first == "Hardware" && !r.contains("hardware")) r["hardware"] = p.second;
        else if (p.first == "isa" && !r.contains("isa")) r["isa"] = p.second;
        else if (p.first == "uarch" && !r.contains("uarch")) r["uarch"] = p.second;
        else if (p.first == "mmu" && !r.contains("mmu")) r["mmu"] = p.second;
        else if (p.first == "CPU implementer" && !r.contains("implementer")) r["implementer"] = p.second;
    }
    if (processor_entries > 0) r["cpuinfo_processors"] = processor_entries;
    return r;
}

json sys_service::mounts() {
    json r;
    std::ifstream in("/proc/mounts");
    if (!in) {
        r["error"] = "/proc/mounts unavailable";
        r["mounts"] = json::array();
        return r;
    }
    json arr = json::array();
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string dev, mnt, fstype, opts;
        if (!(iss >> dev >> mnt >> fstype >> opts)) continue;
        arr.push_back({{"device", dev},
                       {"mount_point", mnt},
                       {"fs_type", fstype},
                       {"options", opts}});
    }
    r["mounts"] = std::move(arr);
    r["count"] = r["mounts"].size();
    return r;
}

json sys_service::processes(uint64_t max_count) {
    json r;
    max_count = std::min<uint64_t>(max_count == 0 ? 128 : max_count, 4096);
    DIR* d = opendir("/proc");
    if (!d) {
        r["error"] = "/proc unavailable";
        r["processes"] = json::array();
        return r;
    }
    json arr = json::array();
    uint64_t partial_errors = 0;
    while (dirent* e = readdir(d)) {
        if (arr.size() >= max_count) break;
        if (!is_numeric(e->d_name)) continue;
        std::string pid_s = e->d_name;
        std::string base = std::string("/proc/") + pid_s;

        json p;
        p["pid"] = std::stoll(pid_s);

        // /proc/<pid>/stat: "pid (comm) state ppid ..." — comm may contain
        // spaces/parens, so split at the LAST ')'.
        std::ifstream stat_in(base + "/stat");
        std::string stat_line;
        if (std::getline(stat_in, stat_line)) {
            size_t rp = stat_line.rfind(')');
            if (rp != std::string::npos && rp + 2 < stat_line.size()) {
                size_t lp = stat_line.find('(');
                if (lp != std::string::npos)
                    p["name"] = stat_line.substr(lp + 1, rp - lp - 1);
                std::istringstream rest(stat_line.substr(rp + 2));
                std::string state;
                int64_t ppid = 0;
                if (rest >> state >> ppid) {
                    p["state"] = state;
                    p["ppid"] = ppid;
                }
            }
        }
        // /proc/<pid>/status may be unreadable for foreign processes; treat
        // missing fields as partial results, not failures.
        std::ifstream status_in(base + "/status");
        std::string line;
        while (std::getline(status_in, line)) {
            if (line.compare(0, 6, "VmRSS:") == 0) {
                p["rss_bytes"] = kb_value(trim(line.substr(6)));
            } else if (line.compare(0, 4, "Uid:") == 0) {
                unsigned long long uid = 0;
                if (std::sscanf(trim(line.substr(4)).c_str(), "%llu", &uid) == 1)
                    p["uid"] = static_cast<uint64_t>(uid);
            }
        }
        if (!p.contains("name")) {
            p["partial"] = true;
            ++partial_errors;
        }
        arr.push_back(std::move(p));
    }
    closedir(d);
    r["processes"] = std::move(arr);
    r["count"] = r["processes"].size();
    r["truncated"] = r["count"].get<uint64_t>() >= max_count;
    r["partial_errors"] = partial_errors;
    return r;
}

} // namespace rootfs_mcp
