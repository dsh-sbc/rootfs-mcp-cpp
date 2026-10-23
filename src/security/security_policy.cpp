#include "rootfs_mcp/security_policy.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <limits.h>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace rootfs_mcp {

namespace {

// Directories that must never be deleted or moved, regardless of config.
// Anything beneath /proc, /sys, /dev or /boot is equally protected; "/"
// itself is protected as an exact match.
const char* const kHardProtectedExact[] = {"/"};
const char* const kHardProtectedSubtree[] = {"/proc", "/sys", "/dev", "/boot"};

void require_absolute(const std::string& path, const char* what) {
    if (path.empty() || path[0] != '/')
        throw policy_error(std::string(what) + " must be an absolute path: " + path);
}

std::string errno_message(const std::string& prefix, int err) {
    return prefix + ": " + std::strerror(err);
}

} // namespace

server_mode parse_mode(const std::string& s) {
    if (s == "readonly") return server_mode::readonly_mode;
    if (s == "controlled") return server_mode::controlled;
    if (s == "admin") return server_mode::admin;
    throw policy_error("unknown mode: " + s + " (expected readonly|controlled|admin)");
}

std::string mode_to_string(server_mode m) {
    switch (m) {
        case server_mode::readonly_mode: return "readonly";
        case server_mode::controlled: return "controlled";
        case server_mode::admin: return "admin";
    }
    return "unknown";
}

authorized_path::~authorized_path() { reset(); }

authorized_path::authorized_path(authorized_path&& o) noexcept
    : rootfd(o.rootfd), rel(std::move(o.rel)), canonical(std::move(o.canonical)),
      root(std::move(o.root)) {
    o.rootfd = -1;
}

authorized_path& authorized_path::operator=(authorized_path&& o) noexcept {
    if (this != &o) {
        reset();
        rootfd = o.rootfd;
        o.rootfd = -1;
        rel = std::move(o.rel);
        canonical = std::move(o.canonical);
        root = std::move(o.root);
    }
    return *this;
}

void authorized_path::reset() {
    if (rootfd >= 0) {
        close(rootfd);
        rootfd = -1;
    }
}

bool security_policy::is_under(const std::string& path, const std::string& root) {
    if (root.empty() || root[0] != '/' || path.empty() || path[0] != '/') return false;
    if (root == "/") return true;
    if (path == root) return true;
    return path.compare(0, root.size(), root) == 0 && path[root.size()] == '/';
}

std::string security_policy::canonicalize_existing(const std::string& path) {
    require_absolute(path, "path");
    char buf[PATH_MAX];
    if (!realpath(path.c_str(), buf))
        throw policy_error(errno_message("cannot resolve path " + path, errno));
    return buf;
}

std::string security_policy::canonicalize_for_create(const std::string& path) {
    require_absolute(path, "path");

    // Strip trailing components until the remaining prefix exists; the
    // stripped components must be plain file names.
    std::vector<std::string> tail;
    std::string prefix = path;
    while (true) {
        struct stat st;
        if (lstat(prefix.c_str(), &st) == 0) break;
        if (errno != ENOENT && errno != ENOTDIR)
            throw policy_error(errno_message("cannot stat ancestor of " + path, errno));
        size_t slash = prefix.find_last_of('/');
        if (slash == std::string::npos || slash == 0) {
            tail.push_back(prefix.substr(slash == std::string::npos ? 0 : 1));
            prefix = "/";
            break;
        }
        tail.push_back(prefix.substr(slash + 1));
        prefix.erase(slash);
    }

    std::string canonical_prefix;
    if (prefix == "/") {
        canonical_prefix = "/";
    } else {
        char buf[PATH_MAX];
        if (!realpath(prefix.c_str(), buf))
            throw policy_error(errno_message("cannot resolve ancestor of " + path, errno));
        canonical_prefix = buf;
    }

    std::string result = canonical_prefix;
    for (auto it = tail.rbegin(); it != tail.rend(); ++it) {
        const std::string& comp = *it;
        if (comp.empty() || comp == "." || comp == "..")
            throw policy_error("path component rejected in " + path +
                               " ('..' is not allowed below the resolved prefix)");
        if (result != "/") result += '/';
        result += comp;
    }
    return result;
}

std::vector<std::string> security_policy::canonicalize_list(const json& arr,
                                                            const char* field,
                                                            bool must_exist) {
    std::vector<std::string> out;
    if (arr.is_null()) return out;
    if (!arr.is_array())
        throw policy_error(std::string("config field '") + field + "' must be an array");
    for (const auto& item : arr) {
        if (!item.is_string())
            throw policy_error(std::string("config field '") + field + "' entries must be strings");
        std::string p = item.get<std::string>();
        require_absolute(p, field);
        if (must_exist) {
            out.push_back(canonicalize_existing(p));
        } else {
            struct stat st;
            if (lstat(p.c_str(), &st) == 0)
                out.push_back(canonicalize_existing(p));
            else
                out.push_back(p); // keep lexical deny entry for not-yet-existing paths
        }
    }
    return out;
}

security_policy security_policy::from_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw policy_error("cannot open config file: " + path);
    std::stringstream ss;
    ss << in.rdbuf();
    json j;
    try {
        j = json::parse(ss.str());
    } catch (const std::exception& e) {
        throw policy_error("invalid JSON in config " + path + ": " + e.what());
    }
    return from_json(j);
}

security_policy security_policy::from_json(const json& j) {
    security_policy p;
    if (!j.is_object()) throw policy_error("config root must be a JSON object");

    p.mode_ = parse_mode(j.value("mode", std::string("readonly")));

    if (j.contains("listen") && j["listen"].is_object()) {
        p.listen_.host = j["listen"].value("host", std::string("127.0.0.1"));
        p.listen_.port = j["listen"].value("port", 9898);
        if (p.listen_.port <= 0 || p.listen_.port > 65535)
            throw policy_error("listen.port out of range");
    }
    if (j.contains("server") && j["server"].is_object()) {
        p.server_name_ = j["server"].value("name", p.server_name_);
        p.server_version_ = j["server"].value("version", p.server_version_);
    }

    p.allow_read_ = canonicalize_list(j.value("allow_read", json()), "allow_read", true);
    p.allow_write_ = canonicalize_list(j.value("allow_write", json()), "allow_write", true);
    p.deny_ = canonicalize_list(j.value("deny", json()), "deny", false);
    p.allow_exec_ = canonicalize_list(j.value("allow_exec", json()), "allow_exec", true);

    p.allow_shell_script_ = j.value("allow_shell_script", false);
    p.enable_delete_ = j.value("enable_delete", false);

    auto get_u64 = [&](const char* name, uint64_t def, uint64_t min_v, uint64_t max_v) {
        uint64_t v = j.value(name, def);
        if (v < min_v) v = min_v;
        if (v > max_v) v = max_v;
        return v;
    };
    p.max_read_bytes_ = get_u64("max_read_bytes", 1u << 20, 1, 1ull << 40);
    p.max_write_bytes_ = get_u64("max_write_bytes", 1u << 20, 1, 1ull << 40);
    p.exec_timeout_ms_ = get_u64("exec_timeout_ms", 30000, 100, 3600000);
    p.max_output_bytes_ = get_u64("max_output_bytes", 1u << 20, 64, 1ull << 40);
    uint64_t conc = get_u64("max_concurrent_exec", 4, 1, 256);
    p.max_concurrent_exec_ = static_cast<unsigned>(conc);

    p.audit_ = j.value("audit", true);
    p.audit_file_ = j.value("audit_file", std::string());
    return p;
}

bool security_policy::tool_permitted(const std::string& tool) const {
    static const std::vector<std::string> kReadonlyTools = {
        "fs_list", "fs_read", "fs_stat", "fs_search",
        "sys_info", "sys_memory", "sys_cpu", "sys_mounts", "sys_processes"};
    bool is_readonly_tool = false;
    for (const auto& t : kReadonlyTools)
        if (t == tool) { is_readonly_tool = true; break; }

    if (mode_ == server_mode::readonly_mode)
        return is_readonly_tool;

    if (tool == "fs_remove" && !enable_delete_) return false;
    if (tool == "shell_script_exec" && !allow_shell_script_) return false;
    return true; // controlled / admin: everything else permitted per config
}

void security_policy::check_not_denied(const std::string& canonical) const {
    for (const auto& d : deny_) {
        if (is_under(canonical, d))
            throw policy_error("path is under denied prefix " + d + ": " + canonical);
    }
}

authorized_path security_policy::make_authorized(const std::string& canonical,
                                                 const std::vector<std::string>& roots,
                                                 const char* op) const {
    check_not_denied(canonical);
    for (const auto& r : roots) {
        if (!is_under(canonical, r)) continue;
        authorized_path ap;
        ap.root = r;
        ap.canonical = canonical;
        if (r == "/") {
            ap.rel = canonical == "/" ? "." : canonical.substr(1);
        } else if (canonical == r) {
            ap.rel = ".";
        } else {
            ap.rel = canonical.substr(r.size() + 1);
        }
        // O_PATH fds are valid dirfd arguments for openat/fstatat/mkdirat/
        // unlinkat/renameat while being unusable for I/O themselves.
        ap.rootfd = open(r.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (ap.rootfd < 0)
            throw policy_error(errno_message("cannot open authorized root " + r, errno));
        return ap;
    }
    throw policy_error(std::string("path not authorized for ") + op + ": " + canonical);
}

authorized_path security_policy::authorize_read(const std::string& path) const {
    std::string canonical = canonicalize_existing(path);
    return make_authorized(canonical, allow_read_, "read");
}

authorized_path security_policy::authorize_write(const std::string& path) const {
    if (mode_ == server_mode::readonly_mode)
        throw policy_error("write access denied in readonly mode: " + path);
    std::string canonical = canonicalize_for_create(path);
    return make_authorized(canonical, allow_write_, "write");
}

authorized_path security_policy::authorize_nofollow(const std::string& path,
                                                    const std::vector<std::string>& roots,
                                                    const char* op, bool write) const {
    require_absolute(path, "path");
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) {
        if (!write)
            throw policy_error(errno_message("cannot stat path " + path, errno));
        return make_authorized(canonicalize_for_create(path), roots, op); // new file
    }
    if (!S_ISLNK(st.st_mode)) {
        // Regular existing path: full canonicalization is safe.
        return make_authorized(canonicalize_existing(path), roots, op);
    }
    // Final component is a symlink: authorize the parent (fully resolved)
    // and keep the link itself as the final relative component.
    std::string parent = "/";
    std::string base = path;
    size_t slash = path.find_last_of('/');
    if (slash == 0) {
        base = path.substr(1);
    } else {
        parent = path.substr(0, slash);
        base = path.substr(slash + 1);
    }
    if (base.empty() || base == "." || base == "..")
        throw policy_error("invalid final path component in " + path);
    authorized_path ap = make_authorized(canonicalize_existing(parent), roots, op);
    ap.rel = ap.rel == "." ? base : ap.rel + "/" + base;
    ap.canonical = ap.canonical == "/" ? "/" + base : ap.canonical + "/" + base;
    check_not_denied(ap.canonical);
    return ap;
}

authorized_path security_policy::authorize_read_nofollow(const std::string& path) const {
    return authorize_nofollow(path, allow_read_, "read", false);
}

authorized_path security_policy::authorize_write_nofollow(const std::string& path) const {
    if (mode_ == server_mode::readonly_mode)
        throw policy_error("write access denied in readonly mode: " + path);
    return authorize_nofollow(path, allow_write_, "write", true);
}

std::string security_policy::authorize_exec(const std::string& argv0) const {
    if (mode_ == server_mode::readonly_mode)
        throw policy_error("command execution denied in readonly mode");
    require_absolute(argv0, "executable");
    std::string canonical = canonicalize_existing(argv0);

    if (mode_ == server_mode::admin && allow_exec_.empty()) {
        // Documented high-privilege behaviour: admin with an empty
        // allow_exec list may execute any resolvable executable.
        if (access(canonical.c_str(), X_OK) != 0)
            throw policy_error(errno_message("program is not executable: " + canonical, errno));
        return canonical;
    }
    for (const auto& e : allow_exec_)
        if (canonical == e) return canonical;
    throw policy_error("program not in allow_exec list: " + canonical);
}

void security_policy::check_deletable(const authorized_path& p) const {
    if (p.rel == ".")
        throw policy_error("refusing to delete an authorized root itself: " + p.canonical);
    for (const char* prot : kHardProtectedExact)
        if (p.canonical == prot)
            throw policy_error(std::string("protected system path: ") + prot);
    for (const char* prot : kHardProtectedSubtree)
        if (is_under(p.canonical, prot))
            throw policy_error(std::string("protected system subtree: ") + prot);
    // /etc is protected unless the config explicitly grants a write root at
    // or beneath /etc (a blanket "/" grant is not enough).
    if (is_under(p.canonical, "/etc")) {
        bool explicit_etc = false;
        for (const auto& r : allow_write_)
            if (is_under(r, "/etc")) { explicit_etc = true; break; }
        if (!explicit_etc)
            throw policy_error("protected system subtree: /etc");
    }
}

void security_policy::check_movable(const authorized_path& src,
                                    const authorized_path& dst) const {
    if (src.rel == "." || dst.rel == ".")
        throw policy_error("refusing to move an authorized root itself");
    check_deletable(src); // moving away is equivalent to deleting the source
    // The destination must not land in a protected location either.
    for (const char* prot : kHardProtectedExact)
        if (dst.canonical == prot)
            throw policy_error(std::string("protected system path: ") + prot);
    for (const char* prot : kHardProtectedSubtree)
        if (is_under(dst.canonical, prot))
            throw policy_error(std::string("protected system subtree: ") + prot);
    if (is_under(dst.canonical, "/etc")) {
        bool explicit_etc = false;
        for (const auto& r : allow_write_)
            if (is_under(r, "/etc")) { explicit_etc = true; break; }
        if (!explicit_etc)
            throw policy_error("protected system subtree: /etc");
    }
}

} // namespace rootfs_mcp
