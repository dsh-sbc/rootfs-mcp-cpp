#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "rootfs_mcp/util.hpp"

namespace rootfs_mcp {

enum class server_mode { readonly_mode, controlled, admin };

server_mode parse_mode(const std::string& s); // throws policy_error on unknown
std::string mode_to_string(server_mode m);

class policy_error : public std::runtime_error {
public:
    explicit policy_error(const std::string& msg) : std::runtime_error(msg) {}
};

// Result of a successful path authorization: an owned O_PATH fd of the
// matched authorized root plus the path relative to it. All filesystem
// operations are then performed dirfd-relative so a renamed/swapped
// intermediate directory cannot redirect the operation outside the root.
struct authorized_path {
    int rootfd = -1;      // owned; O_PATH | O_DIRECTORY | O_CLOEXEC
    std::string rel;      // path relative to rootfd ("." when equal)
    std::string canonical; // absolute canonical path (symlinks resolved)
    std::string root;     // matched allow-root (canonical)

    authorized_path() = default;
    ~authorized_path();
    authorized_path(authorized_path&& o) noexcept;
    authorized_path& operator=(authorized_path&& o) noexcept;
    authorized_path(const authorized_path&) = delete;
    authorized_path& operator=(const authorized_path&) = delete;

    void reset();
};

struct listen_config {
    std::string host = "127.0.0.1";
    int port = 9898;
};

class security_policy {
public:
    // Load and validate from a JSON config file. Throws policy_error on
    // unreadable/invalid config.
    static security_policy from_file(const std::string& path);
    // Build from an already-parsed JSON object (used by tests).
    static security_policy from_json(const json& j);

    server_mode mode() const { return mode_; }
    bool allow_shell_script() const { return allow_shell_script_; }
    bool enable_delete() const { return enable_delete_; }
    bool audit_enabled() const { return audit_; }
    const std::string& audit_file() const { return audit_file_; }
    uint64_t max_read_bytes() const { return max_read_bytes_; }
    uint64_t max_write_bytes() const { return max_write_bytes_; }
    uint64_t exec_timeout_ms() const { return exec_timeout_ms_; }   // hard cap
    uint64_t max_output_bytes() const { return max_output_bytes_; } // hard cap
    unsigned max_concurrent_exec() const { return max_concurrent_exec_; }
    const listen_config& listen() const { return listen_; }
    const std::string& server_name() const { return server_name_; }
    const std::string& server_version() const { return server_version_; }

    const std::vector<std::string>& allow_read() const { return allow_read_; }
    const std::vector<std::string>& allow_write() const { return allow_write_; }
    const std::vector<std::string>& deny() const { return deny_; }
    const std::vector<std::string>& allow_exec() const { return allow_exec_; }

    // Mode gating: whether `tool` may be invoked at all in this mode.
    // fs_remove additionally requires enable_delete(); shell_script_exec
    // additionally requires allow_shell_script(); both enforced here.
    bool tool_permitted(const std::string& tool_name) const;

    // Authorize `path` (must exist) for reading. Throws policy_error when
    // denied. On success returns the dirfd-relative handle.
    authorized_path authorize_read(const std::string& path) const;

    // Authorize `path` for writing; the final component may not exist yet
    // (the nearest existing ancestor is canonicalized instead).
    authorized_path authorize_write(const std::string& path) const;

    // No-follow variants: the final component is NOT resolved when it is a
    // symlink, so fs_stat can report the link itself and fs_remove/fs_move
    // operate on the link rather than its target. Intermediate components
    // are always resolved.
    authorized_path authorize_read_nofollow(const std::string& path) const;
    authorized_path authorize_write_nofollow(const std::string& path) const;

    // Authorize an executable path; returns its canonical absolute path.
    // In admin mode with an empty allow_exec list any resolvable executable
    // is permitted (documented high-privilege behaviour).
    std::string authorize_exec(const std::string& argv0) const;

    // Extra checks for destructive operations on an already-authorized path:
    // rejects hard-protected system locations and deletion of an authorized
    // root itself. Throws policy_error.
    void check_deletable(const authorized_path& p) const;
    // Both endpoints of a move must be writable and neither protected.
    void check_movable(const authorized_path& src, const authorized_path& dst) const;

    // Canonicalize an existing path via realpath(); throws policy_error.
    static std::string canonicalize_existing(const std::string& path);
    // Canonicalize a path whose final components may not exist: resolves the
    // nearest existing ancestor and appends the remaining components, which
    // must be plain names (".."/"." rejected). Throws policy_error.
    static std::string canonicalize_for_create(const std::string& path);

    // Component-aware prefix test: path == root or path is strictly beneath
    // root. root "/" contains every absolute path.
    static bool is_under(const std::string& path, const std::string& root);

private:
    server_mode mode_ = server_mode::readonly_mode;
    std::vector<std::string> allow_read_;  // canonical
    std::vector<std::string> allow_write_; // canonical
    std::vector<std::string> deny_;        // canonical where possible
    std::vector<std::string> allow_exec_;  // canonical
    bool allow_shell_script_ = false;
    bool enable_delete_ = false;
    uint64_t max_read_bytes_ = 1u << 20;
    uint64_t max_write_bytes_ = 1u << 20;
    uint64_t exec_timeout_ms_ = 30000;
    uint64_t max_output_bytes_ = 1u << 20;
    unsigned max_concurrent_exec_ = 4;
    bool audit_ = true;
    std::string audit_file_;
    listen_config listen_;
    std::string server_name_ = "rootfs-mcp";
    std::string server_version_ = "1.0.0";

    void check_not_denied(const std::string& canonical) const;
    authorized_path make_authorized(const std::string& canonical,
                                    const std::vector<std::string>& roots,
                                    const char* op) const;
    authorized_path authorize_nofollow(const std::string& path,
                                       const std::vector<std::string>& roots,
                                       const char* op, bool write) const;
    static std::vector<std::string> canonicalize_list(const json& arr,
                                                      const char* field,
                                                      bool must_exist);
};

} // namespace rootfs_mcp
