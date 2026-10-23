#pragma once

#include <map>
#include <semaphore.h>
#include <string>
#include <vector>

#include "rootfs_mcp/security_policy.hpp"
#include "rootfs_mcp/audit_log.hpp"

namespace rootfs_mcp {

struct exec_options {
    std::vector<std::string> argv;               // argv[0] = program
    std::string cwd;                             // empty -> inherit
    uint64_t timeout_ms = 0;                     // 0 -> policy cap; clamped to cap
    uint64_t max_output_bytes = 0;               // 0 -> policy cap; clamped to cap
    std::map<std::string, std::string> env;      // whitelist-filtered
};

struct exec_result {
    bool spawn_ok = true;      // false: program could not be started at all
    std::string spawn_error;   // reason when spawn_ok == false
    int exit_code = -1;        // valid when exited normally
    int term_signal = 0;       // signal that killed the process, if any
    bool timed_out = false;
    bool truncated = false;    // output cap reached
    std::string stdout_text;
    std::string stderr_text;
    uint64_t duration_ms = 0;
};

// Controlled command execution: fork + execve with direct argv (never via a
// shell), stdout/stderr drained simultaneously through poll() on
// non-blocking pipes, wall-clock timeout enforced against the child's whole
// process group (child calls setsid), output/timeout/concurrency caps.
class exec_service {
public:
    exec_service(const security_policy& policy, audit_log& audit);
    ~exec_service();

    exec_service(const exec_service&) = delete;
    exec_service& operator=(const exec_service&) = delete;

    // skip_exec_list: used by shell_script_exec, which is gated by its own
    // policy flag instead of the allow_exec list.
    exec_result run(const exec_options& opts, const std::string& session,
                    bool skip_exec_list = false);

private:
    const security_policy& policy_;
    audit_log& audit_;
    sem_t exec_slots_;
};

// Build the filtered environment block for a child process.
// Default minimal set: PATH, HOME, LANG. User-supplied variables are only
// passed through when their names are on the whitelist.
std::vector<std::string> build_child_env(const std::map<std::string, std::string>& user_env);

} // namespace rootfs_mcp
