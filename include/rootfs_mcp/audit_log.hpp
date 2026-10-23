#pragma once

#include <cstdio>
#include <mutex>
#include <string>

namespace rootfs_mcp {

// Append-only audit log for security-relevant operations (writes, deletes,
// moves, command executions). Destination is stderr or a configured file.
// Never receives or records credentials/secrets.
class audit_log {
public:
    audit_log(bool enabled, std::string file_path);
    ~audit_log();

    audit_log(const audit_log&) = delete;
    audit_log& operator=(const audit_log&) = delete;

    bool enabled() const { return enabled_; }

    // op:     operation name, e.g. "fs_write", "shell_exec"
    // target: path or argv rendering (already sanitized by caller)
    // ok:     whether the operation succeeded
    // detail: short error/result message (no secrets)
    void record(const std::string& session_id, const std::string& op,
                const std::string& target, bool ok, const std::string& detail);

private:
    bool enabled_ = false;
    std::string file_path_;
    FILE* fp_ = nullptr; // nullptr -> stderr
    std::mutex mutex_;
};

} // namespace rootfs_mcp
