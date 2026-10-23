#include "rootfs_mcp/audit_log.hpp"

#include "rootfs_mcp/util.hpp"

#include <ctime>

namespace rootfs_mcp {

audit_log::audit_log(bool enabled, std::string file_path)
    : enabled_(enabled), file_path_(std::move(file_path)) {
    if (enabled_ && !file_path_.empty()) {
        fp_ = std::fopen(file_path_.c_str(), "a");
        if (!fp_) {
            // Fall back to stderr rather than silently dropping audit records.
            enabled_ = true;
        }
    }
}

audit_log::~audit_log() {
    if (fp_) std::fclose(fp_);
}

void audit_log::record(const std::string& session_id, const std::string& op,
                       const std::string& target, bool ok, const std::string& detail) {
    if (!enabled_) return;
    std::lock_guard<std::mutex> lock(mutex_);
    FILE* out = fp_ ? fp_ : stderr;
    std::string ts = format_time_utc(static_cast<int64_t>(std::time(nullptr)));
    std::fprintf(out, "%s audit session=%s op=%s target=%s result=%s detail=%s\n",
                 ts.c_str(), session_id.empty() ? "-" : session_id.c_str(),
                 op.c_str(), target.c_str(), ok ? "ok" : "fail", detail.c_str());
    std::fflush(out);
}

} // namespace rootfs_mcp
