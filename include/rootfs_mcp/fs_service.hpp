#pragma once

#include <string>

#include "rootfs_mcp/security_policy.hpp"
#include "rootfs_mcp/audit_log.hpp"

namespace rootfs_mcp {

// Filesystem business-logic layer. Every method validates its arguments,
// authorizes the path through the security policy, performs the operation
// dirfd-relative, and returns a JSON result object. Errors are reported by
// throwing policy_error (authorization) or std::runtime_error (I/O) — never
// by a fake success result.
class fs_service {
public:
    fs_service(const security_policy& policy, audit_log& audit)
        : policy_(policy), audit_(audit) {}

    json list(const json& args, const std::string& session);
    json read(const json& args, const std::string& session);
    json write(const json& args, const std::string& session);
    json stat(const json& args, const std::string& session);
    json mkdir(const json& args, const std::string& session);
    json remove(const json& args, const std::string& session);
    json move(const json& args, const std::string& session);
    json search(const json& args, const std::string& session);

private:
    const security_policy& policy_;
    audit_log& audit_;
};

} // namespace rootfs_mcp
