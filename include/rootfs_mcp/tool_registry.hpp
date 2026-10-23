#pragma once

#include <memory>
#include <string>

#include "mcp_server.h"

#include "rootfs_mcp/security_policy.hpp"
#include "rootfs_mcp/fs_service.hpp"
#include "rootfs_mcp/exec_service.hpp"
#include "rootfs_mcp/sys_service.hpp"
#include "rootfs_mcp/audit_log.hpp"

namespace rootfs_mcp {

// Registers all 15 rootfs-mcp tools on an mcp::server and wires them to the
// service layer. Business errors are thrown as mcp::mcp_exception so the
// transport surfaces them as tool errors (isError=true) — never as fake
// success results.
class tool_registry {
public:
    tool_registry(mcp::server& srv, const security_policy& policy,
                  fs_service& fs, exec_service& exec, sys_service& sys,
                  audit_log& audit);

    void register_all();

private:
    mcp::server& srv_;
    const security_policy& policy_;
    fs_service& fs_;
    exec_service& exec_;
    sys_service& sys_;
    audit_log& audit_;
};

} // namespace rootfs_mcp
