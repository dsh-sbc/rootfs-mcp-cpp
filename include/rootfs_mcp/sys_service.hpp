#pragma once

#include <string>

#include "rootfs_mcp/util.hpp"

namespace rootfs_mcp {

// Read-only system information tools. All functions tolerate missing or
// unreadable /proc entries and return partial results instead of failing.
class sys_service {
public:
    json info();                  // uname: kernel, arch, hostname
    json memory();                // /proc/meminfo
    json cpu();                   // /proc/cpuinfo + sysconf
    json mounts();                // /proc/mounts
    json processes(uint64_t max_count); // /proc/[0-9]* scan
};

} // namespace rootfs_mcp
