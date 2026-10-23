// rootfs-mcp: RootFS MCP Server (Streamable HTTP transport).
//
// Usage: rootfs-mcp [config.json]
//   config path resolution order: argv[1], $ROOTFS_MCP_CONFIG,
//   ./config/rootfs-mcp.json, /etc/rootfs-mcp/rootfs-mcp.json

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "mcp_server.h"

#include "rootfs_mcp/audit_log.hpp"
#include "rootfs_mcp/exec_service.hpp"
#include "rootfs_mcp/fs_service.hpp"
#include "rootfs_mcp/security_policy.hpp"
#include "rootfs_mcp/sys_service.hpp"
#include "rootfs_mcp/tool_registry.hpp"
#include "rootfs_mcp/secure_open.hpp"

namespace {

std::atomic<bool> g_stop_requested{false};

void on_signal(int) { g_stop_requested.store(true); }

bool file_exists(const char* p) {
    FILE* f = std::fopen(p, "r");
    if (f) { std::fclose(f); return true; }
    return false;
}

std::string resolve_config_path(int argc, char** argv) {
    if (argc > 1) return argv[1];
    const char* env = std::getenv("ROOTFS_MCP_CONFIG");
    if (env && *env) return env;
    if (file_exists("config/rootfs-mcp.json")) return "config/rootfs-mcp.json";
    return "/etc/rootfs-mcp/rootfs-mcp.json";
}

void usage(const char* argv0) {
    std::fprintf(stderr,
                 "rootfs-mcp 1.0.0 — RootFS MCP Server (Streamable HTTP)\n"
                 "usage: %s [config.json]\n"
                 "  config resolution: argv[1] | $ROOTFS_MCP_CONFIG | "
                 "./config/rootfs-mcp.json | /etc/rootfs-mcp/rootfs-mcp.json\n",
                 argv0);
}

} // namespace

int main(int argc, char** argv) {
    if (argc > 1 && (!std::strcmp(argv[1], "--help") || !std::strcmp(argv[1], "-h"))) {
        usage(argv[0]);
        return 0;
    }
    if (argc > 1 && !std::strcmp(argv[1], "--version")) {
        std::fprintf(stderr, "rootfs-mcp 1.0.0 (protocol %s)\n", mcp::MCP_VERSION);
        return 0;
    }

    std::string config_path = resolve_config_path(argc, argv);
    rootfs_mcp::security_policy policy;
    try {
        policy = rootfs_mcp::security_policy::from_file(config_path);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "rootfs-mcp: %s\n", e.what());
        return 2;
    }

    rootfs_mcp::audit_log audit(policy.audit_enabled(), policy.audit_file());
    rootfs_mcp::fs_service fs(policy, audit);
    rootfs_mcp::exec_service exec(policy, audit);
    rootfs_mcp::sys_service sys;

    mcp::server::configuration conf;
    conf.host = policy.listen().host;
    conf.port = policy.listen().port;
    conf.name = policy.server_name();
    conf.version = policy.server_version();
    conf.mcp_endpoint = "/rootfs";

    mcp::server srv(conf);
    srv.set_instructions(
        "RootFS MCP Server: filesystem, command execution and system info tools. "
        "All file paths are subject to the server security policy.");
    rootfs_mcp::tool_registry registry(srv, policy, fs, exec, sys, audit);
    registry.register_all();

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::fprintf(stderr,
                 "rootfs-mcp: listening on http://%s:%d%s (mode=%s, openat2=%s)\n",
                 conf.host.c_str(), conf.port, conf.mcp_endpoint.c_str(),
                 rootfs_mcp::mode_to_string(policy.mode()).c_str(),
                 rootfs_mcp::openat2_supported() ? "yes" : "no (openat fallback)");

    // Watcher thread: signal handlers only set a flag; the actual stop() call
    // (not async-signal-safe) happens here.
    std::thread watcher([&srv] {
        while (!g_stop_requested.load()) std::this_thread::sleep_for(std::chrono::milliseconds(50));
        srv.stop();
    });

    bool ok = srv.start(true /*blocking*/);
    watcher.join();
    std::fprintf(stderr, "rootfs-mcp: stopped\n");
    return ok ? 0 : 1;
}
