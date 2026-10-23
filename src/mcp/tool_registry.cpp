#include "rootfs_mcp/tool_registry.hpp"

#include <map>
#include <stdexcept>

namespace rootfs_mcp {

namespace {

mcp::json content_result(const json& r) {
    return mcp::json::array({mcp::json{{"type", "text"}, {"text", r.dump(2)}}});
}

// Extract the exec_options shared by shell_exec / shell_script_exec.
void fill_exec_common(const json& args, exec_options& opts) {
    opts.cwd = arg_string(args, "cwd", false);
    opts.timeout_ms = arg_u64(args, "timeout_ms", 0);
    opts.max_output_bytes = arg_u64(args, "max_output_bytes", 0);
    if (args.is_object() && args.contains("env") && !args["env"].is_null()) {
        if (!args["env"].is_object())
            throw std::invalid_argument("argument 'env' must be an object");
        for (auto it = args["env"].begin(); it != args["env"].end(); ++it) {
            if (!it.value().is_string())
                throw std::invalid_argument("env values must be strings");
            opts.env[it.key()] = it.value().get<std::string>();
        }
    }
}

json exec_result_json(const exec_result& r) {
    json out;
    out["spawn_ok"] = r.spawn_ok;
    if (!r.spawn_ok) out["spawn_error"] = r.spawn_error;
    out["exit_code"] = r.exit_code;
    out["term_signal"] = r.term_signal;
    out["timed_out"] = r.timed_out;
    out["truncated"] = r.truncated;
    out["stdout"] = r.stdout_text;
    out["stderr"] = r.stderr_text;
    out["duration_ms"] = r.duration_ms;
    return out;
}

} // namespace

tool_registry::tool_registry(mcp::server& srv, const security_policy& policy,
                             fs_service& fs, exec_service& exec, sys_service& sys,
                             audit_log& audit)
    : srv_(srv), policy_(policy), fs_(fs), exec_(exec), sys_(sys), audit_(audit) {}

void tool_registry::register_all() {
    // Wrap a service call: enforce mode gating, convert any failure into an
    // mcp_exception (surfaced by the transport as a tool error, never as a
    // fake success).
    // Capture references to the long-lived policy/services (never `this`):
    // handlers must stay valid even if the registry object is temporary.
    const security_policy& policy = policy_;
    fs_service& fs = fs_;
    exec_service& exec = exec_;
    sys_service& sys = sys_;
    auto wrap = [&policy](const char* name,
                          std::function<json(const json&, const std::string&)> fn) {
        return [&policy, name, fn](const mcp::json& args,
                                   const std::string& session) -> mcp::json {
            try {
                if (!policy.tool_permitted(name))
                    throw policy_error(std::string("tool '") + name +
                                       "' is not permitted (mode=" +
                                       mode_to_string(policy.mode()) + ")");
                return content_result(fn(args, session));
            } catch (const mcp::mcp_exception&) {
                throw;
            } catch (const std::exception& e) {
                throw mcp::mcp_exception(mcp::error_code::invalid_params, e.what());
            }
        };
    };

    srv_.register_tool(
        mcp::tool_builder("fs_list")
            .with_description("List entries of a directory (name, type, size, mode, mtime, symlink flag)")
            .with_string_param("path", "Absolute directory path")
            .with_number_param("max_entries", "Maximum entries to return (default 256)", false)
            .with_boolean_param("include_hidden", "Include dotfiles (default false)", false)
            .build(),
        wrap("fs_list", [&fs](const json& a, const std::string& s) { return fs.list(a, s); }));

    srv_.register_tool(
        mcp::tool_builder("fs_read")
            .with_description("Read a file with offset/length chunking; binary content is returned base64-encoded")
            .with_string_param("path", "Absolute file path")
            .with_number_param("offset", "Byte offset to start at (default 0)", false)
            .with_number_param("length", "Max bytes to read (capped by max_read_bytes)", false)
            .build(),
        wrap("fs_read", [&fs](const json& a, const std::string& s) { return fs.read(a, s); }));

    srv_.register_tool(
        mcp::tool_builder("fs_write")
            .with_description("Create/overwrite a file, or write at a byte offset; supports base64 content")
            .with_string_param("path", "Absolute file path")
            .with_string_param("content", "Content to write")
            .with_number_param("offset", "Byte offset for partial write (omit to truncate)", false)
            .with_number_param("mode", "File permission bits, e.g. 420 for 0644", false)
            .with_string_param("encoding", "'utf-8' (default) or 'base64'", false)
            .build(),
        wrap("fs_write", [&fs](const json& a, const std::string& s) { return fs.write(a, s); }));

    srv_.register_tool(
        mcp::tool_builder("fs_stat")
            .with_description("Get file/directory attributes without reading the file")
            .with_string_param("path", "Absolute path")
            .build(),
        wrap("fs_stat", [&fs](const json& a, const std::string& s) { return fs.stat(a, s); }));

    srv_.register_tool(
        mcp::tool_builder("fs_mkdir")
            .with_description("Create a directory")
            .with_string_param("path", "Absolute directory path")
            .with_number_param("mode", "Permission bits (default 0755)", false)
            .with_boolean_param("recursive", "Create missing parents (default false)", false)
            .build(),
        wrap("fs_mkdir", [&fs](const json& a, const std::string& s) { return fs.mkdir(a, s); }));

    srv_.register_tool(
        mcp::tool_builder("fs_remove")
            .with_description("Delete a file or directory (requires enable_delete=true)")
            .with_string_param("path", "Absolute path")
            .with_boolean_param("recursive", "Remove directory trees (never follows symlinks)", false)
            .build(),
        wrap("fs_remove", [&fs](const json& a, const std::string& s) { return fs.remove(a, s); }));

    srv_.register_tool(
        mcp::tool_builder("fs_move")
            .with_description("Move/rename a file or directory (same filesystem only)")
            .with_string_param("src", "Absolute source path")
            .with_string_param("dst", "Absolute destination path")
            .build(),
        wrap("fs_move", [&fs](const json& a, const std::string& s) { return fs.move(a, s); }));

    srv_.register_tool(
        mcp::tool_builder("fs_search")
            .with_description("Search file names (glob or substring) or file text beneath a directory; depth/result/time limited")
            .with_string_param("path", "Absolute directory path")
            .with_string_param("pattern", "Name glob/substring or text to find")
            .with_string_param("mode", "'name' (default) or 'content'", false)
            .with_number_param("max_results", "Result cap (default 64)", false)
            .with_number_param("max_depth", "Traversal depth cap (default 8)", false)
            .with_number_param("time_budget_ms", "Time budget (default 10000)", false)
            .build(),
        wrap("fs_search", [&fs](const json& a, const std::string& s) { return fs.search(a, s); }));

    srv_.register_tool(
        mcp::tool_builder("shell_exec")
            .with_description("Execute a program directly (no shell) with timeout, output caps and process-group cleanup")
            .with_array_param("argv", "Argument vector; argv[0] is the program (must be in allow_exec)", "string")
            .with_string_param("cwd", "Working directory (must pass read authorization)", false)
            .with_number_param("timeout_ms", "Wall-clock timeout (capped by exec_timeout_ms)", false)
            .with_number_param("max_output_bytes", "Combined stdout+stderr cap", false)
            .with_object_param("env", "Extra environment variables (whitelist-filtered)", json::object(), false)
            .build(),
        wrap("shell_exec", [&exec](const json& a, const std::string& s) {
            if (!a.is_object() || !a.contains("argv") || !a["argv"].is_array() || a["argv"].empty())
                throw std::invalid_argument("argument 'argv' must be a non-empty string array");
            exec_options opts;
            for (const auto& v : a["argv"]) {
                if (!v.is_string())
                    throw std::invalid_argument("argv entries must be strings");
                opts.argv.push_back(v.get<std::string>());
            }
            fill_exec_common(a, opts);
            return exec_result_json(exec.run(opts, s));
        }));

    srv_.register_tool(
        mcp::tool_builder("shell_script_exec")
            .with_description("Run a shell script via /bin/sh -c (requires allow_shell_script=true; not a security sandbox)")
            .with_string_param("script", "Script text executed with /bin/sh -c")
            .with_string_param("cwd", "Working directory", false)
            .with_number_param("timeout_ms", "Wall-clock timeout", false)
            .with_number_param("max_output_bytes", "Combined stdout+stderr cap", false)
            .with_object_param("env", "Extra environment variables (whitelist-filtered)", json::object(), false)
            .build(),
        wrap("shell_script_exec", [&policy, &exec](const json& a, const std::string& s) {
            std::string script = arg_string(a, "script", true);
            if (!policy.allow_shell_script())
                throw policy_error("shell_script_exec is disabled (allow_shell_script=false)");
            exec_options opts;
            opts.argv = {"/bin/sh", "-c", script};
            fill_exec_common(a, opts);
            return exec_result_json(exec.run(opts, s, /*skip_exec_list=*/true));
        }));

    srv_.register_tool(
        mcp::tool_builder("sys_info")
            .with_description("Kernel name/release/version, architecture, hostname")
            .build(),
        wrap("sys_info", [&sys](const json&, const std::string&) { return sys.info(); }));

    srv_.register_tool(
        mcp::tool_builder("sys_memory")
            .with_description("Memory statistics from /proc/meminfo (bytes)")
            .build(),
        wrap("sys_memory", [&sys](const json&, const std::string&) { return sys.memory(); }));

    srv_.register_tool(
        mcp::tool_builder("sys_cpu")
            .with_description("CPU architecture, online core count and /proc/cpuinfo summary")
            .build(),
        wrap("sys_cpu", [&sys](const json&, const std::string&) { return sys.cpu(); }));

    srv_.register_tool(
        mcp::tool_builder("sys_mounts")
            .with_description("Visible mount table from /proc/mounts")
            .build(),
        wrap("sys_mounts", [&sys](const json&, const std::string&) { return sys.mounts(); }));

    srv_.register_tool(
        mcp::tool_builder("sys_processes")
            .with_description("Process list from /proc (pid, name, state, ppid, rss)")
            .with_number_param("max_count", "Maximum processes to return (default 128)", false)
            .build(),
        wrap("sys_processes", [&sys](const json& a, const std::string&) {
            return sys.processes(arg_u64(a, "max_count", 128));
        }));
}

} // namespace rootfs_mcp
