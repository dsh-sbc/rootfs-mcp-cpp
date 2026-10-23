# rootfs-mcp — RootFS MCP Server

[中文说明](README_CN.md)

An MCP (Model Context Protocol) server over **Streamable HTTP** (MCP
2025-03-26, single `/rootfs` endpoint, POST/GET/DELETE) that exposes Linux
filesystem tools, controlled command execution, and system information to
MCP clients / AI agents. Targets x86_64 (native, tested) and riscv64
(cross-compiled, Xuantie C908 / K230 toolchain).

The MCP protocol and Streamable HTTP transport are reused from the cpp-mcp
library, vendored under `third_party/cpp-mcp` (MIT license, see
`third_party/cpp-mcp/LICENSE`); this project implements the security policy
layer, the filesystem/exec/sys service layers, the tool registry, and the
application entry point.

## Tools (15)

| Tool | Function |
|---|---|
| `fs_list` | List directory entries (name/type/size/mode/mtime/symlink) |
| `fs_read` | Chunked file read (offset/length, has_more, base64 for binary) |
| `fs_write` | Create/overwrite/offset write, base64 input, mode bits |
| `fs_stat` | File attributes without reading the file |
| `fs_mkdir` | Create directory (recursive option) |
| `fs_remove` | Delete file/dir (disabled unless `enable_delete=true`) |
| `fs_move` | Rename/move (same filesystem) |
| `fs_search` | Name (glob/substring) or content search; depth/count/time limited |
| `shell_exec` | fork+execve with argv directly (no shell), timeout, caps |
| `shell_script_exec` | `/bin/sh -c` script (requires `allow_shell_script=true`) |
| `sys_info` | uname: kernel, architecture, hostname |
| `sys_memory` | /proc/meminfo statistics |
| `sys_cpu` | CPU arch, core count, cpuinfo summary (x86/RISC-V aware) |
| `sys_mounts` | /proc/mounts table |
| `sys_processes` | /proc process scan (pid/name/state/ppid/rss) |

## Build

```bash
# native x86_64
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
(cd build && ctest --output-on-failure)

# cross riscv64 (Xuantie C908 toolchain, tests forced OFF)
cmake -S . -B build-riscv64 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-riscv64.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build-riscv64 -j

# deploy to target board via scp (builds first, then copies the ELF and
# default config; override with -DSCP_HOST/-DSCP_PORT/-DSCP_USER/-DSCP_PATH)
cmake --build build-riscv64 --target cp
# or: (cd build-riscv64 && make cp)
# defaults: root@192.168.0.113:/root, port 2222
```

## Run

```bash
./build/rootfs-mcp config/rootfs-mcp.json   # or a path of your choice
# config resolution: argv[1] | $ROOTFS_MCP_CONFIG | ./config/rootfs-mcp.json | /etc/rootfs-mcp/rootfs-mcp.json
```

The server listens on `http://<listen.host>:<listen.port>/rootfs`. Logs and the
audit trail go to stderr or `audit_file` — never into the HTTP response
channel. SIGINT/SIGTERM stop the server gracefully.

## Security model (summary)

- Modes: `readonly` (default) / `controlled` / `admin`.
- Path authorization: deny list first, then component-aware prefix match
  against canonicalized `allow_read`/`allow_write` roots; `..` escapes and
  symlink escapes rejected; all I/O is performed dirfd-relative
  (`openat`/`openat2` with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS` when the
  kernel supports it, component-wise `O_NOFOLLOW` walk otherwise).
- Special files (devices/FIFO/socket) are never read or written as regular
  files; FIFO reads fail fast instead of blocking.
- `/`, `/proc`, `/sys`, `/dev`, `/boot` (and `/etc` unless explicitly
  granted) are hard-protected against delete/move regardless of config.
- Command execution: allow_exec list (admin mode with an empty list permits
  any executable), argv passed directly to execve (no shell), wall-clock
  timeout kills the whole process group, output/timeout/concurrency caps,
  whitelist-filtered environment.
- Audit log for writes, deletes, moves and executions (time, session id,
  operation, target, result).

See `docs/architecture.md`, `docs/configuration.md`,
`docs/mcp-client-example.md` and `docs/verification.md`.

## Install

```bash
sudo ./scripts/install.sh [PREFIX]   # default /usr/local
```

Installs the binary, `/etc/rootfs-mcp/rootfs-mcp.json`, and a systemd unit
example when systemd is present.

## License

See `LICENSE` in this repository (MIT). The vendored cpp-mcp library retains
its own MIT license at `third_party/cpp-mcp/LICENSE`.
