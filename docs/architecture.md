# rootfs-mcp 架构说明

## 分层

```
MCP client (Streamable HTTP, POST/GET/DELETE /rootfs)
        |
+-------------------------------+   复用 vendored cpp-mcp
|  transport + JSON-RPC 层       |   mcp::server (third_party/cpp-mcp/src/rootfs_server.cpp)
|  (会话、initialize、tools/*)    |
+-------------------------------+
        |
+-------------------------------+   src/rootfs/tool_registry.cpp
|  tool_registry                 |   15 个工具的参数解析、模式门控、
|                                |   结果包装（content[]/isError）
+-------------------------------+
        |
+-------+--------+-----------+-----------+
| fs_service     | exec_service | sys_service |   业务层，相互独立
| src/fs/        | src/exec/    | src/sys/    |
+----------------+--------------+-------------+
        |                |
+-------------------------------+   安全策略层
| security_policy                |   src/security/：配置加载、路径授权、
|                                |   模式门控、受保护路径
+-------------------------------+
        |
+-------------------------------+   src/util/secure_open.cpp
| secure_open (openat2/openat)   |   dirfd 相对打开，禁止符号链接逃逸
+-------------------------------+
        |
+-------------------------------+   src/util/audit_log.cpp
| audit_log (stderr/文件)         |
+-------------------------------+
```

层间依赖单向向下：MCP 协议/传输层完全来自 cpp-mcp，本项目不重实现
JSON-RPC 分帧；业务层不感知 HTTP；安全策略层不感知业务语义。

## 关键设计

### 路径授权（security_policy）

1. 存在路径：`realpath()` 全量解析（符号链接、`..` 一并消解）。
2. 不存在路径（写目标）：剥离尾部组件直到找到存在的最近祖先，
   `realpath()` 祖先后逐个拼接剩余组件；剩余组件中出现 `..`/`.` 直接拒绝。
3. 判定顺序：先 `deny`（前缀最高优先），再要求落在
   `allow_read`/`allow_write` 的组件感知前缀内。默认拒绝。
4. 授权结果携带被命中根的 `O_PATH` dirfd + 相对路径，之后的所有 I/O
   （`openat`/`fstatat`/`mkdirat`/`unlinkat`/`renameat`）都以 dirfd
   为基准，避免 TOCTOU 换目录逃逸。
5. `fs_stat`/`fs_remove`/`fs_move` 使用 no-follow 变体：最终组件是符号
   链接时不解析（操作链接本身），中间组件始终解析。

### 安全打开（secure_open）

- 内核支持 `openat2()`（运行时用一次系统调用探测缓存）时：
  `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`，
  由内核在解析期保证不逃逸、不跟随任何符号链接。
- 不支持时回退：逐段 `openat(O_PATH|O_NOFOLLOW)` + `fstat` 校验中间
  组件必须是真实目录，最终组件加 `O_NOFOLLOW`，打开后再用
  `/proc/self/fd/<fd>` 与授权时的 canonical 路径交叉比对，不一致即
  ELOOP 失败（检测竞态换链）。
- 读打开总是带 `O_NONBLOCK`：`fstat` 之前 FIFO 不会阻塞；判定为非普通
  文件（FIFO/块/字符设备/socket/目录）立即报错关闭。

### 命令执行（exec_service）

- `fork` + `execve`，argv 直接传递，默认不经过 `/bin/sh`。
- 子进程 `setsid()` 成为新进程组组长；超时先 `kill(-pgid, SIGTERM)`，
  1 秒后 `SIGKILL` —— 整个进程组（含孙进程）都被清理。
- stdout/stderr 各一根管道，`O_NONBLOCK` + `poll()` 同时排空，子进程
  不会因管道写满死锁；输出超过上限继续丢弃读取并置 `truncated=true`。
- 第三根带 `O_CLOEXEC` 的错误管道：子进程 execve 失败时写入 errno 说明
  后 `_exit(127)`；父端读到数据即判定 spawn 失败（`spawn_ok=false`），
  与命令非零退出严格区分。
- 直接子进程已退出但管道仍被孙进程持有：300ms 宽限后 `SIGKILL` 进程组
  释放管道，绝不无限等待；墙钟超时是最终兜底。
- 环境变量白名单（PATH/HOME/LANG/LC_*/TERM/TMPDIR/TZ），默认最小集合；
  用户传入的变量仅白名单内的名字会被传递。
- 并发闸门：POSIX 计数信号量 `max_concurrent_exec`，满时立即报错而非排队。

### 审计

写、删、移动、命令执行记录：`时间 session op target result detail`，
输出到 stderr 或 `audit_file`。不记录任何凭据。

### 权限模式

- `readonly`（默认）：仅 fs_list/fs_read/fs_stat/fs_search + sys_*。
- `controlled`：写/删/移动/执行按配置逐项开放；`fs_remove` 还需
  `enable_delete=true`，`shell_script_exec` 还需 `allow_shell_script=true`。
- `admin`：全部工具；`allow_exec` 为空列表时允许执行任意可解析的
  可执行文件（文档化的高权限行为）。
- 硬保护：`/`、`/proc`、`/sys`、`/dev`、`/boot` 子树以及（未被显式
  授权的）`/etc` 子树禁止删除/移动，与配置无关。授权根本身禁止删除。

V1.0 的高权限模式只提供配置钩子与说明：真正的隔离应配合独立进程、
降权（setuid/capabilities）、挂载命名空间等 OS 级机制，本服务不把
黑名单或提示词约束当作安全边界。
