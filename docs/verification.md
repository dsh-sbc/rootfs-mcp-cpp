# rootfs-mcp 验证记录（docs/verification.md）

验证日期：2026-10-22。主机：x86_64 Linux 6.8.0-111-generic (Ubuntu 22.04)，
gcc（原生）+ Xuantie-900 riscv64 gcc 14.1.1（交叉）。

## 1. 原生 x86_64 构建

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j12
```

结果：成功，退出码 0；项目自有源码（rootfs_mcp_core、rootfs-mcp、tests）
在 `-Wall -Wextra` 下零告警零错误。构建日志尾部：

```
[100%] Built target test_exec
[100%] Built target rootfs-mcp
[100%] Built target test_fs
[100%] Built target test_security
native build exit=0
```

## 2. 原生测试（ctest，每个用例 TIMEOUT 60s）

```
cd build && ctest --output-on-failure
```

```
1/4 Test #1: test_protocol ....................   Passed    0.01 sec
2/4 Test #2: test_fs ..........................   Passed    0.00 sec
3/4 Test #3: test_exec ........................   Passed    3.17 sec
4/4 Test #4: test_security ....................   Passed    0.00 sec
100% tests passed, 0 tests failed out of 4
```

共 66 个 gtest 用例（test_protocol 12 / test_fs 28 / test_exec 13 /
test_security 13），全部通过。覆盖 SRS §7 可在主机验证的验收项：

- 协议：initialize 握手、tools/list 返回 15 个工具、tools/call 调用、
  无效参数 → isError=true、未知工具 → -32602、未知方法 → -32601、
  无效 JSON → HTTP 400、缺会话头 → 400、未 initialized 的会话 →
  -32600、DELETE 终止会话（之后 POST → 404）、GET 缺会话头 → 400、
  连续 10 条顺序 POST 边界不错乱（每条响应 id 与请求一致）。
- 文件：列目录（含隐藏文件开关、max_entries 截断）、小文件读、大文件
  分段读（has_more）、二进制 base64 往返、max_read_bytes 截断、创建/
  覆盖/偏移写、base64 写、mode 位、超 max_write_bytes 拒绝、stat（含
  symlink 本体）、mkdir 递归、非空目录非递归删除失败、递归删除不跟随
  符号链接、删除授权根本身拒绝、move、`..` 逃逸拒绝、符号链接逃逸
  拒绝（读/写）、deny 优先级、FIFO 读取快速失败（< 2s 实测 < 1ms）、
  写特殊文件拒绝、搜索 name/content、深度/数量上限、不跟随符号链接。
- 执行：stdout/stderr/退出码、非零退出不伪报成功、超时 SIGTERM→SIGKILL
  进程组（用唯一标记符号链接验证无残留进程）、输出截断
  truncated=true、程序不存在 → 明确独立错误、execve 失败经错误管道
  报告 spawn 失败、未授权程序拒绝、readonly 拒绝执行、env 白名单过滤、
  cwd 授权校验、孙进程持有管道不永久阻塞（351ms 返回）、并发闸门
  （max_concurrent_exec=1 时第二个执行立即失败）。
- 安全：模式解析、组件感知前缀匹配、deny 优先、`..` 拒绝、symlink
  逃逸拒绝、模式门控、enable_delete/allow_shell_script 门控、
  allow_exec 校验、admin 空列表行为、受保护系统路径（/、/proc、/sys、
  /dev、/etc）、open_beneath 拒绝符号链接组件、openat2 探测。

## 3. 端到端冒烟测试（真实二进制 + curl）

配置：controlled 模式，allow_read=["/"]，
allow_write=["/tmp/rootfs-mcp-smoke"]，allow_exec=["/bin/echo",
"/bin/uname"]，审计到文件。启动：

```
$ ./build/rootfs-mcp /tmp/rootfs-mcp-smoke/smoke-config.json
rootfs-mcp: listening on http://127.0.0.1:18099/rootfs (mode=controlled, openat2=yes)
```

完整报文交换（截取）：

```
## initialize response body
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":null,
 "serverInfo":{"name":"rootfs-mcp","version":"1.0.0"},"instructions":"RootFS MCP Server: ..."}}
## Mcp-Session-Id: 604ea251-0c25-5477-fce2-8ba702c4f6b3
## notifications/initialized -> HTTP 202
## tools/list (names)
15 tools: fs_list, fs_mkdir, fs_move, fs_read, fs_remove, fs_search, fs_stat, fs_write,
          shell_exec, shell_script_exec, sys_cpu, sys_info, sys_memory, sys_mounts, sys_processes
## tools/call fs_read
{"jsonrpc":"2.0","id":3,"result":{"isError":false,"content":[{"type":"text","text":
 "{\n  \"path\": \"/tmp/rootfs-mcp-smoke/data.txt\",\n  \"offset\": 0,\n  \"length\": 11,\n
   \"size\": 11,\n  \"has_more\": false,\n  \"encoding\": \"utf-8\",\n  \"content\": \"smoke data\\n\"\n}"}]}}
## tools/call fs_write (authorized)
{"jsonrpc":"2.0","id":4,"result":{"isError":false,"content":[{"type":"text","text":
 "{\n  \"path\": \"/tmp/rootfs-mcp-smoke/written2.txt\",\n  \"bytes_written\": 8, ...\n}"}]}}
## tools/call shell_exec /bin/uname -m
{"jsonrpc":"2.0","id":5,"result":{"isError":false,"content":[{"type":"text","text":
 "{\n  \"spawn_ok\": true,\n  \"exit_code\": 0,\n  ... \"stdout\": \"x86_64\\n\", ...\n}"}]}}
## tools/call sys_memory -> total_bytes=33470459904, available_bytes=25870520320, ...
## unauthorized fs_write to /etc -> isError
{"jsonrpc":"2.0","id":7,"result":{"isError":true,"content":[{"type":"text",
 "text":"path not authorized for write: /etc/pwned"}]}}
## unknown tool -> JSON-RPC error
{"jsonrpc":"2.0","id":8,"error":{"code":-32602,"message":"Tool not found: nope"}}
## DELETE session -> HTTP 200
## audit log
2026-10-22T11:22:53Z audit session=604ea251-... op=fs_write target=/tmp/rootfs-mcp-smoke/written2.txt result=ok detail=bytes=8
2026-10-22T11:22:53Z audit session=604ea251-... op=shell_exec target=/bin/uname -m result=ok detail=exit=0
2026-10-22T11:22:53Z audit session=604ea251-... op=fs_write target=/etc/pwned result=fail detail=path not authorized for write: /etc/pwned
```

日志（cpp-mcp logger + rootfs-mcp）只写 stderr，HTTP 响应体中无日志
污染（见上述响应，均为纯 JSON）。SIGTERM 优雅停机实测：

```
exit=0
2026-10-22 19:24:07 [INFO] MCP server stopped
rootfs-mcp: stopped
```

## 4. riscv64 交叉编译

```
cmake -S . -B build-riscv64 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-riscv64.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build-riscv64 -j12
```

结果：成功，退出码 0（测试自动禁用：CMAKE_CROSSCOMPILING 时
ROOTFS_MCP_BUILD_TESTS 被 FORCE OFF）。仅有的 21 条告警全部来自上级
仓库 cpp-mcp/httplib 源码在工具链更严格 flags（-Wshadow/-Wundef）下的
既有告警，本项目源码零告警。

ELF 检查：

```
$ file build-riscv64/rootfs-mcp
ELF 64-bit LSB pie executable, UCB RISC-V, RVC, double-float ABI, version 1 (GNU/Linux),
dynamically linked, interpreter /lib/ld-linux-riscv64-lp64d.so.1, for GNU/Linux 4.15.0, not stripped
$ readelf -h:  Class: ELF64   Type: DYN   Machine: RISC-V
$ readelf -d NEEDED:
  libpthread.so.0 libatomic.so.1 libstdc++.so.6 libm.so.6 libgcc_s.so.1 libc.so.6
  ld-linux-riscv64-lp64d.so.1
```

**riscv64 运行时：未验证。** 本机无目标设备且无 qemu-riscv64
（`which qemu-riscv64` → 不存在），交叉产物未在任何 riscv64 环境执行。
主机编译成功不等于目标设备运行成功（SRS §9）。

## 5. 功能状态表（SRS §9 验收标注）

| 功能 | 状态 |
|---|---|
| Streamable HTTP 传输（/rootfs POST/GET/DELETE，Mcp-Session-Id） | 已实现并验证（复用 cpp-mcp） |
| initialize / notifications/initialized / ping / tools/list / tools/call | 已实现并验证 |
| fs_list / fs_read / fs_stat / fs_search | 已实现并验证（x86_64） |
| fs_write / fs_mkdir / fs_remove / fs_move | 已实现并验证（x86_64） |
| 大文件分段读 / base64 二进制 / has_more | 已实现并验证 |
| shell_exec（argv 直传、无 shell、超时杀进程组、输出截断、并发闸门、env 白名单、错误管道区分 spawn 失败） | 已实现并验证 |
| shell_script_exec（默认禁用，独立开关） | 已实现并验证（门控路径；启用路径走同一执行引擎） |
| sys_info / sys_memory / sys_cpu / sys_mounts / sys_processes | 已实现并验证（x86_64）；RISC-V cpuinfo 字段缺失的兼容为防御性编码，未在 riscv64 实机验证 |
| 路径授权（deny 优先、canonical 前缀、dirfd 相对操作） | 已实现并验证 |
| openat2(RESOLVE_BENEATH\|NO_SYMLINKS\|NO_MAGICLINKS) + openat/O_NOFOLLOW 回退 | 已实现并验证（本机内核支持 openat2；回退路径经单测覆盖） |
| 特殊文件拒绝（设备/FIFO/socket）、FIFO 快速失败 | 已实现并验证 |
| 受保护系统目录删除/移动保护、授权根保护 | 已实现并验证 |
| readonly/controlled/admin 三模式 | 已实现并验证 |
| 审计日志（时间/session/op/target/result，stderr 或文件） | 已实现并验证 |
| 资源限制（读写大小、超时、输出、深度/数量/时间、并发） | 已实现并验证 |
| x86_64 原生构建 + 测试 | 已实现并验证 |
| riscv64 交叉编译 + ELF 检查 | 已实现并验证（编译）；**运行时未验证**（无设备/qemu） |
| systemd unit / install.sh | 已实现但未验证（未在本机执行安装） |
| GET /rootfs SSE 服务端推送流 | 已实现（cpp-mcp 提供）但未验证业务用途——本服务无主动推送场景，仅验证缺失会话头返回 400 |

## 6. 已知限制

1. `fs_move` 仅支持同一文件系统（renameat 跨设备返回 EXDEV 错误，不做
   复制回退）。
2. `fs_search` 内容搜索跳过 >32MB 文件与二进制文件；匹配为子串匹配
   （name 模式在含 `*?[` 时用 fnmatch glob）。
3. openat2 不可用的内核上回退为逐段 openat+O_NOFOLLOW+fstat+fd 路径
   交叉校验；mkdir/rename/unlink 等 dirfd 相对操作对中间目录的 TOCTOU
   防护依赖授权时的 canonical 校验，弱于 openat2 的内核级保证。
4. admin 模式 + 空 allow_exec 列表 = 任意可执行文件（文档化的高权限
   行为）。高权限模式的 OS 级隔离（降权/capabilities/挂载命名空间）
   V1.0 仅提供配置钩子与说明，未内置实现。
5. 无认证/TLS 层；默认监听 127.0.0.1，远程暴露需自行加前置防护。
6. 服务以非 root 运行为推荐前提（systemd unit 示例含 ProtectSystem 等
   加固项）；需要写系统目录时再由配置显式授权并承担相应风险。
7. **同端口多实例会破坏会话亲和性**：cpp-httplib 监听 socket 默认设置
   SO_REUSEPORT（third_party/cpp-mcp/common/httplib.h:2122），第二个实例绑定同一端口不会失败，
   内核会在多个监听 socket 间负载均衡连接。由于 MCP 会话状态保存在单实例
   内存中，后续请求被分发到另一实例时会得到 404 "Session not found"。
   部署时必须保证同一 host:port 只有一个实例在运行（systemd unit 已满足；
   手工启动前可用 `ss -tlnp | grep <port>` 检查端口占用）。
