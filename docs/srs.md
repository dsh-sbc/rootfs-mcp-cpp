# RootFS MCP Server 软件需求规格说明书（实施版）

> 本文件以用户提供的 SRS V1.0 为准，并包含以下已确认的修订：
>
> **修订 1（传输方式）**：V1.0 **只使用 Streamable HTTP 通信方式**（MCP 2025-03-26 规范，
> 单一 `/rootfs` 端点，POST/GET/DELETE）。不实现 stdio 传输，不实现旧版 HTTP+SSE 对外接口。
> 原文 §2.3 中 stdio 相关要求以本修订为准；日志仍只允许写 stderr/syslog/文件，不得污染协议通道。
>
> **修订 2（目标平台）**：目标架构为 **x86_64（原生构建验证）和 RISC-V riscv64（交叉编译）**,
> 不交付 ARM。RISC-V 工具链参考 `/build/ai_wh/xiaozhi/protocol_hub/config/toolchain-riscv64.cmake`：
> Xuantie-900 riscv64 gcc 14.1.1（glibc），sysroot 为
> `/build/k230_huskylens_pack/output/k230_canmv_huskylens_defconfig/host/riscv64-buildroot-linux-gnu/sysroot`，
> CPU  flags `-mcpu=c908v`。

**项目名称：** RootFS MCP Server
**版本：** V1.0
**项目类型：** 嵌入式 Linux 系统工具 / MCP Server
**交付目标：** 实现一个可交叉编译、可部署于嵌入式 Linux rootfs 中的 MCP 服务，为 MCP Client / AI Agent 提供 Linux 根文件系统访问、文件操作、系统信息查询及命令执行能力。

---

## 1. 项目目标

开发一个轻量级 RootFS MCP Server，使符合 MCP 协议的客户端能够通过标准工具调用接口访问 Linux 系统。

服务应提供以下能力：

1. 浏览和查询整个根文件系统中的文件和目录。
2. 读取文件内容，支持大文件分段读取。
3. 创建、修改、移动和删除文件及目录。
4. 查询文件属性、权限、大小及时间信息。
5. 执行 Linux 命令并返回标准输出、标准错误、退出码和超时状态。
6. 获取 CPU、内存、内核版本、挂载点和进程等系统信息。
7. 支持通过交叉编译生成目标架构可执行文件。
8. 通过配置文件管理文件访问范围、写权限、命令执行权限和资源限制。

项目必须交付真实可编译、可运行、可测试的源代码，不得只提供架构设计、伪代码或接口占位实现。

## 2. 技术要求

### 2.1 编程语言与构建

- 首选 C++17。
- 使用 CMake 作为构建系统。
- 使用 POSIX API 和 Linux 系统调用实现系统操作。
- JSON 解析库优先选择轻量级实现（本项目使用 cpp-mcp 自带的 nlohmann/json 单头文件）。
- 避免引入大型运行时、数据库或不必要的第三方依赖。
- 支持原生 Linux 编译与交叉编译。
- 代码必须兼容目标系统实际使用的 libc，包括 glibc 或 musl。
- 默认以可移植的 POSIX 实现为基础，对 Linux 特有功能提供兼容处理。

### 2.2 MCP 协议

实现符合 MCP 规范的服务端，至少支持：

- `initialize`
- `notifications/initialized`
- `ping`
- `tools/list`
- `tools/call`

要求：

- 使用 JSON-RPC 2.0 消息格式。
- 正确处理请求 ID、参数校验、方法不存在、无效 JSON 和工具执行错误。
- 工具定义必须包含名称、描述和 JSON Schema 参数定义。
- 工具调用结果使用标准 MCP 工具结果结构。
- 工具业务错误与 JSON-RPC 协议错误应合理区分。
- 协议版本应通过初始化协商，不得将某一版本号硬编码为所有客户端均适用。
- 不得将普通日志输出到协议数据通道。

### 2.3 传输方式（已修订）

V1.0 **只实现 Streamable HTTP 传输**（MCP 2025-03-26）：

- 单一 HTTP 端点（默认 `/rootfs`），支持 POST（客户端→服务端消息）、GET（服务端→客户端 SSE 流，可选）、DELETE（会话终止）。
- 通过 `Mcp-Session-Id` 头管理会话。
- 支持 MCP 客户端远程连接的使用方式。
- 日志写入 stderr 或文件，不得混入 HTTP 响应体。
- 代码架构应允许后续增加其他独立传输模块。

## 3. 功能需求

### 3.1 文件系统接口

所有文件操作统一通过文件系统服务层实现，不允许在 MCP 协议处理代码中直接散布文件操作逻辑。

#### 3.1.1 `fs_list`

功能：列出指定目录的子文件和子目录。

输入参数：

- `path`：必填，目标绝对路径。
- `max_entries`：可选，最大返回条目数。
- `include_hidden`：可选，是否包含隐藏文件。

返回信息：文件名、文件类型、文件大小、文件权限（可获取时）、修改时间（可获取时）、是否为符号链接（可获取时）。

要求：支持空目录；支持目录不存在和权限不足等错误；返回结果必须受到条目数及输出大小限制；不得在未经授权的情况下递归遍历整个文件系统。

#### 3.1.2 `fs_read`

功能：读取指定文件内容。

输入参数：`path`（必填）；`offset`（可选，默认 0）；`length`（可选，单次读取长度必须受配置限制）。

要求：支持文本文件和二进制文件；支持大文件分段读取；返回实际读取长度及是否还有后续内容；对无法直接表示为文本的二进制内容，采用 Base64 或明确的编码约定；对伪文件系统中的动态文件和特殊文件设置读取策略；不允许无限制读取文件；禁止通过普通文件读取接口无限读取 FIFO、设备节点等特殊文件。

#### 3.1.3 `fs_write`

功能：创建或写入普通文件。

输入参数：`path`（必填）；`content`（必填）；`offset`（可选）；`mode`（可选，文件权限）；`encoding`（可选，默认 UTF-8；支持约定的二进制编码方式 base64）。

要求：区分创建、覆盖和指定偏移写入；支持最大写入长度限制；写入失败时返回明确错误；不允许通过符号链接绕过写入授权；默认禁止写入未授权路径；不允许对特殊文件执行普通文件写入逻辑；不得在失败时误报写入成功。

#### 3.1.4 `fs_stat`

功能：获取文件或目录属性。

返回：文件类型、文件大小、权限位、UID、GID、修改时间、访问时间和状态变更时间（系统支持时）、符号链接状态。

不得为了查询属性而自动读取整个文件。

#### 3.1.5 `fs_mkdir`

功能：创建目录。

输入参数：`path`、`mode`、`recursive`。

要求：验证路径授权，处理目录已存在、权限不足及父目录不存在等情况。

#### 3.1.6 `fs_remove`

功能：删除文件或目录。

输入参数：`path`、`recursive`。

要求：删除操作默认关闭，须由策略显式启用；非递归模式不得删除非空目录；递归删除必须限制在授权路径中；禁止删除授权根目录本身；不跟随符号链接进入其目标执行递归删除；对关键系统目录和特殊挂载点实施保护策略。

#### 3.1.7 `fs_move`

功能：移动或重命名文件。

输入参数：`src`、`dst`。

要求：同时检查源路径和目标路径的访问权限，禁止通过移动操作绕过写权限策略。

#### 3.1.8 `fs_search`

功能：在指定目录下搜索文件名或文件文本。

输入参数：`path`、`pattern`、`mode`（name 文件名匹配或 content 文本匹配）、`max_results`、`max_depth`。

要求：限制遍历深度、结果数量和执行时间；默认不跟随符号链接递归遍历；遇到权限不足或不可读文件时，允许返回部分结果及错误统计；文本搜索不得默认扫描整个 rootfs。

### 3.2 命令执行接口

#### 3.2.1 `shell_exec`

功能：执行 Linux 命令并返回执行结果。

输入参数：

- `argv`：必填，字符串数组，第一个元素为可执行程序。
- `cwd`：可选，工作目录。
- `timeout_ms`：可选，命令超时时间。
- `max_output_bytes`：可选，输出总量限制。
- `env`：可选，允许传递的环境变量集合（键值对，仅允许白名单内的变量名）。

返回字段：`exit_code`、`stdout`、`stderr`、`timed_out`、`truncated`、`duration_ms`。启动失败（程序不存在/无权限）以独立字段或明确错误返回，不得与命令非零退出混淆。

实现要求：

1. 使用 `fork` 配合 `execve`（或 `posix_spawn`），直接传递 argv。
2. 不得将 argv 自动拼接成 shell 命令字符串。
3. 默认不经过 `/bin/sh -c`。
4. 正确采集 stdout 和 stderr。
5. 同时排空管道，避免子进程因管道写满而死锁。
6. 采用非阻塞 I/O、`poll` 或 `select` 实现超时和输出采集。
7. 超时时终止整个受控任务（进程组），而不仅是直接子进程。
8. 对 stdout、stderr、运行时间、并发数设置上限。
9. 对可执行程序和工作目录实施授权校验。
10. 使用受控环境变量，避免继承不必要的敏感环境变量。
11. 返回真实退出状态，不得把启动失败、超时和命令执行失败混为一类。
12. 进程退出但管道仍被后代进程持有时，必须避免无限等待（超时兜底）。

V1.0 默认只开放配置允许的可执行程序和参数策略。任意命令执行能力作为可选高权限模式（admin）提供，不得默认开放。

#### 3.2.2 `shell_script_exec`

可选扩展，默认禁用。启用时必须：通过独立策略授权；明确记录完整脚本或经脱敏后的审计信息；使用统一的超时、输出和进程清理机制；不得宣称它能在 root 权限下仅凭字符串黑名单实现可靠沙箱隔离。

### 3.3 系统信息接口

至少实现以下只读工具：

| 工具 | 功能 |
|---|---|
| `sys_info` | 内核版本、系统架构、系统版本（uname 等） |
| `sys_memory` | 内存总量、可用量及相关统计（/proc/meminfo） |
| `sys_cpu` | CPU 架构、核数及可获取的 CPU 信息（/proc/cpuinfo + sysconf） |
| `sys_mounts` | 当前进程可见的挂载信息（/proc/mounts） |
| `sys_processes` | 查询进程 PID、名称、状态及可获取的资源信息（遍历 /proc/\[0-9\]\*） |

要求：尽可能直接读取系统接口或调用系统 API；不依赖目标设备必须安装 `grep`、`awk`、`ps` 等工具；正确处理 `/proc`、`/sys` 不存在或不可读的情况；对权限不足的字段提供部分结果，而不是导致整个接口失败；不得假定不同 Linux 内核版本提供完全相同的字段。

## 4. 安全与权限策略

### 4.1 全局配置

提供配置文件 `config/rootfs-mcp.json`，至少支持：

- 服务监听地址与端口（transport: streamable HTTP）。
- 允许读取的路径（allow_read）。
- 允许写入的路径（allow_write）。
- 禁止访问的路径（deny，优先级最高）。
- 允许执行的程序（allow_exec）。
- 是否允许 shell 脚本执行（allow_shell_script，默认 false）。
- 单次文件读取上限（max_read_bytes）。
- 单次文件写入上限（max_write_bytes）。
- 单次命令超时时间（exec_timeout_ms 上限）。
- 单次命令输出上限（max_output_bytes 上限）。
- 最大并发任务数（max_concurrent_exec）。
- 是否启用删除接口（enable_delete，默认 false）。
- 是否启用审计日志（audit_log / audit_file）。

必须提供默认配置文件和配置说明。

### 4.2 路径安全

- 对路径穿越（`..`）进行防护。
- 不允许通过符号链接绕过授权目录限制。
- 采用目录文件描述符相对操作（openat/fstatat 等）作为主要文件访问机制。
- 在支持 `openat2()` 的系统上可以使用其路径解析约束（RESOLVE_NO_SYMLINKS 等）；不支持的系统上提供兼容实现（逐段 openat + O_NOFOLLOW + fstat 校验）。
- 不得把 `realpath()` 或简单字符串前缀判断当作完整的安全机制（可作为辅助快速检查，但授权判定必须基于解析后的真实路径 + dirfd 打开）。
- 默认禁止对块设备、字符设备、FIFO 和 socket 执行普通文件写入操作。
- 对 `/proc`、`/sys`、`/dev` 等特殊文件系统制定独立策略（默认只读且禁止读取块/字符设备与 FIFO）。

### 4.3 权限模式

至少支持三种模式：`readonly`、`controlled`、`admin`。默认 `readonly`。

高权限模式应配合独立进程、降权、capabilities、挂载命名空间或其他实际可用的隔离机制（文档说明，V1.0 提供配置钩子与说明即可）。不得把黑名单、隐藏工具或提示词约束当作操作系统级安全边界。

### 4.4 审计与错误处理

- 对文件写入、删除、移动及命令执行记录审计日志。
- 日志至少包含时间、操作类型、调用结果和请求关联 ID（session id）。
- 不记录认证密钥等敏感信息。
- 错误信息应便于调试，但不得不必要地泄露凭据。
- 任何失败操作不得返回虚假的成功状态。

## 5. 工程结构要求

```text
rootfs-mcp/
├── CMakeLists.txt
├── README.md
├── LICENSE
├── config/
│   └── rootfs-mcp.json
├── cmake/
│   └── toolchain-riscv64.cmake
├── include/
│   └── rootfs_mcp/
│       ├── fs_service.hpp
│       ├── exec_service.hpp
│       ├── sys_service.hpp
│       ├── security_policy.hpp
│       ├── audit_log.hpp
│       └── tool_registry.hpp
├── src/
│   ├── main.cpp
│   ├── fs/
│   ├── exec/
│   ├── sys/
│   ├── security/
│   ├── mcp/
│   └── util/
├── tests/
│   ├── test_protocol.cpp
│   ├── test_fs.cpp
│   ├── test_exec.cpp
│   └── test_security.cpp
├── scripts/
│   └── install.sh
└── docs/
    ├── srs.md
    ├── architecture.md
    ├── configuration.md
    └── mcp-client-example.md
```

必须保持 MCP 协议层、传输层、业务层和安全策略层相互独立。
MCP 协议与 Streamable HTTP 传输层复用 vendored 的 cpp-mcp 库（`third_party/cpp-mcp`，
即 `mcp::server` 的 `/rootfs` 端点实现），本项目不重新实现 JSON-RPC 分帧。

## 6. 交叉编译与部署（已修订目标）

### 6.1 构建要求

```bash
# 原生 x86_64
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# 交叉编译 riscv64
cmake -S . -B build-riscv64 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-riscv64.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build-riscv64 -j
```

### 6.2 目标环境

- x86_64（原生构建 + 运行测试，必须实际验证）。
- riscv64（Xuantie C908 工具链，glibc，交叉编译必须成功；用 `file`/`readelf` 验证 ELF 架构与动态库依赖；如无目标设备或 qemu-riscv64 则明确标记"未在目标环境运行验证"）。

### 6.3 部署要求

提供：二进制安装方法（scripts/install.sh）；配置文件安装方法；运行示例；依赖检查方法；退出和故障排查说明；可选的 systemd unit 示例。服务以 root 身份运行不是默认前提，优先最小权限。

## 7. 测试与验收标准

### 7.1 MCP 协议测试（基于 Streamable HTTP）

- 客户端可以成功完成 initialize 握手（POST /rootfs）。
- `tools/list` 返回全部已注册工具。
- `tools/call` 可以正确调用工具。
- 无效参数返回明确错误（invalid_params）。
- 未知方法和未知工具得到正确处理（method_not_found 等）。
- 日志不会污染 HTTP 协议响应。
- 连续多条消息不发生边界错乱。

### 7.2 文件系统测试

- 能列出普通目录内容；能读取小文件和分段读取大文件。
- 能正确报告文件不存在、权限不足和路径非法。
- 能创建、修改和删除测试目录内的文件。
- 默认策略下，越权写入和删除必须被拒绝。
- 通过 `..` 和符号链接尝试越权访问时必须拒绝。
- 不会因 FIFO 或设备节点导致无限阻塞（带超时判定）。
- 搜索操作遵守深度、结果数量和时间限制。

### 7.3 命令执行测试

- 能执行已授权的普通程序；返回正确 stdout、stderr 和退出码。
- 非零退出码不会被错误报告为成功退出。
- 超时后能终止受控进程及其后代任务（验证进程组清理）。
- 输出超过限制时能截断并设置 `truncated=true`。
- 不存在的可执行程序返回明确错误（spawn 失败）。
- 高并发、异常退出及管道关闭场景不会导致永久阻塞。
- 未授权程序必须被拒绝。

### 7.4 交叉编译测试

- 能在主机上构建 x86_64 并运行测试。
- 能生成 riscv64 可执行文件，并用 `file`/`readelf` 检查 ELF 架构和动态库依赖。
- 无目标设备时明确标记 riscv64 运行时未验证。

### 7.5 资源限制测试

- 文件读写有大小上限；命令有时间及输出上限；搜索有深度和结果数量限制；并发任务数受到限制；错误路径不会导致无限循环或无界内存分配。

## 8. 交付物

1. 完整项目源代码。2. 完整 CMake 构建文件。3. MCP 协议实现（复用 cpp-mcp）。4. 所有已承诺工具的真实实现。5. 默认配置文件及配置说明。6. 原生编译和交叉编译说明。7. 部署及 MCP Client 配置示例。8. 单元测试和协议测试。9. 安全策略说明。10. 构建日志、测试结果和已知限制清单（docs/verification.md）。

禁止使用空函数、硬编码模拟结果或占位实现冒充交付完成。

## 9. 最终验收原则

只有在源码真实存在、构建成功、核心工具可以通过 MCP 调用、错误处理有效、安全测试通过并提供可复现构建步骤后，才能标记项目完成。每个功能标注实现状态：已实现并验证 / 已实现但未验证 / 未实现。不得将主机编译成功等同于目标设备运行成功。
