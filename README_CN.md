# rootfs-mcp — RootFS MCP Server（中文说明）

一个基于 **Streamable HTTP**（MCP 2025-03-26 规范，单一 `/rootfs` 端点，
POST/GET/DELETE）的 MCP（Model Context Protocol）服务端，向 MCP 客户端 /
AI Agent 提供 Linux 文件系统工具、受控命令执行和系统信息查询能力。
目标平台：x86_64（原生构建，已测试）和 riscv64（交叉编译，玄铁 C908 /
K230 工具链）。

MCP 协议与 Streamable HTTP 传输层复用 cpp-mcp 库（vendor 在
`third_party/cpp-mcp`，MIT 协议，见 `third_party/cpp-mcp/LICENSE`）；
本项目实现安全策略层、文件系统/命令执行/系统信息服务层、工具注册表和
应用入口。

## 工具列表（15 个）

| 工具 | 功能 |
|---|---|
| `fs_list` | 列出目录项（名称/类型/大小/权限/修改时间/是否符号链接） |
| `fs_read` | 分段读文件（offset/length、has_more、二进制自动 base64） |
| `fs_write` | 创建/覆盖/指定偏移写入，支持 base64 输入和权限位 |
| `fs_stat` | 查询文件属性（不读取文件内容） |
| `fs_mkdir` | 创建目录（可递归） |
| `fs_remove` | 删除文件/目录（默认禁用，需 `enable_delete=true`） |
| `fs_move` | 重命名/移动（限同一文件系统） |
| `fs_search` | 文件名（glob/子串）或内容搜索；深度/数量/时间受限 |
| `shell_exec` | fork+execve 直传 argv（不经过 shell），超时与输出上限 |
| `shell_script_exec` | `/bin/sh -c` 脚本（需 `allow_shell_script=true`） |
| `sys_info` | uname：内核、架构、主机名 |
| `sys_memory` | /proc/meminfo 内存统计 |
| `sys_cpu` | CPU 架构、核数、cpuinfo 摘要（兼容 x86/RISC-V 格式差异） |
| `sys_mounts` | /proc/mounts 挂载表 |
| `sys_processes` | /proc 进程扫描（pid/名称/状态/ppid/rss） |

## 编译

```bash
# 原生 x86_64
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
(cd build && ctest --output-on-failure)

# 交叉编译 riscv64（玄铁 C908 工具链，测试自动关闭）
cmake -S . -B build-riscv64 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-riscv64.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build-riscv64 -j

# 通过 scp 部署到目标板（先构建，再拷贝 ELF 和默认配置；
# 可用 -DSCP_HOST/-DSCP_PORT/-DSCP_USER/-DSCP_PATH 覆盖）
cmake --build build-riscv64 --target cp
# 或：(cd build-riscv64 && make cp)
# 默认值：root@192.168.0.113:/root，端口 2222
```

## 运行

```bash
./build/rootfs-mcp config/rootfs-mcp.json   # 或指定任意配置路径
# 配置解析顺序：argv[1] | $ROOTFS_MCP_CONFIG | ./config/rootfs-mcp.json | /etc/rootfs-mcp/rootfs-mcp.json
```

服务监听 `http://<listen.host>:<listen.port>/rootfs`（默认
`http://127.0.0.1:9898/rootfs`）。日志与审计输出到 stderr 或
`audit_file`，绝不混入 HTTP 响应通道。SIGINT/SIGTERM 优雅停机。

## 权限模式（mode）

`mode` 可设置为以下三个值：

| 模式 | 说明 |
|---|---|
| `readonly`（默认） | 只允许只读工具：`fs_list`/`fs_read`/`fs_stat`/`fs_search` 和 `sys_*`；写、删、移、命令执行一律拒绝 |
| `controlled` | 按配置开放有限能力：`allow_write` 内的写/建目录/移动，`enable_delete=true` 时允许删除，`allow_exec` 列表内的命令执行 |
| `admin` | 高权限模式，必须显式启用；所有工具按配置开放，且 **`allow_exec` 为空时允许执行任意可解析的可执行文件**（请知悉风险） |

非法值会在启动时报错退出。

## 如何让 Agent 对 rootfs 有写权限

编辑配置文件（默认 `config/rootfs-mcp.json`）：

```json
{
  "mode": "controlled",
  "allow_read": ["/"],
  "allow_write": ["/var/lib/myapp", "/tmp/myapp"],
  "enable_delete": true
}
```

要点：

1. **`mode` 必须改为 `"controlled"`**（或 `"admin"`），`readonly` 下写操作
   一律被拒绝。
2. **`allow_write` 列出允许写入的根目录**；`fs_write`、`fs_mkdir`、
   `fs_move`、`fs_remove` 只允许作用在这些目录子树内。路径在配置加载时
   必须真实存在（会做 canonicalize，不存在则启动报错）。
3. **删除操作默认关闭**，需要 `fs_remove` 时显式设置 `"enable_delete": true`。
4. 需要执行命令时配置 **`allow_exec`**（程序绝对路径白名单），例如
   `"allow_exec": ["/bin/echo", "/usr/bin/systemctl"]`。
5. 注意 **OS 层面权限**：运行 rootfs-mcp 的用户本身必须对目标目录有写
   权限（推荐以最小权限用户运行，不要默认用 root）。
6. 改完配置重启服务生效。

`deny` 列表优先级最高，可用于在授权范围内再挖掉敏感子路径
（如 `/etc/shadow`）；`/`、`/proc`、`/sys`、`/dev`、`/boot` 等关键目录
无论配置如何都禁止删除/移动。

## 安全模型（摘要）

- 路径授权：deny 列表优先，然后对 canonicalize 后的
  `allow_read`/`allow_write` 根做组件感知的前缀匹配；`..` 逃逸与符号
  链接逃逸一律拒绝；所有 I/O 基于目录 fd 相对操作（内核支持时用
  `openat2` 的 `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`，否则逐段
  `openat` + `O_NOFOLLOW` 遍历）。
- 特殊文件（块/字符设备、FIFO、socket）永不按普通文件读写；FIFO 读取
  快速失败而非阻塞。
- 命令执行：`allow_exec` 白名单，argv 直传 execve（不拼接 shell 字符串），
  墙钟超时杀整个进程组，输出/超时/并发均有上限，环境变量白名单过滤。
- 审计日志记录写、删、移动和命令执行（时间、会话 ID、操作、目标、结果）。

详见 `docs/architecture.md`、`docs/configuration.md`、
`docs/mcp-client-example.md` 和 `docs/verification.md`。

## 安装

```bash
sudo ./scripts/install.sh [PREFIX]   # 默认 /usr/local
```

安装二进制、`/etc/rootfs-mcp/rootfs-mcp.json`，存在 systemd 时同时安装
unit 示例。

## 许可证

见本仓库 `LICENSE`（MIT）。vendored 的 cpp-mcp 库保留其自有 MIT 许可证
（`third_party/cpp-mcp/LICENSE`）。
