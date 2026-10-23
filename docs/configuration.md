# rootfs-mcp 配置说明

配置文件为 JSON。启动时路径解析顺序：`argv[1]` → `$ROOTFS_MCP_CONFIG` →
`./config/rootfs-mcp.json` → `/etc/rootfs-mcp/rootfs-mcp.json`。

## 字段

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `mode` | string | `"readonly"` | `readonly` / `controlled` / `admin` |
| `listen.host` | string | `"127.0.0.1"` | Streamable HTTP 监听地址 |
| `listen.port` | int | `9898` | 监听端口 |
| `server.name` / `server.version` | string | rootfs-mcp / 1.0.0 | initialize 响应中的 serverInfo |
| `allow_read` | string[] | `[]` | 允许读取的根路径（启动时 canonicalize，必须存在） |
| `allow_write` | string[] | `[]` | 允许写入/删除/移动的根路径 |
| `deny` | string[] | `[]` | 禁止访问前缀，优先级最高（可不存在，按词法保留） |
| `allow_exec` | string[] | `[]` | 允许执行程序的绝对路径（启动时解析为 canonical 路径） |
| `allow_shell_script` | bool | `false` | 是否开放 `shell_script_exec`（readonly 模式下恒关闭） |
| `enable_delete` | bool | `false` | 是否开放 `fs_remove` |
| `max_read_bytes` | int | 1048576 | `fs_read` 单次读取硬上限 |
| `max_write_bytes` | int | 1048576 | `fs_write` 单次写入硬上限 |
| `exec_timeout_ms` | int | 30000 | 命令墙钟超时硬上限（100–3600000） |
| `max_output_bytes` | int | 1048576 | 命令 stdout+stderr 合计输出硬上限 |
| `max_concurrent_exec` | int | 4 | 最大并发命令数（1–256），满时新请求立即失败 |
| `audit` | bool | `true` | 是否启用审计日志 |
| `audit_file` | string | `""` | 审计输出文件；空字符串 = stderr |

## 判定规则

1. `deny` 优先于一切 allow 列表（前缀匹配，组件感知：`/a` 不匹配
   `/abc`）。
2. 授权基于解析后的真实路径（符号链接与 `..` 先消解）；不存在写目标
   解析其最近存在的祖先。
3. `readonly`：任何写/执行工具直接拒绝；`admin` 且 `allow_exec` 为空
   时允许执行任意可解析的可执行文件（高权限行为，请知悉风险）。
4. `/`、`/proc`、`/sys`、`/dev`、`/boot` 及未显式授权的 `/etc` 子树
   永远禁止删除/移动；授权根本身禁止删除。

## 示例：受控模式

```json
{
  "mode": "controlled",
  "listen": { "host": "127.0.0.1", "port": 9898 },
  "allow_read": ["/"],
  "allow_write": ["/var/lib/myapp", "/tmp/myapp"],
  "deny": ["/etc/shadow", "/proc/kcore", "/dev/mem"],
  "allow_exec": ["/bin/echo", "/usr/bin/systemctl"],
  "allow_shell_script": false,
  "enable_delete": true,
  "exec_timeout_ms": 10000,
  "max_output_bytes": 65536,
  "max_concurrent_exec": 2,
  "audit": true,
  "audit_file": "/var/log/rootfs-mcp-audit.log"
}
```

注意：`allow_write`/`allow_read`/`allow_exec` 中的路径在配置加载时必须
存在（要做 canonicalize）；不存在的路径会在启动时直接报错，避免运行
期才发现配置笔误。
