# MCP 客户端接入示例

rootfs-mcp 只实现 Streamable HTTP 传输（MCP 2025-03-26）：单一端点
`/rootfs`，POST 发送消息、GET 打开服务端推送流（可选）、DELETE 终止会话，
会话由 `Mcp-Session-Id` 头管理。

## 客户端配置（以支持 streamable http 的 MCP 客户端为例）

```json
{
  "mcpServers": {
    "rootfs": {
      "type": "streamableHttp",
      "url": "http://192.168.1.10:9898/rootfs"
    }
  }
}
```

把 `192.168.1.10:9898` 换成配置文件里的 `listen.host`/`listen.port`。
服务默认只监听 `127.0.0.1`；远程接入需显式把 `listen.host` 改为
`0.0.0.0` 或具体网卡地址，并自行评估暴露面（V1.0 无认证层，请仅在
可信网络中暴露，或置于反向代理/防火墙之后）。

## 手工会话流程（curl）

```bash
# 1) initialize —— 响应头返回 Mcp-Session-Id
curl -i -X POST http://127.0.0.1:9898/rootfs \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-03-26","capabilities":{},
        "clientInfo":{"name":"my-client","version":"1.0"}}}'

# 2) notifications/initialized（带 Mcp-Session-Id，HTTP 202）
curl -X POST http://127.0.0.1:9898/rootfs \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -H "Mcp-Session-Id: <session-id>" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# 3) tools/list / tools/call
curl -X POST http://127.0.0.1:9898/rootfs \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -H "Mcp-Session-Id: <session-id>" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

curl -X POST http://127.0.0.1:9898/rootfs \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -H "Mcp-Session-Id: <session-id>" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
        "name":"fs_read","arguments":{"path":"/etc/os-release","length":4096}}}'

# 4) 结束会话
curl -X DELETE http://127.0.0.1:9898/rootfs -H "Mcp-Session-Id: <session-id>"
```

## 错误形态

- 协议错误（未知方法、未知工具、参数缺失等）：JSON-RPC `error` 对象，
  如 `{"code":-32602,"message":"Tool not found: xxx"}`。
- 工具业务错误（越权、文件不存在、超时等）：正常 `result`，但
  `isError=true`，`content[0].text` 为错误说明 —— 永远不会伪报成功。
- 传输错误：HTTP 400（缺会话头/坏 JSON）、404（会话不存在或已删除）。
