#!/bin/sh
# rootfs-mcp installer. Usage:
#   sudo ./scripts/install.sh [PREFIX]      # default PREFIX=/usr/local
# Installs: $PREFIX/bin/rootfs-mcp, /etc/rootfs-mcp/rootfs-mcp.json,
#           optional systemd unit (when systemd is present).
set -eu

PREFIX="${1:-/usr/local}"
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$SRC_DIR/build/rootfs-mcp}"
CONF_DIR=/etc/rootfs-mcp

[ -x "$BIN" ] || { echo "error: binary not found: $BIN (build first)" >&2; exit 1; }
[ -f "$SRC_DIR/config/rootfs-mcp.json" ] || { echo "error: config missing" >&2; exit 1; }

echo "installing $BIN -> $PREFIX/bin/rootfs-mcp"
install -d "$PREFIX/bin"
install -m 0755 "$BIN" "$PREFIX/bin/rootfs-mcp"

install -d "$CONF_DIR"
if [ -f "$CONF_DIR/rootfs-mcp.json" ]; then
    echo "keeping existing $CONF_DIR/rootfs-mcp.json (new default saved as .dist)"
    install -m 0640 "$SRC_DIR/config/rootfs-mcp.json" "$CONF_DIR/rootfs-mcp.json.dist"
else
    install -m 0640 "$SRC_DIR/config/rootfs-mcp.json" "$CONF_DIR/rootfs-mcp.json"
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
    cat > /etc/systemd/system/rootfs-mcp.service <<'EOF'
[Unit]
Description=RootFS MCP Server (Streamable HTTP)
After=network.target

[Service]
ExecStart=/usr/local/bin/rootfs-mcp /etc/rootfs-mcp/rootfs-mcp.json
Restart=on-failure
# Least privilege: run unprivileged unless the policy requires otherwise.
# User=rootfs-mcp
ProtectSystem=full
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    echo "systemd unit written: /etc/systemd/system/rootfs-mcp.service"
    echo "enable with: systemctl daemon-reload && systemctl enable --now rootfs-mcp"
fi

echo "done. Start with: rootfs-mcp $CONF_DIR/rootfs-mcp.json"
echo "Check: the config's listen.host/port, mode and allow_* lists before exposing it."
