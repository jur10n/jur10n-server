#!/usr/bin/env bash
# Apply the minimum inbound firewall policy for the VPS.
# This script is intentionally non-interactive and does not reset existing
# UFW rules. Review the warning and run it only from a trusted console/session.
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
	printf 'ufw-setup: run as root (for example, via sudo)\n' >&2
	exit 1
fi
command -v ufw >/dev/null 2>&1 || {
	printf 'ufw-setup: ufw is not installed; install it separately before running this template\n' >&2
	exit 1
}

cat >&2 <<'WARNING'
[安全提示]
这是非交互脚本，不会询问确认，也不会自动恢复 SSH 连接。
它会先放行 TCP 22022、80、443，再设置默认入站拒绝并启用 UFW。
请确认当前 SSH 使用的是 22022，并准备好 VPS 带外控制台；不要在
错误端口上运行，否则可能失去 SSH 访问。现有 UFW 规则不会被重置。
WARNING

# Keep these three rules first so enabling the firewall cannot lock out the
# configured SSH port or the two public HTTPS/HTTP entry points.
ufw allow 22022/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

ufw default deny incoming
ufw default allow outgoing
ufw --force enable
ufw status verbose
