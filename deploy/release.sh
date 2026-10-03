#!/usr/bin/env bash
# jur10n 发布脚本：本地测试 -> 上传 staging -> 原子切换 -> 健康检查 -> 失败自动回滚。
#
# 用法（在项目根目录或任意位置运行）：
#   bash deploy/release.sh api            # 发布后端（先本地跑 node --test）
#   bash deploy/release.sh web            # 本地构建并发布 dashboard 静态产物
#   bash deploy/release.sh all            # 两者都发
#   bash deploy/release.sh status         # 查看服务器当前版本与历史
#   bash deploy/release.sh rollback [stamp] [api|web]  # 回滚，默认 api 的上一个版本
#
# 连接参数从以下任一文件读取（已 gitignore，按顺序取第一个存在的）：
#   deploy/deploy.env / vpn/deploy.env，需要：VPS_IP、SSH_KEY
# 也可用环境变量 SKIP_TESTS=1 跳过本地测试（不推荐）。
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
for envfile in "$HERE/deploy.env" "$HERE/../vpn/deploy.env"; do
  if [ -f "$envfile" ]; then . "$envfile"; break; fi
done
KEY="${SSH_KEY:?需要补充：在 deploy/deploy.env 或 vpn/deploy.env 里设置 SSH_KEY}"
IP="${VPS_IP:?需要补充：在 deploy/deploy.env 或 vpn/deploy.env 里设置 VPS_IP}"
APP_ROOT="${APP_ROOT:-/srv/jur10n}"
SERVICE="${SERVICE:-jur10n-api}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
GITREF="$(cd "$ROOT" && git rev-parse --short HEAD 2>/dev/null || echo nogit)"
SSH="ssh -i $KEY -o BatchMode=yes -o ConnectTimeout=15 root@$IP"
SCP="scp -i $KEY -o BatchMode=yes -o ConnectTimeout=15"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log() { printf '\n==> %s\n' "$*"; }

run_tests() {
  if [ "${SKIP_TESTS:-0}" = "1" ]; then log "SKIP_TESTS=1，跳过本地测试"; return; fi
  log "本地测试 server/"
  (cd "$ROOT/server" && node --test)
}

release_api() {
  run_tests
  log "打包后端源码 ($GITREF)"
  (cd "$ROOT/server" && tar -czf "$TMP/api.tgz" src package.json package-lock.json)
  $SCP "$TMP/api.tgz" "root@$IP:/tmp/jur10n-api-$STAMP.tgz"
  log "服务器侧：staging -> 依赖 -> 原子切换 -> 健康检查"
  $SSH "APP_ROOT='$APP_ROOT' SERVICE='$SERVICE' STAMP='$STAMP' GITREF='$GITREF' bash -s" <<'REMOTE'
set -Eeuo pipefail
cd "$APP_ROOT"
mkdir -p "api-staging-$STAMP"
tar -xzf "/tmp/jur10n-api-$STAMP.tgz" -C "api-staging-$STAMP"
echo "$STAMP $GITREF" > "api-staging-$STAMP/RELEASE_STAMP"

# 依赖：lockfile 未变时硬链接复用现有 node_modules（秒级）；变了才全新 npm ci
if [ -d api/node_modules ] && [ "$(sha256sum api/package-lock.json | cut -d' ' -f1)" = "$(sha256sum api-staging-$STAMP/package-lock.json | cut -d' ' -f1)" ]; then
  cp -al api/node_modules "api-staging-$STAMP/node_modules"
  echo "node_modules 复用（lockfile 未变）"
else
  echo "lockfile 变化：全新 npm ci --omit=dev"
  (cd "api-staging-$STAMP" && npm ci --omit=dev --no-fund --no-audit)
  # npm 11 的 install-scripts 门闸可能拦掉 argon2 的构建脚本
  if ! (cd "api-staging-$STAMP" && node -e "import('argon2').then(()=>process.exit(0),()=>process.exit(1))"); then
    echo "argon2 未构建，尝试修复"
    (cd "api-staging-$STAMP" && npm install-scripts approve argon2 2>/dev/null || true && npm rebuild argon2)
    (cd "api-staging-$STAMP" && node -e "import('argon2').then(()=>process.exit(0),()=>{console.error('argon2 仍不可用');process.exit(1)})")
  fi
fi
node --check "api-staging-$STAMP/src/server.js"

swap_and_check() {
  systemctl stop "$SERVICE"
  mv api "api.previous-$STAMP"
  mv "api-staging-$STAMP" api
  chown -R jur10n:jur10n api
  systemctl start "$SERVICE"
  sleep 2
  curl -fsS http://127.0.0.1:3000/healthz >/dev/null
}

if swap_and_check; then
  echo "healthz OK：发布 $STAMP ($GITREF) 完成"
  rm -f "/tmp/jur10n-api-$STAMP.tgz"
  ls -1dt api.previous-* 2>/dev/null | tail -n +4 | xargs -r rm -rf
else
  echo "healthz 失败，自动回滚到 $STAMP 之前的版本" >&2
  systemctl stop "$SERVICE" 2>/dev/null || true
  rm -rf api
  mv "api.previous-$STAMP" api
  systemctl start "$SERVICE"
  sleep 2
  curl -fsS http://127.0.0.1:3000/healthz >/dev/null && echo "已回滚，旧版本恢复健康" || true
  exit 1
fi
REMOTE
}

release_web() {
  log "本地构建 dashboard"
  (cd "$ROOT/dashboard" && npm run build)
  log "打包静态产物"
  (cd "$ROOT/dashboard/dist" && tar -czf "$TMP/dist.tgz" .)
  $SCP "$TMP/dist.tgz" "root@$IP:/tmp/jur10n-dist-$STAMP.tgz"
  log "服务器侧：静态产物原子切换"
  $SSH "APP_ROOT='$APP_ROOT' STAMP='$STAMP' GITREF='$GITREF' bash -s" <<'REMOTE'
set -Eeuo pipefail
cd "$APP_ROOT"
mkdir -p "dashboard-staging-$STAMP/dist"
tar -xzf "/tmp/jur10n-dist-$STAMP.tgz" -C "dashboard-staging-$STAMP/dist"
echo "$STAMP $GITREF" > "dashboard-staging-$STAMP/dist/RELEASE_STAMP"
rm -rf dashboard/dist.old
[ -d dashboard/dist ] && mv dashboard/dist "dashboard/dist.old-$STAMP"
mv "dashboard-staging-$STAMP/dist" dashboard/dist
rm -rf "dashboard-staging-$STAMP"
chown -R root:root dashboard/dist
chmod -R go+rX dashboard/dist
echo "dashboard 发布 $STAMP ($GITREF) 完成"
rm -f "/tmp/jur10n-dist-$STAMP.tgz"
ls -1dt dashboard/dist.old-* 2>/dev/null | tail -n +3 | xargs -r rm -rf
REMOTE
}

rollback() {
  local kind="${3:-api}"
  if [ "$kind" = "web" ]; then
    local stamp="${2:-}"
    [ -z "$stamp" ] && stamp=$($SSH "ls -1dt $APP_ROOT/dashboard/dist.old-* 2>/dev/null | head -1" | sed 's/.*dist\.old-//')
    [ -z "$stamp" ] && { echo "没有可回滚的 dashboard 版本"; exit 1; }
    log "回滚 dashboard 到 $stamp"
    $SSH "cd '$APP_ROOT' && mv dashboard/dist 'dashboard/dist.failed-$STAMP' && mv 'dashboard/dist.old-$stamp' dashboard/dist && chown -R root:root dashboard/dist && echo 回滚完成"
  else
    local stamp="${2:-}"
    [ -z "$stamp" ] && stamp=$($SSH "ls -1dt $APP_ROOT/api.previous-* 2>/dev/null | head -1" | sed 's/.*previous-//')
    [ -z "$stamp" ] && { echo "没有可回滚的后端版本"; exit 1; }
    log "回滚后端到 $stamp"
    $SSH "APP_ROOT='$APP_ROOT' SERVICE='$SERVICE' STAMP='$STAMP' PREV='$stamp' bash -s" <<'REMOTE'
set -Eeuo pipefail
cd "$APP_ROOT"
systemctl stop "$SERVICE"
mv api "api.failed-$STAMP"
mv "api.previous-$PREV" api
chown -R jur10n:jur10n api
systemctl start "$SERVICE"
sleep 2
curl -fsS http://127.0.0.1:3000/healthz >/dev/null && echo "已回滚到 $PREV，healthz OK"
REMOTE
  fi
}

status() {
  log "服务器状态"
  $SSH "bash -s" <<'REMOTE'
echo -n "服务: "; systemctl is-active jur10n-api caddy sing-box | paste -sd' '
echo -n "api 版本: "; cat /srv/jur10n/api/RELEASE_STAMP 2>/dev/null || echo "(无标记，脚本启用前部署)"
echo -n "dashboard 版本: "; cat /srv/jur10n/dashboard/dist/RELEASE_STAMP 2>/dev/null || echo "(无标记)"
echo -n "healthz: "; curl -fsS -m 5 http://127.0.0.1:3000/healthz || echo FAIL
echo; echo "可回滚后端版本:"; ls -1dt /srv/jur10n/api.previous-* 2>/dev/null || echo "  无"
echo "可回滚 dashboard 版本:"; ls -1dt /srv/jur10n/dashboard/dist.old-* 2>/dev/null || echo "  无"
REMOTE
}

case "${1:-}" in
  api) release_api ;;
  web) release_web ;;
  all) release_api; release_web ;;
  rollback) rollback "$@" ;;
  status) status ;;
  *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
