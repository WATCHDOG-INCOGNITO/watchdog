#!/usr/bin/env bash
# CTF 문제 환경 teardown — docker compose down + network disconnect.
#
# 사용:
#   ./ctf_teardown.sh <for_user_path>
# 예:
#   ./ctf_teardown.sh codegate2023-fin/general/web-warmup/prob/for_user

set -euo pipefail

FOR_USER="${1:-}"
if [[ -z "$FOR_USER" ]]; then
  echo "usage: $0 <for_user_path>" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ABS_DIR="$REPO_ROOT/$FOR_USER"

PROJECT="$(basename "$ABS_DIR" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')"
# watchdog_default 네트워크에서 disconnect
for c in $(docker ps --format "{{.Names}}" | grep -E "^${PROJECT}-" || true); do
  docker network disconnect watchdog_default "$c" 2>/dev/null || true
done

if [[ -f "$ABS_DIR/docker-compose.yml" ]]; then
  ( cd "$ABS_DIR" && docker compose down -v ) 1>/dev/null 2>&1 || true
  echo "[+] torn down $FOR_USER"
else
  echo "[!] $ABS_DIR/docker-compose.yml not found (skip)"
fi
