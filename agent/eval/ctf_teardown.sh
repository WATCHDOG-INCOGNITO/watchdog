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

ALIAS="${2:-}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ABS_DIR="$REPO_ROOT/$FOR_USER"

# 모든 ALIAS-* container + container_name 고정 케이스 둘 다 disconnect
if [[ -n "$ALIAS" ]]; then
  CONTAINERS=$(docker ps --format "{{.Names}}" | grep -E "^${ALIAS}-" || true)
  if [[ -z "$CONTAINERS" ]]; then
    CONTAINERS=$(cd "$ABS_DIR" 2>/dev/null && docker compose -p "$ALIAS" ps --format '{{.Name}}' 2>/dev/null || true)
  fi
  for c in $CONTAINERS; do
    docker network disconnect watchdog_default "$c" 2>/dev/null || true
  done
fi

if [[ -f "$ABS_DIR/docker-compose.yml" ]]; then
  ( cd "$ABS_DIR" && docker compose -p "${ALIAS:-default}" down -v ) 1>/dev/null 2>&1 || true
  echo "[+] torn down $FOR_USER (project=${ALIAS:-default})"
else
  echo "[!] $ABS_DIR/docker-compose.yml not found (skip)"
fi
