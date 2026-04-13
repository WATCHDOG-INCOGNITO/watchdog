#!/usr/bin/env bash
# CTF 문제 하나를 setup — docker compose up + watchdog_default 네트워크에 join.
#
# 사용:
#   ./ctf_setup.sh <for_user_path> <alias>
# 예:
#   ./ctf_setup.sh codegate2023-fin/general/web-warmup/prob/for_user warmup
#
# 하는 일:
#   1) <for_user_path> 에서 docker compose up -d --build
#   2) 메인 웹서버 컨테이너 찾아 watchdog_default 네트워크에 <alias> 로 join
#   3) (있으면) bot 컨테이너도 같이 join
#   4) backend에서 http://<alias>/ 로 도달 가능한지 간단 확인
#
# webserver / bot 컨테이너 이름은 compose service 이름 기반 추정:
#   - webserver, web, app, api, api-server, nginx — 앞에서 매치되는 첫 거
#   - bot, admin-bot, adminbot
# 패턴에 안 맞으면 --web-service / --bot-service 로 override.

set -euo pipefail

FOR_USER="${1:-}"
ALIAS="${2:-}"
WEB_SERVICE="${WEB_SERVICE:-}"
BOT_SERVICE="${BOT_SERVICE:-}"

if [[ -z "$FOR_USER" || -z "$ALIAS" ]]; then
  echo "usage: $0 <for_user_path> <alias> [env: WEB_SERVICE=... BOT_SERVICE=...]" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ABS_DIR="$REPO_ROOT/$FOR_USER"
if [[ ! -f "$ABS_DIR/docker-compose.yml" ]]; then
  echo "[!] $ABS_DIR/docker-compose.yml not found" >&2
  exit 1
fi

echo "[+] CTF setup: $FOR_USER → alias=$ALIAS"
echo "[+] docker compose up ..."
( cd "$ABS_DIR" && docker compose up -d --build ) 1>/dev/null

# compose project 이름(기본: dir 이름 소문자)
PROJECT="$(basename "$ABS_DIR" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')"
# 실제 containers
CONTAINERS=$(docker ps --format "{{.Names}}" | grep -E "^${PROJECT}-" || true)
if [[ -z "$CONTAINERS" ]]; then
  echo "[!] no containers matched prefix ${PROJECT}-" >&2
  exit 1
fi

echo "[+] containers:" && echo "$CONTAINERS" | sed 's/^/    /'

detect_service() {
  local patterns="$1"
  for p in $patterns; do
    local hit
    hit=$(echo "$CONTAINERS" | grep -E "^${PROJECT}-${p}-[0-9]+$" || true)
    if [[ -n "$hit" ]]; then
      echo "$hit" | head -1
      return 0
    fi
  done
  return 1
}

WEB_CONT="${WEB_SERVICE:-$(detect_service "webserver web app api api-server nginx api_server")}"
BOT_CONT="${BOT_SERVICE:-$(detect_service "bot adminbot admin-bot admin_bot")}"
if [[ -z "$WEB_CONT" ]]; then
  echo "[!] web container not detected. Set WEB_SERVICE=<name> and rerun." >&2
  echo "    candidates:" && echo "$CONTAINERS" | sed 's/^/      /'
  exit 1
fi
echo "[+] web: $WEB_CONT"
[[ -n "$BOT_CONT" ]] && echo "[+] bot: $BOT_CONT"

# watchdog_default 네트워크 존재 확인
if ! docker network inspect watchdog_default >/dev/null 2>&1; then
  echo "[!] watchdog_default network not found. Start watchdog stack first: docker compose up -d" >&2
  exit 1
fi

# web 컨테이너를 watchdog 네트워크에 alias로 join
# 이미 join돼 있으면 disconnect → alias 재지정해 reconnect
if docker network inspect watchdog_default -f '{{range .Containers}}{{.Name}} {{end}}' | grep -qw "$WEB_CONT"; then
  docker network disconnect watchdog_default "$WEB_CONT" 2>/dev/null || true
fi
docker network connect --alias "$ALIAS" --alias webserver watchdog_default "$WEB_CONT"
echo "[+] joined $WEB_CONT to watchdog_default (aliases: $ALIAS, webserver)"

if [[ -n "$BOT_CONT" ]]; then
  if docker network inspect watchdog_default -f '{{range .Containers}}{{.Name}} {{end}}' | grep -qw "$BOT_CONT"; then
    docker network disconnect watchdog_default "$BOT_CONT" 2>/dev/null || true
  fi
  docker network connect --alias bot watchdog_default "$BOT_CONT"
  echo "[+] joined $BOT_CONT to watchdog_default (alias: bot)"
  # bot DNS refresh 위해 재시작
  docker restart "$BOT_CONT" >/dev/null 2>&1 || true
fi

# backend에서 도달 가능 확인
echo "[+] backend → $ALIAS ..."
if docker exec watchdog-backend-1 sh -c "getent hosts $ALIAS >/dev/null && curl -sS -m 5 -o /dev/null -w '%{http_code}' http://$ALIAS/ 2>&1" 2>/dev/null; then
  echo ""
  echo "[+] OK — setup complete"
else
  echo "[!] unreachable (may need --network-alias adjustment)"
fi
