#!/bin/bash
set -e

echo "[browser] starting Xvfb on $DISPLAY (1920x1080x24) ..."
Xvfb "$DISPLAY" -screen 0 1920x1080x24 -ac +extension RANDR -noreset >/tmp/xvfb.log 2>&1 &
sleep 1

echo "[browser] starting x11vnc (port $VNC_PORT, capslock-aware) ..."
# -capslock      : caps_lock 을 shift 처럼 동작시켜 client 대/소문자 매핑을
#                  서버가 그대로 반영 (기본 x11vnc 는 Lock 키 상태 무시)
# -nomodtweak    : 서버가 modifier 키를 추측하지 않고 client 가 보낸 그대로
#                  eval — Shift/Ctrl 조합이 보다 예측가능
# -noxkb         : XKB extension 우회 — 일부 keyboard layout 문제 방지
x11vnc -display "$DISPLAY" -forever -shared -nopw \
    -rfbport "$VNC_PORT" -noxdamage -quiet \
    -capslock -nomodtweak \
    >/tmp/x11vnc.log 2>&1 &

echo "[browser] starting noVNC + websockify (port $NOVNC_PORT -> localhost:$VNC_PORT) ..."
websockify --web=/usr/share/novnc "$NOVNC_PORT" "localhost:$VNC_PORT" >/tmp/novnc.log 2>&1 &

sleep 2

echo "[browser] all bg services up. launching Flask agent on port $AGENT_PORT ..."
exec python3 /app/browser_agent.py
