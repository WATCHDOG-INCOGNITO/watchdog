#!/bin/bash
set -euo pipefail

export DISPLAY="${DISPLAY:-:99}"
DISPLAY_NUM="${DISPLAY#:}"
X_LOCK_FILE="/tmp/.X${DISPLAY_NUM}-lock"
X_SOCKET_FILE="/tmp/.X11-unix/X${DISPLAY_NUM}"

if pgrep -f "Xvfb ${DISPLAY}" >/dev/null 2>&1 && [ -S "$X_SOCKET_FILE" ]; then
  echo "[browser] reusing existing Xvfb on $DISPLAY ..."
else
  if [ -e "$X_LOCK_FILE" ] || [ -e "$X_SOCKET_FILE" ]; then
    echo "[browser] removing stale X lock/socket for $DISPLAY ..."
    rm -f "$X_LOCK_FILE" "$X_SOCKET_FILE"
  fi

  echo "[browser] starting Xvfb on $DISPLAY (1920x1080x24) ..."
  Xvfb "$DISPLAY" -screen 0 1920x1080x24 -ac +extension RANDR -noreset >/tmp/xvfb.log 2>&1 &
  XVFB_PID=$!

  for _ in $(seq 1 20); do
    if [ -S "$X_SOCKET_FILE" ] && kill -0 "$XVFB_PID" 2>/dev/null; then
      break
    fi
    if ! kill -0 "$XVFB_PID" 2>/dev/null; then
      echo "[browser] Xvfb failed to start:" >&2
      cat /tmp/xvfb.log >&2 || true
      exit 1
    fi
    sleep 0.5
  done

  if [ ! -S "$X_SOCKET_FILE" ]; then
    echo "[browser] Xvfb did not become ready on $DISPLAY" >&2
    cat /tmp/xvfb.log >&2 || true
    exit 1
  fi
fi

echo "[browser] starting x11vnc (port $VNC_PORT, capslock-aware) ..."
x11vnc -display "$DISPLAY" -forever -shared -nopw \
  -rfbport "$VNC_PORT" -noxdamage -quiet \
  -capslock -nomodtweak \
  >/tmp/x11vnc.log 2>&1 &
X11VNC_PID=$!

echo "[browser] starting noVNC + websockify (port $NOVNC_PORT -> localhost:$VNC_PORT) ..."
websockify --web=/usr/share/novnc "$NOVNC_PORT" "localhost:$VNC_PORT" >/tmp/novnc.log 2>&1 &
NOVNC_PID=$!

sleep 2

if ! kill -0 "$X11VNC_PID" 2>/dev/null; then
  echo "[browser] x11vnc failed to stay up:" >&2
  cat /tmp/x11vnc.log >&2 || true
  exit 1
fi

if ! kill -0 "$NOVNC_PID" 2>/dev/null; then
  echo "[browser] websockify failed to stay up:" >&2
  cat /tmp/novnc.log >&2 || true
  exit 1
fi

echo "[browser] all bg services up. launching Flask agent on port $AGENT_PORT ..."
exec python3 /app/browser_agent.py
