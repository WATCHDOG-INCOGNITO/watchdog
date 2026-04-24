# watchdog-browser — Docker-embedded Playwright chromium with Xvfb + x11vnc + noVNC.
# Exposes:
#   6080  noVNC web client (http://localhost:6080/vnc.html?autoconnect=1)
#   8891  browser_agent Flask API (watchdog backend <-> agent RPC)
#
# Use case: user clicks "Login via browser" in Watchdog UI → frontend embeds
# noVNC iframe → user completes SSO (Google/SAML/etc) inside the embedded
# chromium → agent auto-detects auth cookie + exports Playwright storage_state
# → POSTs to watchdog backend /api/profiles/import.

FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        xvfb \
        x11vnc \
        novnc \
        websockify \
        net-tools \
        supervisor \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir playwright==1.48.0 flask requests
RUN playwright install chromium --with-deps || true

# /usr/share/novnc is provided by apt novnc package; use vnc_lite.html as the
# default entry (websockify --web serves this directory).

WORKDIR /app

COPY startup.sh /startup.sh
COPY browser_agent.py /app/browser_agent.py
RUN chmod +x /startup.sh

ENV DISPLAY=:99
ENV VNC_PORT=5900
ENV NOVNC_PORT=6080
ENV AGENT_PORT=8891
ENV WATCHDOG_API=http://backend:8000
ENV PROFILES_DIR=/profiles

EXPOSE 6080 8891

CMD ["/startup.sh"]
