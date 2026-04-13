FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    libpq-dev curl wget git unzip nmap \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /tmp/nuclei.zip \
  && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ && rm /tmp/nuclei.zip && chmod +x /usr/local/bin/nuclei || true

RUN curl -sL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_amd64.zip -o /tmp/httpx.zip \
  && unzip -o /tmp/httpx.zip -d /usr/local/bin/ && rm /tmp/httpx.zip && chmod +x /usr/local/bin/httpx || true

RUN curl -sL https://github.com/projectdiscovery/katana/releases/latest/download/katana_linux_amd64.zip -o /tmp/katana.zip \
  && unzip -o /tmp/katana.zip -d /usr/local/bin/ && rm /tmp/katana.zip && chmod +x /usr/local/bin/katana || true

RUN pip install --no-cache-dir sqlmap

RUN curl -sL https://github.com/hahwul/dalfox/releases/latest/download/dalfox_linux_amd64 -o /usr/local/bin/dalfox \
  && chmod +x /usr/local/bin/dalfox || true

RUN curl -sL https://github.com/ffuf/ffuf/releases/latest/download/ffuf_linux_amd64 -o /tmp/ffuf.tar.gz \
  && tar xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ && rm /tmp/ffuf.tar.gz && chmod +x /usr/local/bin/ffuf || true

RUN pip install --no-cache-dir wafw00f

# ── Public payload DB (commodity check용 ground truth) ──
# 인터넷에 이미 공개된 payload 목록을 로컬에 두고, novel 판정 시 이것과 substring 매칭.
# payloadbox 시리즈는 합쳐서 ~5MB 미만, 가장 자주 인용되는 SQLi/XSS/CMDi/LFI/SSRF 페이로드 모음.
RUN mkdir -p /app/payloads_db && cd /app/payloads_db \
  && curl -sSL -o sqli.txt    https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/exploit/SQL_Injection.txt \
  && curl -sSL -o xss.txt     https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt \
  && curl -sSL -o cmdi.txt    https://raw.githubusercontent.com/payloadbox/command-injection-payload-list/master/command-injection-payload-list.txt \
  && curl -sSL -o lfi.txt     https://raw.githubusercontent.com/payloadbox/rfi-lfi-payload-list/master/Intruder/lfi-Intruder.txt \
  && curl -sSL -o ssrf.txt    https://raw.githubusercontent.com/payloadbox/ssrf-payload-list/master/ssrf-payloads.txt \
  || echo "WARN: payload DB partial — commodity_check_local will still work with what got downloaded"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Pre-download sentence-transformers model so it's baked into the image
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-mpnet-base-v2')"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libnspr4 libatk1.0-0t64 \
    libatk-bridge2.0-0t64 libcups2t64 libdrm2 libxkbcommon0 libxcomposite1 \
    libxdamage1 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2t64 \
    libxfixes3 fonts-unifont \
  && apt-get clean && rm -rf /var/lib/apt/lists/* \
  && playwright install chromium

COPY . /app

EXPOSE 8000 8889
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]