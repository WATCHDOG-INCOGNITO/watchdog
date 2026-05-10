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

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

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