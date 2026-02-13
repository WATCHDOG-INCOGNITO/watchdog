FROM python:3.12-slim

WORKDIR /app

# Keep base OS packages updated so Trivy doesn't fail on already-fixed CVEs.
RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Pure-stdlib HTTP server used only for CI/CD smoke testing.
COPY app.py /app/app.py

EXPOSE 8000
CMD ["python", "-u", "/app/app.py"]
