# PhishForge OSINT microservice.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies from pyproject (the project itself is installed last so
# that dependency layers cache independently of source changes).
COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install .

COPY app ./app

# subfinder is optional: when present on PATH the /recon/subdomains endpoint
# uses it, otherwise it falls back to crt.sh. It is not installed here.

EXPOSE 8099

# In-container we bind 0.0.0.0; the compose port mapping publishes it only to
# the host loopback (127.0.0.1). Set OSINT_TOKEN to require X-OSINT-TOKEN.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8099"]
