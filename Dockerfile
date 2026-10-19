FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS builder

WORKDIR /app

# Install build dependencies in builder stage
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml requirements.txt requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

# Copy source and install package without re-resolving dependencies
COPY src/ src/
RUN pip install --no-cache-dir --no-deps .

# --- Final stage: slim runtime image ---
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

WORKDIR /app

# Pull security updates for OS packages present in the base image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends liblzma5 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user matching the host bind-mount owner.
ARG PUID=1001
ARG PGID=3001
RUN groupadd -g "${PGID}" sonoplay \
    && useradd -u "${PUID}" -g sonoplay -d /app -s /sbin/nologin sonoplay

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# pip is a build tool, not a runtime dependency. Removing it also removes
# its CVE surface from the shipped image.
RUN rm -rf /usr/local/lib/python3.14/site-packages/pip \
           /usr/local/lib/python3.14/site-packages/pip-*.dist-info \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.14

# Copy application code
COPY templates/ templates/
COPY static/ static/
COPY main.py logging_config.py redaction.py version.py ./
COPY plex/ plex/
COPY dlna/ dlna/
COPY settings/ settings/
COPY utils/ utils/
COPY src/ src/

# Set ownership
RUN chown -R sonoplay:sonoplay /app

# Pre-create config directory with correct ownership so that
# atomic_write_json can create temp files in it.
# Must come BEFORE the VOLUME declaration so Docker preserves
# the ownership when creating an empty volume at runtime.
RUN mkdir -p /config && chown sonoplay:sonoplay /config

ENV HTTP_PORT=32488 CONFIG_PATH=/config PYTHONDONTWRITEBYTECODE=1
EXPOSE 1910/udp 32412/udp $HTTP_PORT
VOLUME /config

# Switch to non-root user
USER sonoplay

CMD ["sh", "-c", "umask 077 && exec python -O main.py"]
