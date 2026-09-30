# syntax=docker/dockerfile:1

# Base images are pinned by digest, the same policy as the CI container pins.
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

LABEL org.opencontainers.image.source="https://github.com/emiliano-go/trustsight-harness" \
      org.opencontainers.image.title="trustsight-harness" \
      org.opencontainers.image.description="Adversarial measurement harness for TrustSight" \
      org.opencontainers.image.licenses="MIT"

# uv is installed from PyPI at a pinned version rather than copied from the
# `ghcr.io/astral-sh/uv` image, so the build needs no second registry and stays
# reproducible against one digest plus one version.
RUN pip install --no-cache-dir uv==0.12.13

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    # Use the base image's interpreter: a uv-managed Python lands under the
    # build user's HOME and breaks once the image runs as `harness`.
    UV_PYTHON_PREFERENCE=system

# The harness measures a *pinned* TrustSight checkout, so the image carries
# both repos side by side; `../trustsight` is the sibling path the harness's
# `[tool.uv.sources]` expects.
WORKDIR /app/trustsight-harness
COPY trustsight /app/trustsight
COPY trustsight-harness /app/trustsight-harness

# The locked dependencies first (cheap layer when only source moves), then the
# project itself.  `--locked` refuses to resolve fresh: the image is the
# harness whose numbers were published.
RUN uv sync --locked --no-install-project --python /usr/local/bin/python3 \
    && uv sync --locked --python /usr/local/bin/python3

# The tool writes campaign records, coverage and regression reports into the
# repository tree at run time, and the operator database under HOME.  Give the
# non-root user both.
RUN useradd --create-home --shell /usr/sbin/nologin harness \
    && chown -R harness:harness /app/trustsight-harness /app/trustsight

ENV HOME=/home/harness
USER harness

HEALTHCHECK --interval=5m --timeout=30s --retries=3 \
    CMD ["/app/trustsight-harness/.venv/bin/python", "-m", "harness", "coverage"]

ENTRYPOINT ["/app/trustsight-harness/.venv/bin/python", "-m", "harness"]
CMD ["--help"]
