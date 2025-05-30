FROM python:3.13-bookworm AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /build

COPY . /build/

# We want the same version of packages, but we might need more because the lock
# file might be meant for another architecture or version of Python. We then
# compile using the constraints and our python we expect to run in production.
RUN uv export --format requirements-txt --output-file /constraints.txt \
    --no-editable --no-dev --no-emit-workspace --frozen --no-index --no-hashes && \
    uv pip compile --constraints /constraints.txt --output-file /requirements.txt pyproject.toml

# Install requirements into /env
RUN --mount=type=cache,target=/root/.cache \
    pip install \
    --no-deps --disable-pip-version-check \
    --target /env \
    --requirement /requirements.txt

# Build application wheel
RUN --mount=type=cache,target=/root/.cache \
    uv build --wheel

# Install the application into /app
RUN --mount=type=cache,target=/root/.cache \
    pip install \
    --no-deps --disable-pip-version-check \
    --target /app \
    dist/*.whl


FROM python:3.13-slim-bookworm
COPY --from=builder /env /env
COPY --from=builder /app /app
RUN useradd -u 1000 -m -s /usr/sbin/nologin nodeman
ENV PYTHONPATH=/app:/env
ENV PATH=/app/bin:$PATH
USER nodeman
ENTRYPOINT ["nodeman_server"]
CMD ["--host", "0.0.0.0", "--port", "8080", "--log-json"]
