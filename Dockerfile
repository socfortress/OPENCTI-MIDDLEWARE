# ---- build ----
FROM python:3.12-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# ---- runtime ----
FROM python:3.12-slim
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
RUN useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin lookup
COPY --from=build /opt/venv /opt/venv
USER 10001
EXPOSE 8000
# --factory: create_app() reads settings at startup so config errors surface
# as one readable message rather than an import-time traceback.
CMD ["sh", "-c", "exec uvicorn opencti_lookup.main:app --factory \
    --host ${APP_HOST:-0.0.0.0} --port 8000 --workers ${WORKERS:-4} \
    --no-access-log --loop uvloop --http httptools"]
