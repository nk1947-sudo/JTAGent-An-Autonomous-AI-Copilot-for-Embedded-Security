FROM node:22-bookworm-slim AS web
WORKDIR /app/web
COPY web/package*.json ./
RUN npm ci --no-fund --no-audit
COPY web/ ./
RUN npm run build

FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY contracts contracts
COPY analysis analysis
COPY edge edge
COPY orchestrator orchestrator
COPY config config
COPY fixtures fixtures
COPY --from=web /app/web/dist web/dist
RUN useradd --create-home sentinel
USER sentinel
ENV PYTHONUNBUFFERED=1 LANGSMITH_TRACING=false LANGCHAIN_TRACING_V2=false
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD /app/.venv/bin/python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=2)"
CMD ["/app/.venv/bin/python","-m","uvicorn","orchestrator.app:create_app","--factory","--host","0.0.0.0","--port","8000","--workers","1","--no-access-log"]
