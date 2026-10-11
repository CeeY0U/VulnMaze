FROM ghcr.io/astral-sh/uv:0.12.4 AS uv

FROM python:3.12-slim AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev --no-install-project --extra honeypot
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev --no-editable --extra honeypot

FROM python:3.12-slim
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TZ=UTC
COPY --from=build /opt/venv /opt/venv
RUN useradd --system --uid 999 --home-dir /cowrie --shell /usr/sbin/nologin cowrie \
 && mkdir -p /cowrie/etc /cowrie/var/log/cowrie /cowrie/var/lib/cowrie/downloads /cowrie/var/lib/cowrie/tty \
 && chown -R cowrie:cowrie /cowrie/var \
 && python -c "from twisted.plugin import IPlugin, getPlugins; list(getPlugins(IPlugin))"
USER cowrie
WORKDIR /cowrie
EXPOSE 2222
CMD ["twistd", "--umask=0022", "-n", "--pidfile=", "-l", "-", "vulnmaze"]
