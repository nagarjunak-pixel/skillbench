FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends g++ curl && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY csrc ./csrc
COPY src ./src

RUN uv sync --no-dev
EXPOSE 8170

CMD ["uv", "run", "skillbench", "serve", "--host", "0.0.0.0", "--port", "8170"]
