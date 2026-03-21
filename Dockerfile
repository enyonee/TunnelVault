FROM python:3.12-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy project files
COPY pyproject.toml uv.lock ./
COPY tunnelvault.py tv tvpn ./
COPY tests/ tests/

# Install with dev deps
RUN uv sync --frozen --group dev --no-install-project

# Run tests
CMD ["uv", "run", "--no-project", "pytest", "tests/", "-x", "-q", "-o", "addopts=", "-m", "not network"]
