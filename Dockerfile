FROM python:3.12-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy all project files
COPY . .

# Install with dev deps
RUN uv sync --frozen --group dev --no-install-project

# Run tests
CMD ["uv", "run", "--no-project", "pytest", "tests/", "-x", "-q", "-o", "addopts=", "-m", "not network"]
