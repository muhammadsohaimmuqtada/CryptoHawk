FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/home/cryptohawk/.local/bin:$PATH

WORKDIR /app
COPY pyproject.toml README.md alembic.ini ./
COPY migrations ./migrations
COPY src ./src
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir . \
    && groupadd --system cryptohawk \
    && useradd --system --gid cryptohawk --create-home cryptohawk \
    && chown -R cryptohawk:cryptohawk /app

USER cryptohawk
EXPOSE 8000
CMD ["uvicorn", "cryptohawk.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
