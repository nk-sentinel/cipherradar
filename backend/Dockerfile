FROM python:3.12-slim

WORKDIR /app

COPY backend/pyproject.toml .
RUN pip install --no-cache-dir .

COPY backend/app/ app/
COPY backend/alembic.ini .
COPY backend/scripts/ scripts/
COPY scanner/ scanner/

RUN chmod +x scripts/entrypoint.sh

EXPOSE 8000

# Non-root user
RUN useradd -m appuser
USER appuser

CMD ["bash", "scripts/entrypoint.sh"]
