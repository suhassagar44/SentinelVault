FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY config/ /app/config/
COPY backend/ /app/backend/

ENV PYTHONPATH=/app/backend
ENV HOTFIX_CONFIG_PATH=/app/config/app.yaml
ENV HOTFIX_SPEC_PATH=/app/config/spec.yaml
ENV HOTFIX_DB_PATH=/app/backend/hotfix_mvp.db
ENV PORT=8000

WORKDIR /app/backend

EXPOSE 8000

CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
