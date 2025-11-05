# syntax=docker/dockerfile:1.4
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . /app
# Make both repository root and src/ available for imports
ENV PYTHONPATH=/app:/app/src

CMD ["python", "-m", "oracle.node.oracle_node"]
