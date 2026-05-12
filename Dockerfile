FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV SHADOWGATE_HOST=0.0.0.0
ENV SHADOWGATE_DATA_DIR=/data

COPY requirements.txt pyproject.toml README.md ./
COPY shadowgate ./shadowgate
COPY tests ./tests
COPY scripts ./scripts
COPY discovery ./discovery
COPY docs ./docs
COPY .env.example ./.env.example
COPY shadowgate_policy.json ./shadowgate_policy.json

RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -e .
RUN mkdir -p /data

EXPOSE 8000

CMD ["python", "-m", "shadowgate.server"]
