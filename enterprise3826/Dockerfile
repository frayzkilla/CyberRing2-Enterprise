FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py init_db.py ./
COPY app ./app
COPY .env.example .env.example

RUN mkdir -p /app/app/static/uploads

EXPOSE 5050

HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
    CMD curl -fsS http://localhost:5050/api/health || exit 1

CMD ["sh", "-c", "python3 init_db.py && python3 app.py"]
