
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PORT=8080

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY ember/ ./ember/
COPY models/ ./models/

CMD exec gunicorn --bind :${PORT} --workers 1 --threads 4 --timeout 1800 app:app
