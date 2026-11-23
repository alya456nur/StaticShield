
FROM python:3.11-slim

# Environment configuration
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

# Working directory
WORKDIR /app

# Install LightGBM system dependency
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY ember/ember/ ./ember/
COPY models/ ./models/
COPY frontend/ ./frontend/

# Start Flask application using Gunicorn
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} --workers 1 --threads 1 --timeout 900 app:app"]
