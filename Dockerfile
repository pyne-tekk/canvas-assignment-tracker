# Official Playwright image — Chromium + all system deps pre-installed
FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Chromium browser (already available in this image, just register it)
RUN playwright install chromium

COPY . .

ENV PYTHONUNBUFFERED=1

# gunicorn timeout 120s to accommodate SSO flow (~15-30s)
CMD gunicorn main:app --bind 0.0.0.0:${PORT:-5000} --timeout 300 --workers 1
