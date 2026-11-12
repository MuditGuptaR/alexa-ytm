FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PORT=5000 \
    DOMAIN="" \
    ALEXA_SKILL_ID="" \
    STREAM_SECRET="" \
    VERIFY_ALEXA_SIGNATURE=false \
    YOUTUBE_API_KEY="" \
    YOUTUBE_COOKIES=""

WORKDIR /app

# Cached layer: only installs ffmpeg (curl removed; not needed by Python)
RUN apt-get update && \
    apt-get install -y --no-install-recommends ffmpeg && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -u 1000 -m appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
USER appuser

EXPOSE 5000

CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-5000}"]


