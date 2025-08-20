FROM python:3.11-slim

# System prep (optional but nice for builds)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# install deps
COPY requirements.txt .
RUN python -m pip install --upgrade pip && pip install -r requirements.txt

# copy app + models
COPY . /app
ENV MODEL_DIR=/app/models

# bind on $PORT (the platform will set it), fallback 8501 locally
CMD streamlit run app.py --server.port ${PORT:-8501} --server.address 0.0.0.0

