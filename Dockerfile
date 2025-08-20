FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --upgrade pip && pip install -r requirements.txt

# Copy your app code and prebuilt models
COPY app.py ./app.py
COPY models ./models

# Start Streamlit on the port provided by Spaces
# (shell form expands $PORT at runtime)
CMD streamlit run app.py --server.port $PORT --server.address 0.0.0.0
