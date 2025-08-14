# Install and run

## Prereqs
- Python 3.11 and pip
- Docker and Docker Compose optional

## Local steps
1. Create a virtual environment
2. `make install`
3. `make train`
4. `make run`
5. Open the app at http://localhost:8501

## Docker steps
1. `make docker-up`
2. The image builds, trains models during build, and serves Streamlit on 8501
