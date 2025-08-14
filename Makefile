.PHONY: install train run docker-build docker-up lint

install:
	python -m pip install --upgrade pip
	pip install -r requirements.txt

train:
	MODEL_DIR=models python train_model.py

run:
	MODEL_DIR=models streamlit run app.py

docker-build:
	docker build -t cognitive-soar:latest .

docker-up:
	docker compose up --build

lint:
	flake8 --max-line-length=100 --ignore=E203,W503 .
