.PHONY: install test lint format run run-ui docker-build docker-run clean

install:
	poetry install
	playwright install chromium

test:
	pytest --cov=specter --cov-report=term-missing

lint:
	ruff check specter/ tests/

format:
	ruff format specter/ tests/

run:
	uvicorn specter.api.main:app --reload --host 0.0.0.0 --port 8000

run-ui:
	cd ui && npm run dev

docker-build:
	docker build -t specter .

docker-run:
	docker-compose up

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
