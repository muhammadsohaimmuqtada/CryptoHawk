.PHONY: install test lint api web docker

install:
	python -m pip install -e '.[dev]'

test:
	pytest

lint:
	ruff check src tests

api:
	uvicorn cryptohawk.api.app:app --reload --port 8000

web:
	cd frontend && npm install && npm run dev

docker:
	docker compose up --build
