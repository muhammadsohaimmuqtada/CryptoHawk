.PHONY: install test lint audit frontend-check api web docker docker-production evaluation-up evaluation-smoke evaluation-down

EVALUATION_COMPOSE = docker compose -f docker-compose.evaluation.yml

install:
	python -m pip install -e '.[dev]'
	cd frontend && npm ci

test:
	pytest --cov=cryptohawk --cov-report=term-missing

lint:
	ruff check src tests migrations scripts

audit:
	pip-audit
	cd frontend && npm audit --audit-level=high

frontend-check:
	cd frontend && npm ci && npm audit --audit-level=high && npm run build

api:
	uvicorn cryptohawk.api.app:app --reload --port 8000

web:
	cd frontend && npm run dev

docker:
	docker compose up --build

docker-production:
	docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --build

evaluation-up:
	$(EVALUATION_COMPOSE) up -d --build db migrate api worker scheduler seed web
	$(EVALUATION_COMPOSE) build smoke
	$(EVALUATION_COMPOSE) run --rm smoke
	@printf '\nCryptoHawk evaluation is ready at http://localhost:3000\n'
	@printf 'Login: tester@cryptohawk.local / CryptoHawk-Eval-Only-2026!\n'

evaluation-smoke:
	$(EVALUATION_COMPOSE) build smoke
	$(EVALUATION_COMPOSE) run --rm smoke

evaluation-down:
	$(EVALUATION_COMPOSE) down -v --remove-orphans
