.PHONY: help install test lint format demo docker-build docker-build-python docker-build-cpp webhook clean

help:
	@echo "GuardianLoop targets:"
	@echo "  install             pip install -e .[dev]"
	@echo "  test                run pytest"
	@echo "  lint                run ruff check"
	@echo "  format              run ruff format"
	@echo "  demo                end-to-end pipeline on samples/demo_cwe121.cpp (smoke test)"
	@echo "  docker-build        build both sandbox images"
	@echo "  webhook             launch the FastAPI GitHub webhook server (:8000)"
	@echo "  clean               remove caches and build artifacts"

install:
	python -m pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check src tests

format:
	ruff format src tests

demo:
	python -m guardianloop.cli samples/demo_sqli.py

docker-build: docker-build-python docker-build-cpp

docker-build-python:
	docker build -f docker/python-sandbox.Dockerfile -t guardianloop/python-sandbox:latest .

docker-build-cpp:
	docker build -f docker/cpp-sandbox.Dockerfile -t guardianloop/cpp-sandbox:latest .

webhook:
	uvicorn guardianloop.webhook.app:app --host 0.0.0.0 --port 8000

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .mypy_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
