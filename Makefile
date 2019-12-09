test:
	pytest -v -n 4 --cov-fail-under 100

lint:
	black threat_modeling
	flake8 --exclude .venv --max-line-length 88
	mypy --strict --package threat_modeling

check: lint test
