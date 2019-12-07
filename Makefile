test:
	pytest -v -n 4 --cov-fail-under 100

lint:
	black threat_modeling
	mypy --strict --package threat_modeling

check: lint test