test:
	pytest --ignore=.venv --doctest-modules --doctest-glob='threat_modeling/*.py' -v -n 4 --cov-report term-missing --cov=threat_modeling --cov-fail-under 100

lint:
	black tests threat_modeling examples
	flake8 --exclude .venv --max-line-length 88
	mypy --strict --ignore-missing-imports --package threat_modeling

check: lint test
