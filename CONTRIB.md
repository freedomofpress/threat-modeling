# Getting started

```
virtualenv --python python3 .venv
source .venv/bin/activate
pip install -r dev-requirements.txt
```

# Run tests, linter, and formatter

```
make check
```

You can run separately with `make test` and `make lint`.