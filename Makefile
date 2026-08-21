PYTHON ?= uv run --locked --no-sync python

.PHONY: benchmark test

test:
	$(PYTHON) -m compileall -q -f setup.py src tests
	$(PYTHON) -m unittest discover -s tests -v

benchmark:
	$(PYTHON) benchmarks/benchmark_content.py
