PYTHON ?= python3
UNITTEST_ARGS ?=
export PYTHONPATH := src:third_party/kilix-license/src:tests/support
# Exported by make itself, so it reaches every recipe command even if the
# recipe's own environment is lost; the harness then requires the scratch.
export KILIX_CONTENT_MAKE_TEST := 1

.PHONY: test check generate pins hygiene

test:
	@set -eu; \
	scratch=$$(mktemp -d "$${TMPDIR:-/tmp}/kilix-content-check.XXXXXX"); \
	mkdir -p "$$scratch/home" "$$scratch/xdg-cache" "$$scratch/xdg-config" \
	  "$$scratch/xdg-data" "$$scratch/xdg-state" "$$scratch/xdg-runtime" \
	  "$$scratch/kilix-data" "$$scratch/kilix-storage" "$$scratch/kilix-home" \
	  "$$scratch/gpu-terminal" "$$scratch/tmp"; \
	trap 'rm -rf "$$scratch"' EXIT; \
	export KILIX_CONTENT_TEST_SCRATCH="$$scratch" \
	  HOME="$$scratch/home" \
	  XDG_CACHE_HOME="$$scratch/xdg-cache" \
	  XDG_CONFIG_HOME="$$scratch/xdg-config" \
	  XDG_DATA_HOME="$$scratch/xdg-data" \
	  XDG_STATE_HOME="$$scratch/xdg-state" \
	  XDG_RUNTIME_DIR="$$scratch/xdg-runtime" \
	  KILIX_DATA_HOME="$$scratch/kilix-data" \
	  KILIX_STORAGE_HOME="$$scratch/kilix-storage" \
	  KILIX_HOME="$$scratch/kilix-home" \
	  GPU_TERMINAL_HOME="$$scratch/gpu-terminal" \
	  TMPDIR="$$scratch/tmp" \
	  PYTHONPATH="src:third_party/kilix-license/src:tests/support"; \
	$(PYTHON) -m compileall -q -f setup.py src tests; \
	$(PYTHON) -m unittest discover -s tests -t . -v $(UNITTEST_ARGS)

generate:
	PYTHONPATH=src:third_party/kilix-license/src $(PYTHON) tools/generate_upstream_records.py
	PYTHONPATH=src:third_party/kilix-license/src $(PYTHON) tools/regenerate_catalog_digests.py

pins:
	PYTHONPATH=src:third_party/kilix-license/src $(PYTHON) tools/generate_upstream_records.py --check

check: test pins

hygiene:
	hygiene-scan --recurse

benchmark:
	$(PYTHON) benchmarks/benchmark_content.py
