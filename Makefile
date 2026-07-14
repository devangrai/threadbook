PYTHON ?= python3

.PHONY: check build test harness-test clean

check:
	$(PYTHON) tools/harness.py check

build: check
	@if [ -f Cargo.toml ]; then cargo build --workspace; \
	else echo "No Rust workspace yet; specification build passed."; fi

test: check harness-test
	@if [ -f Cargo.toml ]; then cargo test --workspace; fi
	@if [ -f apps/desktop-ui/package.json ]; then npm --prefix apps/desktop-ui test -- --run; fi

harness-test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'

clean:
	rm -rf artifacts/harness/*
	touch artifacts/harness/.gitkeep
