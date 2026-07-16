PYTHON ?= python3

.PHONY: check build production-bundle test harness-test phase-evidence supply-chain-generate supply-chain-check npm-clean-install clean

check:
	$(PYTHON) tools/harness.py check

build: check supply-chain-check production-bundle

production-bundle: npm-clean-install
	env -u NPM_TOKEN -u NODE_AUTH_TOKEN -u npm_config_registry \
		-u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
		-u WARDROBE_REMOTE_RECOMMENDATIONS_RELEASE \
		-u WARDROBE_TRY_ON_RELEASE \
		-u VITE_WARDROBE_REMOTE_RECOMMENDATIONS_RELEASE \
		-u VITE_WARDROBE_TRY_ON_RELEASE \
		CARGO_NET_OFFLINE=true npm_config_offline=true \
		./node_modules/.bin/tauri build --config src-tauri/tauri.conf.json

supply-chain-generate:
	$(PYTHON) tools/release_supply_chain.py generate

supply-chain-check:
	$(PYTHON) tools/release_supply_chain.py check

npm-clean-install:
	env -u NPM_TOKEN -u NODE_AUTH_TOKEN -u npm_config_registry \
		-u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
		npm_config_offline=true npm_config_ignore_scripts=true \
		npm ci --offline --ignore-scripts --no-audit --no-fund
	$(PYTHON) tools/release_supply_chain.py check-installed

test: check harness-test
	cargo test --workspace
	npm --workspace @wardrobe/desktop-ui test -- --run
	$(MAKE) phase-evidence

harness-test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'

phase-evidence:
	@if [ -n "$$HARNESS_RUN_DIR" ]; then \
		$(PYTHON) tools/evaluators/run.py; \
	else \
		echo "No harness run active; phase evidence skipped."; \
	fi

clean:
	rm -rf artifacts/harness/*
	touch artifacts/harness/.gitkeep
