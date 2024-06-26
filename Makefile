.PHONY: pydep
pydep:
	pip install -r requirements-dev.txt

.PHONY: pydep-upgrade
pydep-upgrade:
	pip install -U pip-tools
	CUSTOM_COMPILE_COMMAND="make pydep-upgrade" pip-compile --output-file requirements-dev.txt requirements-dev.in
	pip install -r requirements-dev.txt

.PHONY: pylib
pylib:
	maturin develop

.PHONY: install
install: pydep pylib

.PHONY: test
test:
	pytest -n auto .

.PHONY: fmt
fmt:
	cargo fmt
	isort .
	ruff format .

.PHONY: lint
lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings --no-deps
	ruff .

.PHONY: clean
clean:
	cargo clean
	find ./ -depth -type d -name '__pycache__' -prune -print -exec rm -rf {} +

.PHONY: ci-ready
ci-ready: fmt lint test

.PHONY: ci-ready-clean
ci-ready-clean: clean ci-ready

.PHONY: release
release: ci-ready-clean
	cargo release --execute
