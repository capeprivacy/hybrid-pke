.PHONY: pydep
pydep:
	pip install maturin~=0.13.0 pytest

.PHONY: pylib
pylib:
	maturin develop

.PHONY: install
install: pydep pylib

.PHONY: test
test:
	pytest .

.PHONY: fmt
fmt:
	cargo fmt

.PHONY: lint
lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings --no-deps

.PHONY: clean
clean:
	cargo clean

.PHONY: ci-ready
ci-ready: fmt lint test

.PHONY: ci-clean-check
ci-clean-check: clean ci-ready

.PHONY: release
release: ci-clean-check
	cargo release --execute
