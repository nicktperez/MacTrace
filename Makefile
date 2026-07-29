.PHONY: install demo live test reset-demo menubar package-macos

install:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

demo:
	.venv/bin/python -m mactrace --mode demo

live:
	.venv/bin/python -m mactrace --mode live

test:
	.venv/bin/pytest

reset-demo:
	.venv/bin/python -m mactrace.demo --reset

menubar:
	.venv/bin/python -m mactrace.menubar

package-macos:
	./scripts/build_macos_app.sh
