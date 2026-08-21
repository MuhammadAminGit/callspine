.PHONY: setup test lint dev fault clean

setup:
	uv venv && uv pip install -e ".[dev]"

test:
	.venv/bin/python -m pytest -q

lint:
	.venv/bin/python -m ruff check src tests faultkit

dev:
	RETELL_API_KEY=$${RETELL_API_KEY:-dev-secret} \
	VAPI_SECRET=$${VAPI_SECRET:-dev-secret} \
	.venv/bin/python -m uvicorn callspine.app:app --reload --port 8000

fault:
	.venv/bin/python faultkit/replay.py --provider $${PROVIDER:-retell} --fault $${FAULT:-all}

clean:
	rm -f *.db && find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
