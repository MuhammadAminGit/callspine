.PHONY: setup test lint dev fault clean

setup:
	uv venv && uv pip install -e ".[dev]"

test:
	.venv/bin/python -m pytest -q

lint:
	.venv/bin/python -m ruff check src tests faultkit

# These dev credentials match faultkit's defaults, so `make dev` + `make fault` just works.
dev:
	RETELL_API_KEY=$${RETELL_API_KEY:-dev-secret} \
	VAPI_SECRET=$${VAPI_SECRET:-dev-secret} \
	CALLSPINE_API_TOKEN=$${CALLSPINE_API_TOKEN:-dev-token} \
	.venv/bin/python -m uvicorn --factory callspine.app:create_app --reload --port 8000

fault:
	.venv/bin/python faultkit/replay.py --provider $${PROVIDER:-vapi} --fault $${FAULT:-all} --calls $${CALLS:-3}

clean:
	rm -f *.db *.db-wal *.db-shm && find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
