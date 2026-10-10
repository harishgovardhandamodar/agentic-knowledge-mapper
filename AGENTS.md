# Agent development guidelines

## Running tests

Run Python tests:
```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

Run Fluid (React+TS) tests and typecheck:
```bash
cd fluid && npm test 2>/dev/null || npx vitest run
cd fluid && npx tsc --noEmit
```

## Linting

```bash
ruff check .
ruff format .  # optional
```

## CLI tool behavior
(Existing opencode instructions follow below)

