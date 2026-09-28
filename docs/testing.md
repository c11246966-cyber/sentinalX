# SentinelX Automated Testing Strategy

## 1. Test Suite Organization

```
tests/
├── conftest.py               # Shared pytest fixtures & FastAPI TestClient
├── test_health.py            # Healthcheck endpoints & dependency fallback tests
├── test_config.py            # Pydantic configuration & CORS parser tests
└── test_models_syntax.py     # Schema & validation integrity tests
```

## 2. Running Automated Tests

### Python Backend Unit & Integration Tests (pytest)
```bash
pytest -v tests/
```

### Direct Unittest Execution (Zero external dependencies)
```bash
python3 -m unittest discover tests
```

### TypeScript Frontend Compilation & Type Verification
```bash
npm run build
npm run lint
```
