# Framework Testing Kit Guidelines

## 1. Test Kit Overview

All framework extractors and semantic tests MUST utilize `tests/framework_testkit.py`.

## 2. Provided Test Infrastructure
- `FixtureLoader`: Loads golden fixture files and directories under `tests/fixtures/`.
- `FrameworkAssertions`: Validates presence of routes, handlers, middlewares, models, configs, and auth policies in ISR.
- `SnapshotAssertions`: Performs deterministic dictionary and JSON snapshot comparisons.
- `ASTAssertions`: Validates AST node structure properties.
- `ISRAssertions`: Enforces ISR schema versioning and mandatory contract attributes.

## 3. Recommended Test Pattern
```python
from tests.framework_testkit import FixtureLoader, FrameworkAssertions, ISRAssertions

def test_flask_extraction():
    fixture_path = FixtureLoader.get_fixture_path("flask")
    # Execute extractor...
    ISRAssertions.assert_valid_isr(result.isr)
    FrameworkAssertions.assert_route_exists(result.isr, "/login", "POST")
```
