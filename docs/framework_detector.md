# Framework Detector Specifications

## 1. Detection Engine

`FrameworkDetector` provides multi-source deterministic detection across filesystem manifests and AST markers without non-deterministic heuristics.

## 2. Detection Sources & Weights
- **Manifest File Scan** (Weight 0.6): Analyzes `requirements.txt`, `pyproject.toml`, `package.json`, `composer.json`, `go.mod`, etc.
- **AST Import Scan** (Weight 0.9): Detects framework package import aliases.
- **Instantiation Call Scan** (Weight 1.0): Identifies framework application initializations (`Flask(__name__)`, `FastAPI()`, `express()`, `gin.Default()`).

## 3. Output Schema

Returns `FrameworkDetectionResult`:
- `framework`: Upper-case framework identifier (e.g. `FLASK`, `FASTAPI`, `EXPRESS`, `DJANGO`, `NEXTJS`, `LARAVEL`, `GIN`).
- `version`: Version string.
- `language`: Primary programming language (`Python`, `JavaScript`, `PHP`, `Go`).
- `confidence`: Floating-point score [0.0 - 1.0].
- `capabilities`: Tuple of supported capabilities (`routing`, `middleware`, `orm`, `auth`, `config`, etc.).
- `evidence`: Tuple of string snippets supporting detection.
