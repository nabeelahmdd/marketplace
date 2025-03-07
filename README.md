# Python Code Formatting Setup Guide

This guide helps you set up automatic code formatting for Python projects using pre-commit hooks.

## Prerequisites

- Python 3.x installed
- pip (Python package installer)
- git initialized in your project

## Step 1: Clone and Setup Project

```bash
# Clone the project
git clone <project-url>
cd <project-name>

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install project requirements (includes all formatting tools)
pip install -r requirements.txt
```

## Step 2: Create Configuration Files

### 1. Create `.pre-commit-config.yaml`

```yaml
# .pre-commit-config.yaml
exclude: "(frontend/.*|migrations/.*|node_modules/.*|__init__.py)"

repos:
  - repo: https://github.com/psf/black
    rev: 24.10.0
    hooks:
      - id: black
        args: ["--line-length=80"]
        language_version: python3
        types: [python]

  - repo: https://github.com/pycqa/isort
    rev: 5.13.2
    hooks:
      - id: isort
        args: ["--profile", "black", "--line-length", "80"]
        types: [python]

  - repo: https://github.com/charliermarsh/ruff-pre-commit
    rev: v0.1.14
    hooks:
      - id: ruff
        args: ["--fix"]
        types: [python]
```

### 2. Create `pyproject.toml`

```toml
[tool.black]
line-length = 80
skip-string-normalization = true
extend-exclude = '''
(
  frontend/.*
  | migrations/.*
)
'''

[tool.ruff]
line-length = 80

[tool.ruff.lint]
select = ["E", "F", "D", "W"]
ignore = ["D100", "D101", "D102", "D103", "D104", "D105", "D106", "D107", "D200", "D205", "D400", "D401", "D415"]

[tool.ruff.lint.per-file-ignores]
"__init__.py" = ["E402", "F401"]

[tool.isort]
profile = "black"
line_length = 80
multi_line_output = 3
include_trailing_comma = true
force_grid_wrap = 0
use_parentheses = true
ensure_newline_before_comments = true
skip = ["migrations", "frontend"]
```

### 3. Create `.flake8`

```ini
[flake8]
max-line-length = 80
extend-ignore = E203, W503, W293
exclude =
    .git,
    __pycache__,
    build,
    dist,
    *.egg-info,
    */migrations/*,
    frontend/*,
    venv
ignore = D100, D101, D102, D103, D104, D105, D106, D107, D200, D205, D400, D401
```

### 4. Create `.editorconfig`

```ini
[*.py]
max_line_length = 80
indent_style = space
indent_size = 4
```

## Step 3: Install Pre-commit Hooks

```bash
# Remove existing hooks if any
rm -rf .git/hooks/*

# Clean pre-commit cache
pre-commit clean

# Uninstall any existing pre-commit hooks
pre-commit uninstall

# Install hooks
pre-commit install

# Test the setup
pre-commit run --all-files
```

## What This Setup Does

- **Black**: Code formatting
- **isort**: Import sorting
- **ruff**: Fast Python linter
- Line length is set to 80 characters
- Ignores:
  - Frontend files
  - Migration files
  - `__init__.py` files
  - node_modules

## Usage

The hooks will run automatically when you commit changes. They will:
1. Format your Python code (black)
2. Sort imports (isort)
3. Fix common issues (ruff)

If any tool modifies files, the commit will fail. Simply add the modified files and commit again.

```bash
# If commit fails due to formatting
git add .
git commit -m "Your message"  # Try committing again
```

## Manual Running

To run formatting on all files manually:
```bash
pre-commit run --all-files
```

To run on specific files:
```bash
pre-commit run --files path/to/file.py
```

## VS Code Integration

Add these settings to your `.vscode/settings.json`:

```json
{
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true
    },
    "editor.defaultFormatter": "ms-python.python",
    "[python]": {
        "editor.formatOnSave": true,
        "editor.defaultFormatter": "ms-python.python"
    },
    "python.formatting.provider": "black",
    "python.formatting.blackArgs": ["--line-length=80"],
    "files.trimTrailingWhitespace": true,
    "files.insertFinalNewline": true
}
```

## Troubleshooting

If hooks aren't running on commit:
1. Make sure you've activated your virtual environment: `source venv/bin/activate`
2. Verify requirements are installed: `pip freeze`
3. Reinstall hooks: `pre-commit install`
4. Check hook status: `pre-commit run --all-files`

If you get errors about missing tools:
```bash
# Make sure you're in your virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Reinstall requirements
pip install -r requirements.txt
```

## Note for Team Members
All required formatting tools (black, isort, ruff, pre-commit) are included in the project's `requirements.txt`. You don't need to install them separately if you've installed the project requirements.
