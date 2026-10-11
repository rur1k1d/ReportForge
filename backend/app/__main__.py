"""Allow ``python -m app`` to act as the ReportForge CLI."""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())