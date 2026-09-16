"""Allow ``python -m arxml_secdiff`` alongside the installed console script."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
