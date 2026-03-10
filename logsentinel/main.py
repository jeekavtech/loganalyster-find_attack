"""Entry point for the LogSentinel CLI."""

import os
import sys

# When running directly from the package folder, ensure the project root is on sys.path.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Try to import as a module when running from the project root, or as a script from inside the package.
try:
    from logsentinel.core.engine import main as engine_main
except ImportError:
    from core.engine import main as engine_main


if __name__ == "__main__":
    engine_main()
