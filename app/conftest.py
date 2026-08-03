"""One log directory for the whole suite, bound before `main` is imported.

test_main.py used to set HB_LOG_DIR unconditionally at import time, which
overrode the value the README and AGENTS.md tell you to pass and left the suite
dependent on pytest collecting test_main before test_regressions. Collect them
in the other order and test_main failed.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
os.environ.setdefault("HB_LOG_DIR", tempfile.mkdtemp(prefix="hb-test-"))
