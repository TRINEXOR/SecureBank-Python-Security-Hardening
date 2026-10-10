"""One command: unit/functional/security tests -> attack simulation -> static analysis."""
import subprocess, sys
steps = [[sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
         [sys.executable, "attacks.py"], [sys.executable, "run_static_analysis.py"]]
for s in steps:
    if subprocess.call(s) != 0:
        sys.exit(1)
