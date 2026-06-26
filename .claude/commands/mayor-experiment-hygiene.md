Clean up stale experiment artifacts.

1. Check for stale virtual environments: `find . -maxdepth 2 -name '.venv*' -type d -mtime +7`.
   - Report any found; do NOT delete without operator approval.
2. Check for orphaned experiment outputs: `find experiments/outputs/ -type f -mtime +7 2>/dev/null`.
   - Report any found with sizes.
3. Check for large generated files in `output/`: `find output/ -type f -size +50M 2>/dev/null`.
   - Report any found with sizes.
4. Check for stale `__pycache__` dirs: `find . -name '__pycache__' -type d | wc -l`.
   - If count > 20, suggest cleanup.
5. Report summary: N stale venvs, N orphaned outputs, N large files, N pycache dirs.
   If nothing to clean, report "all clean".
