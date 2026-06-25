Refresh the mayor dashboard at `ai/dashboard.md`.

1. Read current `ai/dashboard.md`.
2. Check `bd list` for tracker state.
3. Check `git worktree list` for in-flight workers.
4. Check `gh pr list` for open PRs (if remote exists).
5. Check `git log --oneline -5` for recent merges.
6. Rewrite `ai/dashboard.md` with current timestamp and updated sections.
7. Keep it short enough that a returning operator re-orients in 30 seconds.
