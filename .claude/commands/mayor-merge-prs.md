Check for PRs ready to merge.

1. Check if a remote is configured: `git remote -v`. If no remote, report "no remote configured" and stop.
2. Run `gh pr list --state open` to list open PRs.
3. For each open PR:
   - Check CI status: `gh pr view <number> --json state,statusCheckRollup`.
   - If no checks configured (empty statusCheckRollup) and tests passed per PR body: merge-ready.
   - If all checks pass (0-fail, 0-pending): merge-ready.
   - If a check is failing on the touched surface: flag for fix-worker dispatch.
   - If a check is pending but structurally irrelevant to the diff: flag as `--admin` candidate with justification.
4. For merge-ready PRs: merge with `gh pr merge <number> --merge`, then:
   - `git pull --ff-only`
   - Verify the worker closed the bead (`bd show <id>` — close it if not).
   - Clean up the worktree: `git worktree remove <path>` and `git branch -d <branch>`.
   - Update `ai/dashboard.md`.
5. Report: N merged, N awaiting CI, N need fix-workers.
