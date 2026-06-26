Clean up stale worktrees and orphan branches.

1. Run `git worktree list` — identify any worktrees beyond the main checkout.
2. For each non-main worktree, check if its branch has been merged to master.
   - If merged: `git worktree remove <path>` and `git branch -d <branch>`.
   - If unmerged but stale (no commits in 24h and no matching open bead): report to operator, do not remove.
3. Run `git branch --list 'worktree-agent-*'` — find orphan branches with no worktree.
   - If merged to master: `git branch -d <branch>`.
   - If unmerged: report to operator.
4. Check for stale tracking refs: `git remote prune origin --dry-run` (if remote exists).
5. Report summary: cleaned N worktrees, N branches, N stale refs. Or "all clean".
