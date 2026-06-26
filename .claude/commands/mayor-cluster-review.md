Check for clustering opportunities among open beads.

1. Run `bd list --status=open` to get all open issues.
2. If fewer than 3 open issues, report "too few for clustering" and stop.
3. Group issues by touched surface (infer from title/description — same module, same file pattern).
4. For any group with 3+ same-surface beads at P3/P4:
   - Propose a cluster: list the bead IDs, the shared surface, and a draft PR title.
   - Do NOT dispatch — present the cluster proposal to the operator.
5. For P1/P2 beads: always flag as solo candidates, never cluster.
6. Report: N clusters proposed, N solo candidates, N unclusterable.
