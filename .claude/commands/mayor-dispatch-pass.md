Review open beads and dispatch workers for ready items.

1. Run `bd ready` to find issues with no blockers.
2. Filter OUT:
   - Issues requiring operator decisions (surface to operator instead).
   - EPICs (break down first).
   - Issues coupled to a release gate.
   - Issues touching a hot zone where another worker is active (check `git worktree list`).
3. For each dispatchable bead:
   - Verify the issue is still valid: grep for the alleged broken symbol/missing file.
   - If already fixed, close as verified-duplicate with cross-ref.
   - Otherwise, choose solo vs cluster (P1/P2 → solo; P3/P4 same-surface group of 3+ → cluster).
4. Dispatch workers using the canonical prompt shape from `ai/dispatch-prompt-template.md`:
   - Dedicated worktree per worker.
   - Inject project stance from dashboard.
   - List other in-flight workers and their write surfaces.
   - Include worktree boundary block verbatim.
5. Update `ai/dashboard.md` with in-flight work.
6. Report: N dispatched, N deferred (reason), N need operator decision.
