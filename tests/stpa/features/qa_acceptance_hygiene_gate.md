# QA Suite: Acceptance hygiene gate

## QA-AHG-01: Quality script runs Ruff check on src and acceptance

1. Run `scripts/quality.sh`.
2. Verify the script executes `uv run ruff check src acceptance`.
3. Verify exit code 0 when both directories are clean.

## QA-AHG-02: Quality script runs Ruff format check on src and acceptance

1. Run `scripts/quality.sh`.
2. Verify the script executes `uv run ruff format --check src acceptance`.
3. Verify exit code 0 when both directories are formatted.

## QA-AHG-03: Acceptance test path enforces hygiene gate

1. Run `./scripts/acceptance.sh --test`.
2. Verify the hygiene gate (ruff check + format check) runs BEFORE pytest.
3. Introduce a temporary lint error in an acceptance file.
4. Run `./scripts/acceptance.sh --test` again.
5. Verify the script exits non-zero before reaching pytest.

## QA-AHG-04: Acceptance code is Ruff-clean

1. Run `uv run ruff check acceptance`.
2. Verify zero findings.

## QA-AHG-05: Acceptance code is Ruff-formatted

1. Run `uv run ruff format --check acceptance`.
2. Verify zero files need reformatting.

## QA-AHG-06: CRAP/DRY/mutation scope is src only

1. Read `.factory/swarmforge/config.sh`.
2. Verify `SWARMFORGE_CRAP_CMD` targets `src/`.
3. Verify `SWARMFORGE_DRY_CMD` targets `src/` or `./src`.
4. Verify `SWARMFORGE_MUTATION_CMD` targets `src/`.
5. Verify no acceptance path appears in any of those commands.

## QA-AHG-07: Runtime manifest loads and registers handlers

1. Import `acceptance.runtime_manifest`.
2. Load the manifest.
3. Import every listed runtime feature module.
4. Verify no module raises on import.
5. Verify every registered handler has a non-empty step pattern.

## QA-AHG-08: Generated-output paths remain unchanged

1. Run `./scripts/acceptance.sh` (full generation).
2. Verify `build/acceptance/ir/` contains IR JSON for each feature.
3. Verify `build/acceptance/generated/` contains test files.
4. Verify `build/acceptance/generated/metadata/` contains metadata with relative paths.
5. Verify `git status` shows no generated artifacts staged or tracked.
