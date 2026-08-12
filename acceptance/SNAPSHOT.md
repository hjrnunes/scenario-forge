# Acceptance snapshot contract

`features/` is the only committed source root for the acceptance snapshot.
IR, generated tests, and metadata stay tracked until Plan B moves them to
build output.

## Mapping

```text
features/<rel>.feature
  → acceptance/ir/<rel>.json
  → acceptance/generated/<stem>_acceptance_test.py
  → acceptance/generated/metadata/<slug>.json

acceptance/dry/<rel>.txt     gitignored DRY reports only
```

`<rel>` keeps subdirectories. Generated tests stay flat; duplicate stems are
an error.

Metadata stores repository-relative paths only:

```json
{
  "schema_version": 1,
  "feature_path": "features/sp1_revision.feature",
  "ir_path": "acceptance/ir/sp1_revision.json",
  "feature_hash": "sha256:...",
  "implementation_hash": "sha256:...",
  "hash_scope": "generated_files",
  "generated_files": ["sp1_revision_acceptance_test.py"]
}
```

Generated tests resolve IR from the repository root. They must not embed
`/Users/`, `/private/`, or `file://` paths.

## Membership

A `.feature` file is in the snapshot if and only if it lives under
`features/`. Leftover Gherkin under `acceptance/features/` or
`tests/stpa/features/` is not generated until someone moves it here.

Refresh with:

```bash
uv run python acceptance/refresh_snapshot.py
```

The current APS `gherkin-parser` does not emit step data tables. Refresh
keeps existing `data_table` fields when a reparse would drop them, then
regenerates tests and metadata. Plan B needs an APS parser that preserves
tables before IR can be treated as disposable.

Then run `uv run pytest acceptance/generated/`.

## Plan B

Plan B will keep `features/` as the only committed input and regenerate IR,
DRY reports, and tests into ignored `build/acceptance/` directories.
