"""Shared validation helpers for boundary schema cross-reference checks."""

from __future__ import annotations


def check_duplicate_ids(ids: list[str], field_name: str) -> None:
    """Raise ValueError if *ids* contains duplicates.

    Args:
        ids: List of identifier strings to check.
        field_name: Human-readable field name used in the error message.

    Raises:
        ValueError: If any ID appears more than once.
    """
    seen: set[str] = set()
    for id_val in ids:
        if id_val in seen:
            raise ValueError(f"Duplicate {field_name}: '{id_val}'.")
        seen.add(id_val)


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T23:13:34Z","module_hash":"879d75f0524c181e34e415e9e0417e5d1b99bc933ce798f6d8dd132f91d1e57a","functions":[{"id":"func/check_duplicate_ids","name":"check_duplicate_ids","line":6,"end_line":20,"hash":"1540481fe3f73258f032a832bef43941f9cfa31c513a53b58e4a7e46b81b2726"}]}
# mutate4py-manifest-end
