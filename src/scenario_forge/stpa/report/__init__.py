"""STPA HTML report package.

Generates a self-contained HTML report from a combined STPA output
directory containing SP1, SP2, and SP3 artifacts.
"""

from scenario_forge.stpa.report.generator import generate_report

__all__ = ["generate_report"]
