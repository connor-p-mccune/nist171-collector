"""Control checks, one module per NIST SP 800-171 family.

``FAMILY_CHECKS`` is the registry the CLI runs from: family code to the ordered list of
check functions for that family. Adding a family means writing its module and adding one
line here.
"""

from __future__ import annotations

from nist171.checks import ac
from nist171.checks.common import Check

FAMILY_CHECKS: dict[str, list[Check]] = {
    "AC": ac.CHECKS,
}

#: Families with checks written, in reporting order.
AVAILABLE_FAMILIES = tuple(FAMILY_CHECKS)


def checks_for(families: list[str]) -> list[Check]:
    """Every check belonging to the named families, in registry order."""
    selected: list[Check] = []
    for family in families:
        code = family.strip().upper()
        if code not in FAMILY_CHECKS:
            raise KeyError(
                f"Unknown family {code!r}. Available: {', '.join(AVAILABLE_FAMILIES)}."
            )
        selected.extend(FAMILY_CHECKS[code])
    return selected
