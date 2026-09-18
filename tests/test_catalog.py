"""Tests for the control catalog.

These are data-integrity tests. They do not test Python logic so much as assert that the
catalog still says what NIST and the DoD methodology say -- so that a careless edit to a
point value or a dropped requirement fails loudly instead of quietly changing a score.
"""

from __future__ import annotations

import pytest

from nist171.catalog import load_catalog, load_objectives, objectives_for

# Requirement counts per family, from NIST SP 800-171 Rev 2.
EXPECTED_FAMILY_COUNTS = {
    "AC": 22,
    "AT": 3,
    "AU": 9,
    "CM": 9,
    "IA": 11,
    "IR": 3,
    "MA": 6,
    "MP": 9,
    "PS": 2,
    "PE": 6,
    "RA": 3,
    "CA": 4,
    "SC": 16,
    "SI": 7,
}

IN_SCOPE_FAMILIES = {"AC", "AU", "IA"}

# DoD Assessment Methodology v1.2.1, Annex A.
EXPECTED_POINTS = {
    "3.1.1": 5, "3.1.2": 5, "3.1.3": 1, "3.1.4": 1, "3.1.5": 3, "3.1.6": 1,
    "3.1.7": 1, "3.1.8": 1, "3.1.9": 1, "3.1.10": 1, "3.1.11": 1, "3.1.12": 5,
    "3.1.13": 5, "3.1.14": 1, "3.1.15": 1, "3.1.16": 5, "3.1.17": 5, "3.1.18": 5,
    "3.1.19": 3, "3.1.20": 1, "3.1.21": 1, "3.1.22": 1,
    "3.3.1": 5, "3.3.2": 3, "3.3.3": 1, "3.3.4": 1, "3.3.5": 5, "3.3.6": 1,
    "3.3.7": 1, "3.3.8": 1, "3.3.9": 1,
    "3.5.1": 5, "3.5.2": 5, "3.5.3": 5, "3.5.4": 1, "3.5.5": 1, "3.5.6": 1,
    "3.5.7": 1, "3.5.8": 1, "3.5.9": 1, "3.5.10": 5, "3.5.11": 1,
}

NA_IF_NOT_PERMITTED = {"3.1.12", "3.1.13", "3.1.16", "3.1.17", "3.1.18"}


@pytest.fixture(scope="module")
def catalog():
    return load_catalog()


@pytest.fixture(scope="module")
def objectives():
    return load_objectives()


# --------------------------------------------------------------------------------------
# Required by the build spec
# --------------------------------------------------------------------------------------


def test_catalog_has_exactly_110_requirements(catalog):
    assert len(catalog) == 110


def test_family_counts_match_nist(catalog):
    counts: dict[str, int] = {}
    for control in catalog:
        counts[control["family"]] = counts.get(control["family"], 0) + 1
    assert counts == EXPECTED_FAMILY_COUNTS


def test_exactly_42_requirements_are_in_scope(catalog):
    assert sum(1 for c in catalog if c["in_scope"]) == 42


def test_in_scope_requirements_have_valid_points(catalog):
    for control in catalog:
        if not control["in_scope"]:
            continue
        points = control["points"]
        assert isinstance(points, int), f"{control['id']} points is {points!r}, expected int"
        assert not isinstance(points, bool), f"{control['id']} points must not be a bool"
        assert points in {1, 3, 5}, f"{control['id']} has points {points}, expected 1, 3 or 5"


# --------------------------------------------------------------------------------------
# Additional integrity checks
# --------------------------------------------------------------------------------------


def test_requirement_ids_are_unique(catalog):
    ids = [c["id"] for c in catalog]
    assert len(ids) == len(set(ids))


def test_in_scope_is_true_exactly_for_ac_au_ia(catalog):
    for control in catalog:
        expected = control["family"] in IN_SCOPE_FAMILIES
        assert control["in_scope"] is expected, f"{control['id']} in_scope is wrong"


def test_points_match_dod_annex_a_exactly(catalog):
    actual = {c["id"]: c["points"] for c in catalog if c["in_scope"]}
    assert actual == EXPECTED_POINTS


def test_out_of_scope_requirements_have_null_points(catalog):
    for control in catalog:
        if not control["in_scope"]:
            assert control["points"] is None, f"{control['id']} should have null points"


def test_na_if_not_permitted_set_on_the_right_five(catalog):
    flagged = {c["id"] for c in catalog if c.get("na_if_not_permitted")}
    assert flagged == NA_IF_NOT_PERMITTED


def test_only_3_5_3_has_partial_credit(catalog):
    flagged = {c["id"] for c in catalog if c.get("partial_credit")}
    assert flagged == {"3.5.3"}


def test_every_requirement_has_non_empty_title(catalog):
    for control in catalog:
        assert control["title"].strip(), f"{control['id']} has an empty title"


def test_in_scope_requirements_have_800_53_mapping(catalog):
    for control in catalog:
        if control["in_scope"]:
            mapping = control["nist_800_53_rev4"]
            assert isinstance(mapping, list) and mapping, f"{control['id']} has no 800-53 mapping"


def test_out_of_scope_requirements_have_empty_mapping(catalog):
    for control in catalog:
        if not control["in_scope"]:
            assert control["nist_800_53_rev4"] == []


# --------------------------------------------------------------------------------------
# Objectives
# --------------------------------------------------------------------------------------


def test_objective_ids_are_unique(objectives):
    ids = [o["id"] for o in objectives]
    assert len(ids) == len(set(ids))


def test_every_in_scope_requirement_has_at_least_one_objective(catalog, objectives):
    covered = {o["control_id"] for o in objectives}
    for control in catalog:
        if control["in_scope"]:
            assert control["id"] in covered, f"{control['id']} has no assessment objective"


def test_objectives_only_cover_in_scope_requirements(catalog, objectives):
    in_scope_ids = {c["id"] for c in catalog if c["in_scope"]}
    for objective in objectives:
        assert objective["control_id"] in in_scope_ids


def test_objective_id_starts_with_its_control_id(objectives):
    for objective in objectives:
        assert objective["id"].startswith(objective["control_id"])


def test_objectives_have_text(objectives):
    for objective in objectives:
        assert objective["text"].strip(), f"{objective['id']} has no text"


def test_3_1_1_has_objectives_a_through_f():
    ids = [o["id"] for o in objectives_for("3.1.1")]
    assert ids == [f"3.1.1[{letter}]" for letter in "abcdef"]
