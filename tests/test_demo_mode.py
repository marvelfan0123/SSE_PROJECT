"""Tests for Demonstration Mode."""
import pytest
from core.demo_mode import is_demo_active, activate_demo_scenario, deactivate_demo_scenario, DEMO_ASSESSMENT_ID


def test_demo_mode_lifecycle():
    """Verify demo scenario activation and clean deactivation."""
    # Ensure starting clean
    deactivate_demo_scenario()
    assert is_demo_active() is False

    # Activate
    res = activate_demo_scenario()
    assert res["status"] == "success"
    assert is_demo_active() is True

    # Deactivate
    assert deactivate_demo_scenario() is True
    assert is_demo_active() is False

