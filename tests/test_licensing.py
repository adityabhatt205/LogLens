"""Tests for the enterprise-detection seam.

The commercial ``loglens-enterprise`` add-on is not installed in the
open-source test environment, so these tests verify the safe-default
(standard version) behaviour.
"""

from __future__ import annotations

from loglens import licensing


def test_enterprise_not_available_by_default() -> None:
    assert licensing.enterprise_available() is False


def test_enterprise_version_is_none_without_addon() -> None:
    assert licensing.enterprise_version() is None
