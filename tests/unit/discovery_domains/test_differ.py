from __future__ import annotations

from uc_declarative_abac.discovery_domains import (
    DiscoveryDomain,
    compute_discovery_domain_diff,
)
from uc_declarative_abac.logger import ChangeLogger


def test_discovery_domain_differ_creates_only_missing_domains_when_parent_is_available():
    desired = {
        DiscoveryDomain(tag_key="finance"),
        DiscoveryDomain(tag_key="finance/orders", parent_tag_key="finance"),
    }
    actual = {DiscoveryDomain(tag_key="finance", domain_id="parent-id")}

    diff = compute_discovery_domain_diff(desired, actual, ChangeLogger())

    assert diff.to_create == {
        DiscoveryDomain(
            tag_key="finance/orders",
            parent_domain_id="parent-id",
            parent_tag_key="finance",
        )
    }


def test_discovery_domain_differ_creates_parent_and_child_when_both_are_missing():
    desired = {
        DiscoveryDomain(tag_key="finance"),
        DiscoveryDomain(tag_key="finance/orders", parent_tag_key="finance"),
    }

    diff = compute_discovery_domain_diff(desired, set(), ChangeLogger())

    assert diff.to_create == {
        DiscoveryDomain(tag_key="finance"),
        DiscoveryDomain(tag_key="finance/orders", parent_tag_key="finance"),
    }


def test_discovery_domain_differ_logs_error_when_child_parent_is_unavailable():
    desired = {
        DiscoveryDomain(tag_key="finance/orders", parent_tag_key="finance"),
    }
    change_logger = ChangeLogger()

    diff = compute_discovery_domain_diff(desired, set(), change_logger)

    assert diff.to_create == set()
    assert change_logger.has_errors
    error = change_logger.errors[0]
    error_details = f"{error.context}: {error.exception}".lower()
    assert "finance" in error_details
    assert "parent" in error_details


def test_discovery_domain_differ_updates_existing_domain_when_description_differs():
    desired = {DiscoveryDomain(tag_key="finance", description="Finance data")}
    actual_domain = DiscoveryDomain(
        tag_key="finance",
        description="Legacy description",
        domain_id="domain-id",
        resource_name="domains/domain-id",
    )

    diff = compute_discovery_domain_diff(
        desired,
        {actual_domain},
        ChangeLogger(),
    )

    assert diff.to_update == {
        DiscoveryDomain(
            tag_key="finance",
            description="Finance data",
            domain_id="domain-id",
            resource_name="domains/domain-id",
        )
    }
    assert diff.old_values == {"finance": actual_domain}
