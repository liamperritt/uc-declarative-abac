from __future__ import annotations

from uc_declarative_abac.domains import (
    Domain,
    compute_domain_diff,
)
from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.utils import parse_flat_scope


def test_domain_differ_creates_only_missing_domains_when_parent_is_available():
    desired = {
        Domain(tag_key="finance"),
        Domain(tag_key="finance/orders", parent_tag_key="finance"),
    }
    actual = {Domain(tag_key="finance", domain_id="parent-id")}

    diff = compute_domain_diff(desired, actual, ChangeLogger())

    assert diff.to_create == {
        Domain(
            tag_key="finance/orders",
            parent_domain_id="parent-id",
            parent_tag_key="finance",
        )
    }


def test_domain_differ_creates_parent_and_child_when_both_are_missing():
    desired = {
        Domain(tag_key="finance"),
        Domain(tag_key="finance/orders", parent_tag_key="finance"),
    }

    diff = compute_domain_diff(desired, set(), ChangeLogger())

    assert diff.to_create == {
        Domain(tag_key="finance"),
        Domain(tag_key="finance/orders", parent_tag_key="finance"),
    }


def test_domain_differ_logs_error_when_child_parent_is_unavailable():
    desired = {
        Domain(tag_key="finance/orders", parent_tag_key="finance"),
    }
    change_logger = ChangeLogger()

    diff = compute_domain_diff(desired, set(), change_logger)

    assert diff.to_create == set()
    assert change_logger.has_errors
    error = change_logger.errors[0]
    error_details = f"{error.context}: {error.exception}".lower()
    assert "finance" in error_details
    assert "parent" in error_details


def test_domain_differ_updates_existing_domain_when_description_differs():
    desired = {Domain(tag_key="finance", description="Finance data")}
    actual_domain = Domain(
        tag_key="finance",
        description="Legacy description",
        domain_id="domain-id",
        resource_name="domains/domain-id",
    )

    diff = compute_domain_diff(
        desired,
        {actual_domain},
        ChangeLogger(),
    )

    assert diff.to_update == {
        Domain(
            tag_key="finance",
            description="Finance data",
            domain_id="domain-id",
            resource_name="domains/domain-id",
        )
    }
    assert diff.old_values == {"finance": actual_domain}


def test_domain_differ_does_not_delete_actual_only_domain_without_scope():
    actual = {Domain(tag_key="finance/legacy", domain_id="legacy-id")}

    diff = compute_domain_diff(set(), actual, ChangeLogger())

    assert diff.to_delete == set()


def test_domain_differ_deletes_only_actual_domains_matching_deletion_scope():
    desired = {Domain(tag_key="finance/current")}
    current = Domain(tag_key="finance/current", domain_id="current-id")
    legacy = Domain(tag_key="finance/legacy", domain_id="legacy-id")
    marketing = Domain(tag_key="marketing", domain_id="marketing-id")

    diff = compute_domain_diff(
        desired,
        {current, legacy, marketing},
        ChangeLogger(),
        deletion_scope=parse_flat_scope("finance*"),
    )

    assert diff.to_delete == {legacy}


# ---
# Extended update mask tests


def test_domain_differ_records_description_only_update_mask():
    """Record update_masks when description changes in an existing domain."""
    desired = {Domain(tag_key="finance", description="Finance data")}
    actual = {
        Domain(
            tag_key="finance",
            description="Legacy",
            domain_id="d",
            resource_name="domains/d",
        )
    }

    diff = compute_domain_diff(desired, actual, ChangeLogger())

    assert diff.update_masks == {"finance": ("description",)}
    assert diff.to_update == {
        Domain(
            tag_key="finance",
            description="Finance data",
            domain_id="d",
            resource_name="domains/d",
        )
    }
    assert diff.old_values == {
        "finance": Domain(
            tag_key="finance",
            description="Legacy",
            domain_id="d",
            resource_name="domains/d",
        )
    }


def test_domain_differ_masks_subtitle_draft_and_icon_changes():
    """Record update_masks for subtitle, draft, and icon changes while description remains unchanged."""
    from uc_declarative_abac.domains import DomainIcon

    actual = {
        Domain(
            tag_key="finance",
            description="Fin",
            subtitle="old",
            draft=False,
            icon=DomainIcon(name="BANK", color="#000000"),
            domain_id="d",
            resource_name="domains/d",
        )
    }
    desired = {
        Domain(
            tag_key="finance",
            description="Fin",
            subtitle="new",
            draft=True,
            icon=DomainIcon(name="ROCKET", color="#FF5733"),
        )
    }

    diff = compute_domain_diff(desired, actual, ChangeLogger())

    # description NOT included since it's unchanged
    assert diff.update_masks == {"finance": ("subtitle", "draft", "icon")}
    assert len(diff.to_update) == 1
    updated_domain = next(iter(diff.to_update))
    assert updated_domain.subtitle == "new"
    assert updated_domain.draft is True
    assert updated_domain.icon == DomainIcon(name="ROCKET", color="#FF5733")
    # Keep domain_id and resource_name from actual
    assert updated_domain.domain_id == "d"
    assert updated_domain.resource_name == "domains/d"


def test_domain_differ_ignores_unmanaged_none_metadata_fields():
    """None desired fields are unmanaged; no update recorded if only those differ."""
    from uc_declarative_abac.domains import DomainIcon

    actual = {
        Domain(
            tag_key="finance",
            description="Fin",
            subtitle="keep",
            draft=True,
            icon=DomainIcon(name="BANK", color="#111111"),
            domain_id="d",
            resource_name="domains/d",
        )
    }
    # desired has None for subtitle, draft, icon (unmanaged)
    desired = {Domain(tag_key="finance", description="Fin")}

    diff = compute_domain_diff(desired, actual, ChangeLogger())

    # No update because description matches and other fields are unmanaged (None)
    assert diff.to_update == set()
    assert diff.update_masks == {}
    assert diff.old_values == {}
