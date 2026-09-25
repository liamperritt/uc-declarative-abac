from __future__ import annotations

from unittest.mock import MagicMock

from uc_declarative_abac.domains import (
    Domain,
    DomainIcon,
    compute_domain_diff,
)
from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.principals import Principal, PrincipalResolver
from uc_declarative_abac.types import PrincipalType
from uc_declarative_abac.utils import PrincipalValidationError, parse_flat_scope


def _resolver_passthrough() -> PrincipalResolver:
    """A resolver whose ws_helper is never consulted — tests declare no owners."""
    return PrincipalResolver(MagicMock())


def _resolver(
    name_to_principal: dict[str, Principal] | None = None,
    identifier_to_principal: dict[str, Principal] | None = None,
) -> PrincipalResolver:
    """Build a resolver backed by a ws_helper mock that knows specific principals."""
    ws_helper = MagicMock()
    name_to_principal = name_to_principal or {}
    identifier_to_principal = identifier_to_principal or {}

    def _by_name(name: str) -> Principal:
        if name in name_to_principal:
            return name_to_principal[name]
        raise PrincipalValidationError(f"Principal not found: {name}")

    def _by_identifier(identifier: str) -> Principal:
        if identifier in identifier_to_principal:
            return identifier_to_principal[identifier]
        raise PrincipalValidationError(
            f"Principal not found by identifier: {identifier}"
        )

    ws_helper.resolve_by_name.side_effect = _by_name
    ws_helper.resolve_by_identifier.side_effect = _by_identifier
    return PrincipalResolver(ws_helper)


def _unresolved_by_name(name: str) -> Principal:
    return Principal(PrincipalType.UNKNOWN, name=name)


def _unresolved_by_identifier(identifier: str) -> Principal:
    return Principal(PrincipalType.UNKNOWN, identifier=identifier)


def _user(name: str, identifier: str) -> Principal:
    return Principal(PrincipalType.USER, name=name, identifier=identifier)


def test_domain_differ_creates_only_missing_domains_when_parent_is_available():
    desired = {
        Domain(tag_key="finance"),
        Domain(tag_key="finance/orders", parent_tag_key="finance"),
    }
    actual = {Domain(tag_key="finance", domain_id="parent-id")}

    diff = compute_domain_diff(desired, actual, ChangeLogger(), _resolver_passthrough())

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

    diff = compute_domain_diff(desired, set(), ChangeLogger(), _resolver_passthrough())

    assert diff.to_create == {
        Domain(tag_key="finance"),
        Domain(tag_key="finance/orders", parent_tag_key="finance"),
    }


def test_domain_differ_logs_error_when_child_parent_is_unavailable():
    desired = {
        Domain(tag_key="finance/orders", parent_tag_key="finance"),
    }
    change_logger = ChangeLogger()

    diff = compute_domain_diff(desired, set(), change_logger, _resolver_passthrough())

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
        _resolver_passthrough(),
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

    diff = compute_domain_diff(set(), actual, ChangeLogger(), _resolver_passthrough())

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
        _resolver_passthrough(),
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

    diff = compute_domain_diff(desired, actual, ChangeLogger(), _resolver_passthrough())

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

    diff = compute_domain_diff(desired, actual, ChangeLogger(), _resolver_passthrough())

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

    diff = compute_domain_diff(desired, actual, ChangeLogger(), _resolver_passthrough())

    # No update because description matches and other fields are unmanaged (None)
    assert diff.to_update == set()
    assert diff.update_masks == {}
    assert diff.old_values == {}


# ---
# Owner reconciliation tests (business_owners / technical_owners)


def test_domain_differ_masks_owner_change_via_resolved_comparison():
    """A changed business owner set is masked with the SDK token business_owner_ids."""
    resolver = _resolver(
        name_to_principal={"alice": _user("alice", "alice@co")},
        identifier_to_principal={"bob@co": _user("bob", "bob@co")},
    )
    desired = {
        Domain(
            tag_key="finance",
            description="Fin",
            business_owners=frozenset({_unresolved_by_name("alice")}),
        )
    }
    actual = {
        Domain(
            tag_key="finance",
            description="Fin",
            domain_id="d",
            resource_name="domains/d",
            business_owners=frozenset({_unresolved_by_identifier("bob@co")}),
        )
    }

    diff = compute_domain_diff(desired, actual, ChangeLogger(), resolver)

    assert diff.update_masks == {"finance": ("business_owner_ids",)}
    updated = next(iter(diff.to_update))
    assert updated.business_owners == frozenset({_user("alice", "alice@co")})


def test_domain_differ_ignores_owner_reorder_as_no_change():
    """Owners that resolve to the same set (regardless of source dialect) are no change."""
    resolver = _resolver(
        name_to_principal={
            "alice": _user("alice", "alice@co"),
            "carol": _user("carol", "carol@co"),
        },
        identifier_to_principal={
            "alice@co": _user("alice", "alice@co"),
            "carol@co": _user("carol", "carol@co"),
        },
    )
    desired = {
        Domain(
            tag_key="finance",
            description="Fin",
            business_owners=frozenset(
                {_unresolved_by_name("alice"), _unresolved_by_name("carol")}
            ),
        )
    }
    actual = {
        Domain(
            tag_key="finance",
            description="Fin",
            domain_id="d",
            resource_name="domains/d",
            business_owners=frozenset(
                {
                    _unresolved_by_identifier("carol@co"),
                    _unresolved_by_identifier("alice@co"),
                }
            ),
        )
    }

    diff = compute_domain_diff(desired, actual, ChangeLogger(), resolver)

    assert diff.to_update == set()
    assert diff.update_masks == {}


def test_domain_differ_treats_none_owners_as_unmanaged():
    """Owners left None on desired never produce an owner update, even if actual has owners."""
    resolver = _resolver(
        identifier_to_principal={"bob@co": _user("bob", "bob@co")},
    )
    desired = {Domain(tag_key="finance", description="Fin")}
    actual = {
        Domain(
            tag_key="finance",
            description="Fin",
            domain_id="d",
            resource_name="domains/d",
            business_owners=frozenset({_unresolved_by_identifier("bob@co")}),
        )
    }

    diff = compute_domain_diff(desired, actual, ChangeLogger(), resolver)

    assert diff.to_update == set()
    assert diff.update_masks == {}


def test_domain_differ_fails_when_config_owner_is_unresolvable():
    """A config-side (name) owner that cannot be resolved is a fatal error."""
    resolver = _resolver()
    change_logger = ChangeLogger()
    desired = {
        Domain(
            tag_key="finance",
            description="Fin",
            technical_owners=frozenset({_unresolved_by_name("ghost")}),
        )
    }

    compute_domain_diff(desired, set(), change_logger, resolver)

    assert change_logger.has_errors


def test_domain_differ_warns_and_drops_unresolvable_actual_owner():
    """An actual-side (identifier) owner that cannot be resolved warns and is dropped."""
    resolver = _resolver()
    change_logger = ChangeLogger()
    desired = {Domain(tag_key="finance", description="Fin")}
    actual = {
        Domain(
            tag_key="finance",
            description="Fin",
            domain_id="d",
            resource_name="domains/d",
            business_owners=frozenset({_unresolved_by_identifier("system-sp-uuid")}),
        )
    }

    diff = compute_domain_diff(desired, actual, change_logger, resolver)

    assert not change_logger.has_errors
    assert change_logger.warnings
    assert diff.to_update == set()
