<!--
Thanks for contributing! Please read CONTRIBUTING.md before opening this PR.
Keep PRs focused on a single concern — smaller PRs get reviewed faster.
-->

## Summary

<!-- What does this PR change, and why? -->

## Related issue

<!-- Link the issue this addresses, e.g. "Fixes #123". Open an issue first for anything beyond a trivial fix. -->
Fixes #

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behaviour, CLI flags, or YAML config structure)
- [ ] Documentation only
- [ ] Refactor / internal cleanup (no behaviour change)

## How was this tested?

<!-- Describe how you verified the change. Include commands and results where helpful. -->

## Checklist

- [ ] Tests added or updated, following the BDD naming convention `test_<module>_<does_behaviour>[_when_<state>]` (see `CLAUDE.md`)
- [ ] `.venv/bin/pytest tests/unit -q` passes locally
- [ ] `.venv/bin/ruff check src tests` is clean
- [ ] Idempotency preserved — running the same configs twice produces no changes on the second run (for diff/apply changes)
- [ ] Docs updated where behaviour, CLI flags, or YAML config structure changed (`README.md`, and `deploy/action.yml` inputs where relevant)
- [ ] My code follows the project's [coding conventions](../CONTRIBUTING.md#coding-conventions)
