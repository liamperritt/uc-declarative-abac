# Contributing to UC Declarative ABAC

## Before getting started

First of all — thank you. The fact that you're reading this means you're considering giving up some of your time to make this project better, and that's genuinely appreciated. We want contributing here to be a friendly, low-friction experience, so if anything in this guide is unclear, that's a bug in the guide — please tell us.

## How to contribute

Contributions are managed through GitHub. The best place to start is by opening an issue or a discussion before writing code, so we can agree on the approach together and avoid wasted effort:

- **Bugs and feature requests** — open a [GitHub Issue](https://github.com/liamperritt/uc-declarative-abac/issues). Include what you expected, what happened, and a minimal config or repro where relevant.
- **Questions, ideas, and design discussion** — start a [GitHub Discussion](https://github.com/liamperritt/uc-declarative-abac/discussions) (or an issue if Discussions aren't enabled). This is the right venue to float a change, ask how something works, or propose where you could help.
- **Code changes** — fork the repo, create a branch, and open a Pull Request against `main`. Keep PRs focused on a single concern; smaller PRs get reviewed faster. All PRs are reviewed by the code owners listed in [`.github/CODEOWNERS`](.github/CODEOWNERS).

**ProTip:** Be kind and be patient. Maintainers and fellow contributors are volunteering their time. Assume good faith, keep feedback constructive, and remember there's a real person on the other side of the thread.

Please note we have a [code of conduct](#code-of-conduct) — please follow it in all your interactions with the project.

## Getting started

**Set up your environment.** This project uses [`uv`](https://github.com/astral-sh/uv) and targets Python 3.11+:

```bash
uv venv
uv sync --extra dev
```

Run the test suite before and after your change:

```bash
.venv/bin/pytest tests/unit -q
```

**Working on a change:**

- **Open an issue first** for anything beyond a trivial fix, and reference it from your PR (e.g. `Fixes #123`).
- **Write tests.** This project is developed with Test-Driven / Behaviour-Driven Development — add or update tests alongside (ideally before) the implementation. The full conventions live in [`CLAUDE.md`](CLAUDE.md).
- **Keep the engine idempotent.** Running the same configs twice must produce no changes on the second run; please verify this for any change to the diff/apply pipeline.
- **Update the docs.** If you change behaviour, CLI flags, or YAML config structure, update [`README.md`](README.md) (and the GitHub Action inputs in [`deploy/action.yml`](deploy/action.yml) where relevant) in the same PR.
- **Describe your change** clearly in the PR description: what changed, why, and how you verified it.

**ProTip:** It's frustrating to have a contribution pushed back over a process nobody told you about. If you hit such a case, please open an issue so we can document it here and lower the barrier for the next person.

## Coding conventions

Code should be optimized for readability. This is a Python project; please follow standard Python conventions and the project-specific guidelines documented in [`CLAUDE.md`](CLAUDE.md). In short:

- **Formatting and linting** — code is linted with [Ruff](https://docs.astral.sh/ruff/). Run `.venv/bin/ruff check src tests` and keep it clean.
- **Tests** — use `pytest`. Test functions are root-level (no test classes) and follow the BDD naming convention `test_<module>_<does_behaviour>[_when_<state>]`. Tests should exercise only public interfaces.
- **Structure** — prefer small, flat, well-named helper functions over deep nesting; define helpers above their callers (no forward references within a module); favour immutability (return new values rather than mutating arguments).
- **Databricks integration** — use the `databricks-sdk` for API calls, `pyyaml` for config parsing, and query UC system tables (not APIs) to determine deployed state.

When in doubt, match the style of the surrounding code.

## Code of Conduct

We are committed to providing a welcoming and harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation. We will not discriminate against anyone on any grounds other than the merits of their contributions.

Examples of behaviour that contributes to a positive environment include using welcoming and inclusive language, respecting differing viewpoints, gracefully accepting constructive criticism, and showing empathy toward other community members. Harassment, insulting or derogatory comments, personal or political attacks, public or private harassment, and other conduct that could reasonably be considered inappropriate are not acceptable.

Project maintainers are responsible for clarifying these standards and may take appropriate and fair corrective action — including editing or removing comments, commits, code, issues, and pull requests, or temporarily or permanently banning any contributor — in response to behaviour they deem inappropriate, threatening, offensive, or harmful.

This Code of Conduct is adapted from the [Contributor Covenant](https://www.contributor-covenant.org), version 1.4, available at <https://www.contributor-covenant.org/version/1/4/code-of-conduct/>. To report unacceptable behaviour, please contact the maintainers via a [GitHub Issue](https://github.com/liamperritt/uc-declarative-abac/issues) or by reaching out to the code owners listed in [`.github/CODEOWNERS`](.github/CODEOWNERS).
