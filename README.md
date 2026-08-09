# Jane Verify

**Software validation, testing and documentation built on JaneOS.**

Jane Verify is a separate Jane product. It does not embed or duplicate JaneOS cognition or the Capability Kernel. It registers as a JaneOS application, requests explicit project-scoped capabilities, and is designed to be managed by Jane.

## v1.0

- Detects PHP/Symfony/Laravel, Node/TypeScript/Angular/Vue/React, Python, Java/Spring and .NET projects.
- Runs deterministic validator/test adapters. Commands are adapter-owned, never model-generated, and use `shell=False`.
- Requires JaneOS capability authorization before reads or execution.
- Delegates only authorized project scopes from Jane to the `jane.verify` actor.
- Trusted project mode uses a scrubbed child environment.
- Untrusted project mode requires Docker/Podman, disables networking, drops capabilities, limits resources and hard-kills timed-out containers.
- Performs read-only heuristic code/security inspection.
- Generates Markdown project documentation and validation reports into Jane Verify's own data directory, never into the project by default.
- Includes CLI, REST API and a dependency-free local dashboard.

## JaneOS contract

Provides: `software.validate`, `stack.detect`, `tests.run`, `code.inspect`, `security.inspect`, `documentation.generate`, `report.generate`.

Requires: `review.project.read`, `review.validator.execute`.

Installing Verify grants nothing. A project must be explicitly authorized.

## Setup

```bash
pip install -e ../JaneOS_v0.7.0
pip install -e '.[api,dev]'
pytest -q
```

```bash
jane-verify /path/to/project
jane-verify /path/to/project --trust untrusted
jane-verify --serve
```

Dashboard: `http://127.0.0.1:8010/`

## Product boundary

JaneOS remains Jane's cognitive/runtime platform. Jane is the persistent AI agent and manager. Jane Verify is an application running on JaneOS capabilities and managed by Jane.
