# Development guide

## Scope discipline

Implement one agreed task at a time. Establish inputs, outputs, state ownership, failure behavior, and resource limits before adding a subsystem. Update the architecture documentation when a boundary changes. Keep the README status accurate and distinguish planned behavior from implemented and validated behavior.

The current implementation is verified with Python 3.9.6, the standard library, and `unittest`. Choose packaging, build tools, configuration formats, and additional dependencies only when implementation tasks require them. Document consequential choices and their tradeoffs in this directory; introduce a decision-record convention when the first such decision is made. Do not add placeholder functions, unused abstractions, speculative services, or empty directory trees.

## Source and dependency policy

Use clear names and small modules with explicit responsibilities. Source code must contain zero comments, TODOs, commented-out code, unnecessary docstrings, or standalone explanatory strings. Documentation belongs in Markdown; do not use source comments to hold architecture notes or future-task lists.

Keep dependencies minimal. A new dependency needs an actual use, a maintenance and licensing assessment, and a reproducible versioning strategy appropriate to the eventual toolchain. Do not introduce package manifests or lockfiles before selecting that toolchain.

## Verification

For documentation changes, inspect the final file tree, resolve local links, check Markdown structure and whitespace, and verify that claims match existing files. Check that all required subsystems have a clear owner. Documentation-only work does not require installing a test runner.

For implementation changes, select checks based on the behavior and risk being changed. Follow the [test strategy](../tests/README.md), record commands and results, and state any unverified behavior. Introduce CI only when there are meaningful, reproducible checks to execute.

Before handing off work, review the diff and working-tree status when Git is available. Preserve unrelated work. Commits are performed only when explicitly requested by the repository owner.

## Research and evidence

Research records maintained by the investigator should identify the revision, relevant configuration, dataset origin and permission, labels, environment, method, and results. The current `DetectionExperiment` is only an immutable dataset/operation definition; it does not discover metadata, execute a study, or store these research records. Distinguish measured findings from hypotheses and account for false positives and false negatives. When baselines or models are introduced, separate fitting data from evaluation data and document leakage controls.

Use synthetic or appropriately sanitized fixtures with documented provenance. Keep raw traffic, credentials, local environments, generated outputs, and VM images out of version control. The root ignore file reduces accidental additions; it is not a substitute for reviewing content before staging it.

Follow the [VM-lab strategy](../labs/README.md) for security experiments. Do not treat success on a single lab scenario as evidence of production detection coverage.
