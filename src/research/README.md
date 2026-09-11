# Research examples

`research` exports `ResearchExample(projection, ground_truth=None)` from [research_example.py](research_example.py). It associates an existing [MLFeatureProjection](../ml/README.md) with explicitly supplied research truth. This package owns experimental data representation; it implements no detector, evaluation, or learning operation.

## Contract

| Field | Meaning |
| --- | --- |
| `projection` | Exactly an existing `MLFeatureProjection`, retained by reference. Its feature contract, ordered names, and values remain authoritative. |
| `ground_truth` | An optional exact built-in nonblank string supplied by the caller. `None` means truth was not supplied. |

Truth is opaque text with caller-defined meaning, not a built-in binary label or attack vocabulary. Case, Unicode, and surrounding whitespace are preserved; entirely blank strings are rejected. No category encoding or conversion is performed. Booleans, numeric targets, collections, string subclasses, detector decisions, and evaluation truth records are not accepted as truth. There is no implicit conversion of these values to strings. Richer or numerical research targets would require a separate explicit contract decision.

The existing [GroundTruthRecord](../application/ground_truth.py) describes a detector-specific evaluation target and its explicit positive/negative polarity. It is not interchangeable with research truth. `ResearchExample` neither imports nor converts it, and never derives truth from findings, configurations, thresholds, evaluation results, or predictions. Callers remain responsible for supplying independently established truth; a string type cannot authenticate its origin or experimental meaning.

## Features, ownership, and identity

Construction accepts only an already-created projection. It does not read a snapshot, extract features, inspect packet/flow state, or copy feature definitions. Projection construction owns feature-version compatibility; the example introduces no second supported-version list, feature ordering, or version scheme. Access names, values, and the canonical contract through `example.projection`. Unavailable `None` values and observed zeros remain exactly as supplied.

The example is a frozen dataclass containing only immutable values. It retains the exact projection and truth objects, with no caller-owned mutable container. Changing truth requires constructing another example; the original example and its projection are unchanged.

There is no generated identity, timestamp, row number, or source reference. The caller explicitly associates truth with the supplied projection during construction. The projection intentionally omits observation identity, so this contract cannot verify that the caller selected the correct observation or observation horizon. A future dataset may define ordering and identity separately; constructing examples does not sort, shuffle, sample, or deduplicate them. Equal examples compare equal without implying that repeated observations should be removed.

## Scope

The boundary ends at one immutable research example. It does not construct datasets or extend the existing detector-specific `DetectionDataset` and `DetectionExperiment`. Future research dataset composition can consume examples without changing those evaluation contracts.

No file format, persistence, dataset authentication, preprocessing, normalization, imputation, feature selection, split assignment, training, inference, model metadata, or MLOps is introduced. Representation does not establish dataset validity, representativeness, balance, attack coverage, correct labeling, or scientific correctness. The existing deterministic detection pipeline does not invoke this package.
