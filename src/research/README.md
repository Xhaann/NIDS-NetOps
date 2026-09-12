# Research examples and datasets

`research` exports `ResearchExample(projection, ground_truth=None, observation_window=None)` from [research_example.py](research_example.py). It associates an existing [MLFeatureProjection](../ml/README.md) with optional research truth and closed-window context. This package owns experimental data representation; it implements no detector, evaluation, or learning operation.

## Contract

| Field | Meaning |
| --- | --- |
| `projection` | Exactly an existing `MLFeatureProjection`, retained by reference. Its feature contract, ordered names, and values remain authoritative. |
| `ground_truth` | An optional exact built-in nonblank string supplied by the caller. `None` means truth was not supplied. |
| `observation_window` | An optional exact closed `FlowObservationWindow`, retained by reference. `None` means no observation association was supplied. |

Truth is opaque text with caller-defined meaning, not a built-in binary label or attack vocabulary. Case, Unicode, and surrounding whitespace are preserved; entirely blank strings are rejected. No category encoding or conversion is performed. Booleans, numeric targets, collections, string subclasses, detector decisions, and evaluation truth records are not accepted as truth. There is no implicit conversion of these values to strings. Richer or numerical research targets would require a separate explicit contract decision.

The existing [GroundTruthRecord](../application/ground_truth.py) describes a detector-specific evaluation target and its explicit positive/negative polarity. It is not interchangeable with research truth. `ResearchExample` neither imports nor converts it, and never derives truth from findings, configurations, thresholds, evaluation results, or predictions. Callers remain responsible for supplying independently established truth; a string type cannot authenticate its origin or experimental meaning.

## Features, ownership, and identity

Construction accepts only an already-created projection. It does not read a snapshot, extract features, or copy feature definitions. Optional window validation checks its type, closure state, and retained timestamps. Projection construction owns feature-version compatibility; the example introduces no second supported-version list, feature ordering, or version scheme. Access names, values, and the canonical contract through `example.projection`. Unavailable `None` values and observed zeros remain exactly as supplied.

The example is a frozen dataclass containing only immutable values. It retains the exact projection, truth, and optional window objects, with no caller-owned mutable container. Changing truth requires constructing another example; the original example and its projection are unchanged.

There is no generated identity, timestamp, or row number. Equality includes projection, truth, and the full optional window value. Existing calls with no context keep their projection/truth equality; different window values distinguish examples even when projections and truth are equal. Equal examples and repeated references remain representable. Construction never sorts, samples, or deduplicates.

## Observation association

Keep the window from the same snapshot when associating an observation:

```python
example = ResearchExample(
    project_flow_features(snapshot),
    ground_truth=research_truth,
    observation_window=snapshot.observation_window,
)
```

The immutable window retains its session/window key, canonical flow identity, first/last admitted timestamps, closure reason, and coordinated state. No fields are copied into the 49-value projection. Feature names, values, version, `None`, and zero semantics stay unchanged; no feature is recalculated.

Wrong context types, including subclasses, raise `TypeError`; active windows raise `ValueError`. Validation checks projection, truth, then context. It never closes a window or changes flow state. All existing closed-window reasons are accepted, including explicit segmentation. The recommended inactivity/successful-session-end population remains a study choice, not a filtering policy in this contract.

After the closure check, retained timestamps must follow `PacketObservation`: exact built-in `datetime`, exact built-in `datetime.timezone`, and zero UTC offset. This covers first/last timestamps in flow statistics, flow inter-arrival statistics, and directional inter-arrival statistics, plus both directional last-packet timestamps when present. Datetime subclasses raise `TypeError`; missing, custom, or nonzero-offset timezones raise `ValueError`. Named fixed UTC timezones and absent optional directional timestamps remain valid. Validation neither copies nor normalizes timestamps.

This is a caller-declared association, not proof that the projection came from the window. Construction cannot recover origin from equal values and does not re-extract or compare features to infer it. Supply projection and context from the same snapshot. Calls that omit context still accept existing projections, including those derived from active snapshots; they do not claim a finalized observation association.

Window keys are scoped to caller-declared replay/session context, not globally unique or authenticated. A retained window does not identify the source recording, certify outcome-based admission or successful replay, or record the processing event when closure became available. Keep recording/procedure and annotation context separately. Grouping, leakage checks, retrospective-horizon selection, and one-row-per-selected-window discipline remain study responsibilities; neither the example nor dataset enforces them.

## Ordered research datasets

`research` also exports `ResearchDataset(examples)` from [research_dataset.py](research_dataset.py). Its only field, `examples`, is an immutable tuple containing the exact supplied `ResearchExample` objects in caller order.

The constructor requires an explicit exact built-in list or tuple. Other containers, subclasses, mappings, unordered collections, and arbitrary iterators raise `TypeError`; no implicit iteration or ordering is inferred for them. A list's membership is copied into a tuple, so subsequent caller changes cannot affect the dataset. Each member must be exactly a `ResearchExample`; invalid members raise `TypeError` without conversion or changes to the input. No partial dataset is returned on failure.

Both `ResearchDataset([])` and `ResearchDataset(())` represent an empty dataset. Equal examples and repeated references remain separate sequence entries. Tuple position supplies order without stored row numbers. Dataset equality compares the complete ordered example values, including multiplicity; it depends on neither object identity nor a dataset name. The frozen object has no mutation methods. Construct another dataset to change membership.

The dataset does not inspect or reconstruct projections, feature contracts, names, values, or truth. These remain owned by `ResearchExample` and `MLFeatureProjection`; unlabeled examples, unavailable `None` values, and observed zeros are retained unchanged. No sorting, grouping, shuffling, deduplication, sampling, or balancing occurs.

`ResearchDataset` is not [DetectionDataset](../application/detection_dataset.py). Research examples and datasets are not detector/evaluation ground truth. They neither wrap evaluation cases nor convert `GroundTruthRecord`, and they have no dependency on detector findings, detection identities, metrics, or the existing `DetectionExperiment`. The research branch remains independently importable and usable.

## Scope

The boundary ends at an immutable in-memory ordered research dataset. It does not construct detector findings, evaluate predictions, or extend the existing detector-specific `DetectionDataset` and `DetectionExperiment`.

No file format, persistence, dataset authentication, preprocessing, normalization, imputation, feature selection, split assignment, training, inference, model metadata, or MLOps is introduced. Representation does not establish dataset validity, representativeness, balance, attack coverage, correct labeling, or scientific correctness. The existing deterministic detection pipeline does not invoke this package.
