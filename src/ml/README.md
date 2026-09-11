# ML feature projection

`ml` exports `MLFeatureProjection` and `project_flow_features(snapshot)` from [feature_projection.py](feature_projection.py). This is the model-input boundary for future research code. It consumes exactly an already-extracted [FlowFeatureSnapshot](../analysis/flow_feature_snapshot.py), with no capture, parser, detector, or dataset argument.

```python
from ml import project_flow_features

projection = project_flow_features(snapshot)
contract = projection.feature_contract
names = projection.feature_names
values = projection.values
```

`values` is the model-input representation: an immutable tuple of 49 existing integers, floats, or `None`. `names` is a fixed tuple of 49 unique qualified names in matching order. Keep the contract and names alongside values when defining future consumers; a bare tuple does not carry schema provenance. No array library, serialization format, dataset construction, or model is introduced.

The frozen projection stores only `feature_contract` and `values`; `feature_names` is a read-only schema projection. Construction is restricted to `project_flow_features()` following the existing snapshot factory convention. Direct construction and inputs such as observations, windows, findings, truth, datasets, mappings, or arbitrary vectors raise `TypeError`. No snapshot, flow identity, timestamp, source identifier, closure reason, raw state, or source-object graph is retained.

## Canonical columns

Every column name is exactly `family.field`, and every available value is read directly from `snapshot.family.field`. The following rows define family order; the fields within each row are listed in column order. All numerical fields in the snapshot's six established feature families are included.

| Snapshot family and canonical source | Fields, in order | Values |
| --- | --- | --- |
| [`flow_volume_features`](../analysis/flow_volume_features.py) | `packet_count`, `captured_bytes`, `original_bytes`, `forward_packet_count`, `reverse_packet_count`, `forward_captured_bytes`, `reverse_captured_bytes`, `forward_original_bytes`, `reverse_original_bytes`, `forward_packet_ratio`, `reverse_packet_ratio`, `forward_captured_byte_ratio`, `reverse_captured_byte_ratio`, `forward_original_byte_ratio`, `reverse_original_byte_ratio`, `capture_ratio` | 9 integers and 7 floats. Existing counts, byte totals and dimensionless ratios. |
| [`packet_size_features`](../analysis/packet_size_features.py) | `min_captured_length`, `max_captured_length`, `mean_captured_length`, `variance_captured_length`, `standard_deviation_captured_length`, `min_original_length`, `max_original_length`, `mean_original_length`, `variance_original_length`, `standard_deviation_original_length`, `forward_mean_captured_length`, `reverse_mean_captured_length`, `forward_variance_captured_length`, `reverse_variance_captured_length` | 4 integer extrema and 10 floats. Existing byte-size measurements; variances have squared-byte units. |
| [`flow_duration_features`](../analysis/flow_duration_features.py) | `duration_seconds` | 1 float in seconds. |
| [`flow_rate_features`](../analysis/flow_rate_features.py) | `packets_per_second`, `captured_bytes_per_second`, `original_bytes_per_second` | 3 floats, or 3 `None` slots when the family is unavailable. |
| [`inter_arrival_features`](../analysis/inter_arrival_features.py) | `mean_inter_arrival_seconds`, `variance_inter_arrival_seconds`, `standard_deviation_inter_arrival_seconds`, `min_inter_arrival_seconds`, `max_inter_arrival_seconds` | 5 floats; variance is in squared seconds, the other values in seconds. |
| [`directional_inter_arrival_features`](../analysis/directional_inter_arrival_features.py) | `forward_mean_inter_arrival_seconds`, `forward_variance_inter_arrival_seconds`, `forward_standard_deviation_inter_arrival_seconds`, `forward_min_inter_arrival_seconds`, `forward_max_inter_arrival_seconds`, `reverse_mean_inter_arrival_seconds`, `reverse_variance_inter_arrival_seconds`, `reverse_standard_deviation_inter_arrival_seconds`, `reverse_min_inter_arrival_seconds`, `reverse_max_inter_arrival_seconds` | 5 floats or 5 `None` slots independently per direction, with the same units as global inter-arrival features. |

The converter uses an explicit immutable ordered field list, rather than dictionary/set iteration or automatic discovery of new attributes. It performs no numerical calculations, coercion, rounding, normalization, standardization, imputation, encoding, feature selection, or learned preprocessing. Existing ratios and other derived values are copied, not calculated again. TCP-control counters remain raw coordinated state outside the six numerical families; they are not additional input columns. IP version, addresses, ports and protocol are likewise not encoded as features.

## Availability and version compatibility

Unavailable values retain their established meaning. An absent rate family produces three `None` values at its fixed positions. A directional group without an interval retains five `None` values. No columns are dropped. Existing observed zeros stay zero, including global inter-arrival features without intervals and packet-size features for an unobserved direction. A zero-duration snapshot can therefore contain zero duration and unavailable rates simultaneously. Detector `NOT_EVALUABLE` decisions are not feature values and are never inspected.

The converter reads and retains the snapshot's exact [FeatureContractVersion](../analysis/README.md#explicit-feature-contract-version), currently `FeatureContractVersion("flow-feature-snapshot", "1")`. It rejects any other contract ID/version with `ValueError` before reading numerical features; an incorrectly typed reference raises `TypeError`. This is an explicit compatibility check against the canonical contract, not a second ML versioning system. No detector version, Git revision, environment value, or inferred schema chooses the mapping. Future changes to canonical features or projection ordering require explicit compatibility review and tests; an unknown version is never silently adapted.

## Research boundaries

Labels and ground truth remain separate. The existing [DetectionDataset](../application/README.md#detection-dataset-representation) represents detector-specific evaluation targets with optional truth; it is not a numerical model-input dataset. [DetectionExperiment](../application/README.md#reproducible-experiment-definition) declares a dataset and operation reference. Neither supplies features or is consumed by this projection. They remain unchanged rather than being repurposed or duplicated here.

The separate [ResearchExample](../research/README.md) contract can retain a projection alongside optional caller-supplied research truth text. `ResearchDataset` preserves explicitly ordered examples as immutable membership. Truth never becomes a projection column, and projection does not import or invoke the research package. Research examples and datasets do not reinterpret detector/evaluation truth.

Both active and closed snapshots are valid, as in the canonical feature contract. Projection reads only the supplied immutable snapshot; it never advances flow state, closes a window, reads later observations, or searches for a newer snapshot. Later packets cannot change an earlier projection. Closure and session metadata do not become model inputs.

The caller must choose a snapshot whose observation horizon is appropriate to the future prediction target. A completed flow is not evidence that all its values were available at an earlier prediction cutoff. This boundary cannot certify an externally chosen cutoff or train/test split and creates neither. It excludes labels, detector outcomes, findings, evaluation results, predictions, split membership, and training/runtime metadata by construction; it does not infer any of them. It performs no dataset-wide operations or preprocessing.

The deterministic pipeline does not import or invoke `ml`. Projection is an explicit separate call and changes no detection, finding, truth, evaluation, metrics, benchmark, reporting, capture, or CLI semantics. Models, preprocessing, dataset loading, splitting, training, inference, model selection and MLOps remain deferred. No ML accuracy claim is made.
