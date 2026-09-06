# Detection boundary

This directory owns five future detection families. It contains documentation only.

| Family | Responsibility |
| --- | --- |
| Signature | Match defined patterns against supported analysis inputs. |
| Rule | Evaluate explicit predicates over structured observations or features. |
| Threshold | Evaluate counters or measurements against configured limits and windows. |
| Statistical | Compare measurements with defined statistical baselines. |
| Behavioral | Evaluate entity activity or sequences using bounded state. |

Detectors consume [analysis](../analysis/README.md) outputs through explicit contracts and emit findings with detector identity/version, supporting evidence, and the reason for the finding. Severity and confidence must have defined meanings where supplied. Each detector owns only its detection-specific state, not protocol or session state.

The families may share input contracts but should remain independently testable and configurable. [Event processing](../events/README.md) owns cross-finding correlation, risk scoring, deduplication, and alert lifecycle. External intelligence access belongs to [enrichment](../enrichment/README.md). No rules, signatures, algorithms, training code, or model dependencies are established here.
