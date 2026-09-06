# VM-based security testing strategy

This directory establishes the documentation boundary for future controlled security experiments. It contains no VM definitions, provisioning, traffic generators, attack scripts, or runnable scenarios.

Use only owned or explicitly authorized systems in an isolated virtual network. A future lab may assign sensor, traffic-generator, and target roles to separate VMs; the topology and capture visibility must be verified for each experiment. Keep test traffic contained and document any required management or update connectivity separately. Select the hypervisor, guest systems, network layout, and provisioning tools in a later task.

Each future scenario must document:

- Objective, authorization scope, topology, VM roles, image versions, and resource allocation.
- Repository revision, configuration, detector versions, dependencies, and clock assumptions.
- Input traffic origin, ground-truth labels, preparation, and reproducible execution steps.
- Expected observations and findings, observed alerts, false positives, false negatives, and visibility limitations.
- Evidence locations and hashes, sanitization, retention, cleanup, and snapshot or reset procedure.

Keep VM disks, snapshots, raw PCAPs, credentials, and generated outputs out of version control. Use external artifact storage or the ignored root `artifacts/` directory when actual experiments begin. Retain only reviewed scenario documentation and appropriately sanitized small fixtures in the repository.

Record differences between expected and observed results without overstating detection coverage. Promote reproducible defects into the [automated test suite](../tests/README.md) where possible.
