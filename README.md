# Adaptive Memory Integrity & Telemetry Framework (AMITF)

> A defensive systems-research exploration into dynamic runtime memory integrity for multiplayer games.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

---

## What is AMITF?

AMITF is a research framework aimed at defeating cheating in **Counter-Strike 2** (and similar multiplayer games) through **memory fragmentation**, **encryption epoch rotation**, and **behavioral telemetry** -- without relying solely on static signatures or kernel-level enforcement.

The core insight is:

> Modern cheats depend on deterministic layouts, synchronized state, stable timing, and predictable pointer chains.
> AMITF continuously destabilizes those assumptions.

The goal is **not** perfect memory secrecy. The goal is:

```
Make real-time semantic reconstruction unreliable, expensive, and behaviorally observable.
```

---

## Disclaimer

This project is a **defensive research architecture** intended to:
- reduce scalability of multiplayer game cheats,
- increase the cost of memory observation attacks,
- improve behavioral telemetry,
- and study modern anti-cheat design tradeoffs.

This project does **not** attempt to:
- create malware,
- bypass operating system security,
- distribute cheats,
- or provide offensive tooling.

---

## Core Philosophy

Traditional anti-cheat systems focus on:
- static signature scanning,
- process blacklists,
- fixed memory protection,
- kernel-level enforcement.

AMITF instead assumes:

> Sufficiently privileged attackers may eventually observe memory.

So the goal shifts from `Prevent all access` to:

- **Reduce semantic coherence** -- captured bytes are not reliably meaningful,
- **Increase synchronization difficulty** -- state changes faster than cheats can poll,
- **Increase maintenance cost** -- cheat developers must constantly re-reverse,
- **Increase telemetry surface** -- observation attempts become behavioral signals.

---

## Threat Model

### Targeted cheat categories
- External memory readers
- Usermode overlays / ESP / wallhacks
- Radar cheats
- Legitbot aim assistance
- Kernel-assisted polling cheats
- Low-to-mid sophistication commercial cheat frameworks

### Non-goals
The architecture does **not** (yet, but I will figure out a way to) claim to stop:
- highly resourced hardware-level attackers,
- DMA-based attacks,
- nation-state level analysis,
- or all kernel-level observation.

---

## High-Level Architecture

```
+------------------------------------------------+
|                Game Process                    |
|                                                |
|  Critical Runtime Structures                   |
|      ↓                                         |
|  Dynamic Memory Fragmentation                  |
|      ↓                                         |
|  Encryption Epoch System                       |
|      ↓                                         |
|  Runtime Reconstruction Layer                  |
+------------------------------------------------+
                ↓
+------------------------------------------------+
|        Telemetry & Provenance Engine           |
|                                                |
|  Handle Tracking                               |
|  Access Pattern Monitoring                     |
|  Fault Correlation                             |
|  Process Graph Reconstruction                  |
+------------------------------------------------+
                ↓
+------------------------------------------------+
|          Server-Side Trust Pipeline            |
|                                                |
|  Behavioral Analysis                           |
|  Correlation Scoring                           |
|  Delayed Enforcement                           |
+------------------------------------------------+
```

---

## Prototype Roadmap

| Phase | Name | Status | Description |
|-------|------|--------|-------------|
| 0 | Simulation & Research | 🔄 In Progress | Simulate fragmented structures, epoch scheduler, reconstruction overhead |
| 1 | Telemetry Prototype | ⏳ Planned | Process handle tracker, polling detector, anomaly scoring |
| 2 | Runtime Fragmentation | ⏳ Planned | Randomized block allocator, indirect pointer layer, epoch rotation |
| 3 | GPU-Assisted Pipeline | ⏳ Planned | Async GPU transforms, batched encryption scheduling |
| 4 | Integrated Defense | ⏳ Planned | Correlate memory instability with telemetry signals |
| 5 | Red-Team Testing | ⏳ Planned | Controlled offline evaluation of operational resistance |

---

## Repository Structure

```
├── docs/
│   └── AMITF_intial_plan.md   # Full research & architecture plan
├── python_prototype/
│   ├── phase0_prototype.py    # Phase 0 target process simulation
│   └── process_reader.py      # Phase 0 external memory reader
└── LICENSE                    # Apache 2.0
```

---

## Security Philosophy

The system is built around five pillars:

1. **Entropy** -- increase runtime unpredictability,
2. **Temporal Instability** -- reduce long-term observation reliability,
3. **Semantic Fragmentation** -- prevent externally observed bytes from staying coherent,
4. **Cost Amplification** -- increase engineering burden for cheat maintenance,
5. **Telemetry-Driven Defense** -- use behavior and provenance instead of static signatures.

---

## License

This project is licensed under the [Apache License 2.0](LICENSE).

---

## Further Reading

For the full research plan, threat model, and architectural detail, see [`docs/AMITF_intial_plan.md`](docs/AMITF_intial_plan.md).
