# AMITF — Phase 5 Controlled Red-Team Testing Plan

---

## Overview

Phase 5 is the first real-world operational validation of the full AMITF stack.
All prior phases (0–4) are synthetic: the attacker is our own naive reader, the
target is a Python simulator, and the structures are trivial.

Phase 5 replaces both sides with something that resembles actual game conditions:

- **Target**: a minimal CS2-style game built in the **Source 2 engine** — the
  exact engine Counter-Strike 2 runs on.
- **Attacker**: a realistic external memory reader simulating ESP / radar-style
  cheat tooling, operating via `/proc` (Linux) or `ReadProcessMemory` (Windows).

---

## Why Source 2

Source 2 is the natural choice for this test for several reasons:

- It is the **production engine** of CS2, the primary threat target the AMITF
  architecture is designed to harden.
- The engine is **freely available** via the Source 2 SDK (s2sdk / s&box tooling)
  and does not require a commercial license for research builds.
- Source 2 exposes a **C++ entity system** with real component-based entity
  registration, which maps directly onto the entity register abstractions
  prototyped in phases 0–1.
- Existing public CS2 cheat research (offset dumpers, entity list traversal,
  schema system documentation) provides a **known attacker baseline** to measure
  against — we know what a real reader looks for, so we know exactly what to
  defend.
- Building a **minimal clone** (two teams, player entities with position/health,
  no full gameplay loop needed) is genuinely low effort in Source 2 compared to
  building a custom engine target from scratch.

---

## Target: Dummy CS2 Clone

### Minimum Viable Scope

The clone does not need to be a playable game. It needs to:

- Spawn a **player entity list** using Source 2’s native entity system
- Populate entities with **position (Vector3), health (int), team (int)**
- Run a **game loop** that updates entity state at a realistic tick rate (64Hz
  or 128Hz)
- Integrate the **AMITF runtime fragmentation layer** around the entity list
- Expose the process to an external reader via normal OS memory primitives
  (no special instrumentation)

### What is explicitly NOT needed

- Rendering / visuals beyond a basic debug view
- Networking / multiplayer
- Full weapon / movement / hit-registration systems
- Any Valve-specific gameplay code

### Suggested Implementation Path

1. Create a minimal Source 2 game addon (`.vgc` / `gameinfo.gi` project)
2. Register a custom `CGameRules` subclass with a stripped-down game loop
3. Allocate a fixed-size entity array matching AMITF’s `MAX_ENTITIES` budget
4. Drive entity state updates from a deterministic simulation (random walk or
   pre-recorded coordinate sequence) so ground truth is always known
5. Link or embed the AMITF fragmentation layer as a static library or inline C++
6. Run the process and point the Phase 5 reader at it

---

## Attacker: Mock Reader Profiles

Three attacker profiles should be tested, in order of sophistication:

### Profile A — Naive Signature Scanner
Simulates:
- magic-byte scan across all readable regions
- fixed-offset entity struct decode
- no adaptation to layout changes

Expected result by Phase 5: **complete failure** (v1–v4 defenses should make
fixed-offset decoding produce only garbage).

### Profile B — Polling Reader
Simulates:
- high-frequency (`>500Hz`) repeated reads of known entity list address
- delta comparison to detect state changes
- no schema knowledge, pure positional heuristics

Expected result by Phase 5: **stale / incoherent state** due to short-lived
coherence windows (v5) and epoch relocation (v4). Telemetry layer (v6) should
flag the polling cadence.

### Profile C — Semantic Reconstructor
Simulates:
- schema-aware field discovery
- heuristic padding detection (scan for plausible coordinate ranges)
- pointer chain tracking across relocations
- decoy disambiguation (attempt to filter fake registers)

Expected result by Phase 5: **partial reconstruction at best**, with high
error rate on coordinates and entity identity. This profile is where the
open research questions get answered quantitatively.

---

## Metrics to Collect

| Metric | Description |
|--------|-------------|
| **Reconstruction accuracy** | % of entity coordinates correctly recovered per pass |
| **Stale read rate** | % of passes returning data from a prior epoch |
| **False positive rate** | Decoy structures accepted as real per pass |
| **Detection latency** | Ticks until telemetry layer flags suspicious polling |
| **Overhead** | Frame-time delta with AMITF active vs. baseline (target: <1ms at 128Hz) |
| **Pointer chain survival** | % of epochs where a cached address still resolves correctly (target: 0 by v4) |

---

## Open Research Questions This Phase Answers

1. **How much semantic instability breaks practical reconstruction?**
   Measured directly by Profile C reconstruction accuracy across v1–v7.

2. **How much entropy before gameplay degradation?**
   Measured by frame-time overhead at each prototype stage.

3. **What mutation frequency maximises instability?**
   Sweep epoch duration from 1 tick to 128 ticks and plot reconstruction
   accuracy vs. overhead.

4. **Which telemetry patterns correlate most strongly with polling?**
   Compare Profile B polling signature against Profile A and C baselines.

5. **How quickly do stale snapshots reduce cheat usefulness?**
   Measure position error introduced by stale reads at realistic player
   movement speeds (250 units/s in CS2).

6. **Can decoy structures reduce reconstruction confidence to noise floor?**
   Measure Profile C false positive rate as decoy density increases (v3).

---

## Prerequisites Before Phase 5 Begins

- [ ] v0–v7 prototype stages complete and validated in Python simulator
- [ ] AMITF fragmentation layer ported to C++ (or Rust FFI)
- [ ] Source 2 SDK build environment set up
- [ ] Dummy CS2 clone compiles and runs with a stable 64Hz game loop
- [ ] At least one mock reader profile (Profile A) operational against the clone
  without AMITF active, confirming the attacker baseline works

---

## Notes

- All testing must remain **offline and isolated** (no VAC-connected servers,
  no live game processes).
- The Source 2 clone is purely a **research vehicle** — it is not a game,
  not distributed, and contains no Valve gameplay IP beyond engine primitives.
- Results from Phase 5 feed directly into the research questions and inform
  whether the architecture is viable for a real engine integration proposal.

---

*Document status: planning. Prerequisites not yet met — complete prototype stages v0–v7 first.*
