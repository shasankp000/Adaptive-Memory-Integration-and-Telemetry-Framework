# AMITF — Prototype Progress Checklist

Tracks implementation and validation status of the prototype evolution stages
defined in `docs/AMITF_supplemental_suggestions.md` and `docs/AMITF_intial_plan.md`.

---

## Prototype Stages

| Stage | Description | Implemented | Validated |
|-------|-------------|:-----------:|:---------:|
| **v0** | Stable readable state — packed ctypes structs, double-buffered register | ✅ | ✅ |
| **v1** | Fragmented layout — random noise padding between every entity field, new layout every epoch | ✅ | ✅ |
| **v2** | Randomized field ordering — shuffle which of name/x/y comes first each epoch | ✅ | ✅ |
| **v3** | Decoy structures — fake entity registers with valid magic headers and plausible coordinates | ✅ | ✅ |
| **v4** | Epoch relocation — move structs to new heap addresses each epoch, invalidate old pointers | ✅ | ✅ |
| **v5** | Short-lived coherence windows — plaintext exists only briefly before overwrite | ✅ | ✅ |
| **v6** | Polling telemetry tracking — detect and fingerprint observation cadence | ✅ | ✅ |
| **v7** | Adaptive semantic poisoning — respond to detected polling with increased decoy density | ✅ | ✅ |
| **v8** | Smarter reader + anomaly scoring — upgrade reader with heuristic filters, add suspicion score output to prototype | ✅ | ✅ |
| **v9** | Encryption epoch system — per-epoch TPM-seeded XOR/SHAKE-256 key derivation, real payload fields encrypted at write, decoys carry plausible encrypted garbage | ⬜ | ⬜ |
| **v10** | Polymorphic execution layer — integrate `secure_core.c` mprotect/RWX pipeline; key derivation and reconstruction logic executes from anonymous pages, overwritten after use | ⬜ | ⬜ |
| **v11** | Secure IPC bridge — integrate `secure_ipc.c` memfd/unnamed-mapping anonymous arena; per-packet SHAKE-256 rotating XOR masks on telemetry stream between prototype and reader | ⬜ | ⬜ |
| **v12** | Full integration — encryption + polymorphic exec + secure IPC + anomaly scoring all active simultaneously; run reader v2 again and measure residual precision | ⬜ | ⬜ |

---

## Foundation Work

| Task | Status |
|------|:------:|
| Reader: filter to `rw-p` regions only (drop `r--p`, `r-xp`) | ✅ |
| Reader: tighten count validation to exact `EXPECTED_COUNT` match | ✅ |
| Reader: tight `block_size` = `HEADER_SIZE + EXPECTED_COUNT * ENTITY_SIZE` | ✅ |
| Concurrent run confirmed — epoch increments observed live across passes | ✅ |
| Double-buffering swap observable by external reader | ✅ |
| v1 reader confirmed broken — garbage names and coordinates across all passes | ✅ |
| v2 reader confirmed blind — 20/20 passes returned "No struct found" | ✅ |
| v3 reader confirmed poisoned — 6–7 hits/pass, zero real, confidence at noise floor | ✅ |
| v4 reader confirmed churning — address set unstable every pass, real buffer never found | ✅ |
| v5 reader confirmed too slow — 30/30 scrubs completed, no real buffer observed | ✅ |
| v6 telemetry confirmed — 60 hits / 30 epochs, mean delta converged to ~493 ms | ✅ |
| v7 adaptive poisoning confirmed — poison triggered at epoch 1, decoys 4→12, held for full run | ✅ |
| v8 smarter reader confirmed — heuristics work on noise but fail to disambiguate real from decoys | ✅ |
| v9 encryption layer — reader v2 should decode only garbage even from HIGH-confidence addresses | ⬜ |
| v10 polymorphic exec — key derivation address never stable in RAM; `secure_core.c` compiled + linked | ⬜ |
| v11 IPC bridge — `secure_ipc.c` compiled + linked; telemetry stream verified delta-XOR resistant | ⬜ |
| v12 integration — reader v2 precision measured at full-stack; residual signal documented | ⬜ |

---

## v0 Validation Notes

- Reader produced exactly 2 `rw-p` hits per pass, zero false positives.
- Epoch counter incremented live between passes (concurrent run confirmed).
- Both buffer addresses (`buf_a`, `buf_b`) stable across full process lifetime.
- Active buffer alternated correctly between `buf_a` and `buf_b` on each swap.

---

## v1 Validation Notes

- Target buffer size varies per epoch: observed range **79B – 117B** (baseline packed = 52B).
- Pad sizes regenerated every epoch via `random_pad_sizes()` — 6 values in `[1, 16]`.
- Reader decoded garbage names every pass: `w}5`, `Eg&k`, `=Kh`, `ǹU*B/`, `KP8CT1`, `G*`, `84ܚe`, `jCT1`, etc.
- Reader decoded garbage coordinates every pass: values like `-496974367`, `1135898192`, `-1810616955`.
- **Partial name leakage observed** (`KP8CT1`, `:GCT1`, `jCT1`) when leading pad is short enough that
  the 8-byte name slice partially overlaps the real name bytes. Known v1 limitation — addressed by v2.
- Reader never produced "No struct found" — magic header and count field at fixed positions meant
  `decode_register` always passed the size check. Magic anchor confirmed as reader's only foothold.

---

## v2 Validation Notes

- **Reader completely blind: 20/20 passes returned "No struct found."** Zero hits across the entire run.
- Target buffer size range: **84B – 122B**. Reader's fixed `block_size` of 52B is smaller than every
  observed epoch buffer, causing the entity region slice to be consistently undersized.
- Field order shuffled every epoch across all 6 permutations of `[name, x, y]`:
  observed `['x','name','y']`, `['y','name','x']`, `['name','y','x']`, `['x','y','name']`, etc.
- **Compounding effect**: v1 padding alone left the reader finding garbage structs. Adding v2 field
  shuffle collapsed `decode_register` entirely — the two layers multiply rather than add.
- The variable geometry means the reader's fixed-size slice captures the wrong byte count for
  the entity region on every permutation, causing the size check to fail before any decode attempt.
- This is the anti-economics principle in action: cost to the reader escalated from
  "decode garbage" (v1) to "find nothing" (v2).

---

## v3 Validation Notes

- **Reader saw 6–7 hits per pass. Zero were real. Confidence poisoned to noise floor.**
- 4 intended decoy addresses decoded cleanly every pass with plausible names (`BOT2`, `CT2`, `GUARD`,
  `T3`, `SPEC1`, `BOT1`, `T2`, `CT3`) and coordinates in `[0,9]`.
- 2 ghost hits from the real double-buffer alternated `<-- NEW` / `<-- gone` every 2 passes — the
  real buffers caught by the magic scan at the wrong packed offset. Undecodable but address-churning.
- 2–3 noise false positives from heap regions where random noise bytes coincidentally match `0x1FA1`.
  Decoded garbage names: `JT$D`, `*r23d2`, `[!oXs`, `wXCT`, `jCT1`.
- Decoy names close enough to real names (`CT2`, `CT3` vs `CT1`) that name-filtering offers no
  disambiguation. Epoch counters on all hits increment plausibly. No observable distinguishing signal.
- **Research question #6 answered**: yes, decoy structures reduce reconstruction confidence to the
  noise floor. A reader cannot determine which (if any) of the 7 hits is real.

---

## v4 Validation Notes

- **Real buffer address changed every epoch. Reader had zero contact with real data across 20 passes.**
- Decoy address set churned every 2 passes: 2 addresses `<-- gone`, 2 `<-- NEW` per epoch pair.
  Any allowlist or blocklist a reader builds is partially stale within 2 passes.
- Real buffer address never appeared in reader output at any pass — v1+v2 fragmentation prevented
  the magic scan from matching it even after relocation gave it a fresh address.
- **GC lag observation**: initial `_active_buf` from `gameinit()` (addr `0x7fdc5a362a50`) remained
  visible in `/proc/pid/maps` for **15 passes** (epochs 0–11) after being dereferenced on the first
  `swap_shared()` call, before finally disappearing at pass 16 (epoch 12). Python's garbage collector
  does not immediately reclaim ctypes buffers — the allocation persists until the GC cycle runs.
  In production this lag should be eliminated with an explicit `del old_buf; gc.collect()` call
  immediately after the new buffer is assigned. Without this, a reader that catches the stale address
  early has a multi-epoch window to observe it (though the data inside is still v1+v2 garbage).
- One persistent noise false positive (`0x7fdc5a7bc290` / `0x7fdc5a7bc7a0`) survived most of the run —
  a Python runtime internal allocation whose bytes happen to contain `0x1FA1` at a stable offset.
  Produced garbage names and wild coordinates; not a real struct. `CT1` appearing in pass 20 at this
  address is a partial name coincidence in random noise, not a real decode.
- **Remaining foothold**: one noise false-positive address is long-lived and stable. Targeted by v5
  (short coherence windows) which prevents any address from being useful even if correctly identified.

---

## v5 Validation Notes

- **Scrub counter reached 30/30 — every epoch's plaintext was destroyed within the 50 ms coherence window.**
- Reader polling interval was **500 ms**, 10x slower than the coherence window. Reader never observed
  a real buffer address in any pass; by the time each scan ran, the magic header had already been scrubbed.
- Explicit `del old_buf; gc.collect()` removed the v4 ghost-buffer lag: no long-lived stale real-buffer
  address survived across many passes.
- Reader still saw many plausible decoys because decoy buffers are intentionally never scrubbed.
  Observable address churn remained unstable, preserving v4's anti-allowlist effect.
- Two persistent epoch-0 survivors (`0x7f3ec2b62cf0`, `0x7f3ec2bf1590` / `0x7f3ec2fe8b00`) came from
  Python runtime internal allocations, not the real register. Their frozen tick/epoch values provide a
  distinguishing signal a smarter reader might exploit: any candidate whose epoch never increments is not real.
- **Research question #5 partially answered**: stale snapshots become useless almost immediately once
  coherence windows are shorter than polling cadence. At 50 ms vs 500 ms polling, the reader missed
  every real write across the full run.

---

## v6 Validation Notes

- **Telemetry registered 60 hits across 30 epochs, with mean inter-hit delta converging to 493.30 ms.**
- With `SIMULATE_OBSERVER=0`, the telemetry thread still observed canary mutations because the game
  rewrites the canary on every epoch swap and the scrub worker destroys it ~50 ms later.
- The last telemetry events formed a clear paired pattern: one hit at write time, one hit at scrub time
  roughly **50 ms** later, then a ~950 ms quiet interval before the next epoch pair.
- Reader behaviour remained degraded exactly as in v5: 5–8 hits/pass, all decoys, garbage, or noise
  false positives; the real buffer was never decoded.
- Persistent epoch-0 and garbage survivors still provide a pruning signal for a smarter reader, but no
  observed candidate yielded stable access to real entity state.
- **Research question #4 partially answered**: periodic buffer mutation and scrub timing can be measured
  and fingerprinted as cadence, providing a control-plane signal for adaptive response in v7.

---

## v7 Validation Notes

- **POISON_ACTIVATIONS: 1 — triggered at epoch 1 after only 4 telemetry hits with mean delta ~348.7 ms.**
- Decoy count jumped from **4 → 12** at epoch 1 and held at 12 for the entire remaining 29-epoch run.
  The POISON_HOLD + continuous re-evaluation locked the register into full poison mode permanently
  once the self-write/self-scrub cadence crossed the suspicion threshold.
- **TELEMETRY_TOTAL_HITS: 61**, TELEMETRY_MEAN_DELTA_MS: 500.86 — nearly identical to v6, confirming
  the adaptive layer adds no meaningful overhead to the telemetry accounting path.
- Reader saw **12–14 hits/pass** (up from 5–8 in v6) — a ~3× increase in noise surface.
  All hits were decoys from the expanded pool (`GUARD`, `SPEC1`, `BOT1`, `BOT2`, `CT2`, `CT3`, `T2`, `T3`).
  The real buffer was never decoded in any of the 20 passes.
- Address churn remained consistent: 1–2 `<-- NEW` and 2 `<-- gone` per epoch pair, now spread across
  a 12-entry decoy set instead of 4, making allowlist reconstruction 3× more expensive per epoch.
- The persistent noise-survivor (`0x7f6a927...`, garbage names `, j`) reappeared every pass as before —
  a Python runtime region, not real state. Its frozen-tick / wild-coordinate signature remains a
  distinguishing signal for a smarter reader to prune it.
- **Research question #1 partially answered**: at 12 decoys + 3× address churn, a reader with no
  heuristic filtering sees a completely saturated noise floor with no actionable signal.

---

## v8 Validation Notes

### Prototype Output (phase8_prototype.py)

- **TELEMETRY_TOTAL_HITS: 60** across 30 epochs, mean delta converged to **493.30 ms** — consistent with v6/v7.
- **POISON_ACTIVATIONS: 1** — triggered at epoch 1, decoys held at 12 for full run. Anomaly scoring held [LOW]
  across all 30 epochs (score plateau at ~0.0833), confirming the suspicion scalar correctly reflects a stable,
  non-escalating observation cadence.
- Anomaly score [LOW] plateau at **0.0833** is the expected floor for 2 hits/epoch with low delta variance.
  Score never escalated to [MEDIUM] or [HIGH] — no observer behaviour aggressive enough to trigger escalation.
- `delta_var` stabilised at **~203,000 ms²** after epoch 2, reflecting stable ~493 ms polling intervals.

### Reader Output (process_reader_v2.py) — Key Findings

**Noise pruning worked correctly:**
- Wild-coord candidates (e.g. `0x7fdb71941950`, `0x7fdb71991410`) permanently pinned at **score ≤ −50 [LOW]**
  via `wild_coords(−30) + epoch_frozen(−40)`. Never rose above noise across all 20 passes.
- Frozen-epoch penalty (`epoch_frozen(−40)`) correctly neutralised the persistent Python runtime survivor
  `0x7fdb71926930` (tick=0, epoch=0 across all 20 passes) — max score **+10 [LOW]**.

**Decoy disambiguation failed completely — critical finding:**
- **19 addresses reached HIGH confidence (score = +75)** by pass 4–8, all scoring
  `coords_clean(+30) + epoch_inc(+25) + stability(+20)`.
- The BEST CANDIDATE (`0x7fdb7196e3f0`) was correctly identified in most passes — but it was
  **indistinguishable from 18 equally-scored HIGH candidates**. Precision = ~1/19 ≈ **5%**.
- Root cause: v7 semantic poisoning makes all 12 decoys structurally identical to the real register —
  valid coords, incrementing epochs, stable addresses. All three heuristics are saturated by design.
- No structural signal (coord range, epoch increment, address stability) survives v7's decoy quality.

**The reader's ceiling is the decoy quality floor:**
- As long as decoys are well-behaved (valid coords + incrementing epochs + long-lived), the reader
  cannot disambiguate without accessing the *semantic content* of the payload fields.
- This confirms the next defensive layer must act at the **content level**, not the structural level.

### Research Question #1 — Now Answered

**Q: How much semantic instability breaks practical reconstruction?**

**A:** Three structural heuristics (coord-range, epoch-increment, address-stability) are insufficient
when decoys are structurally perfect mimics. The reader achieves ~5% precision — effectively random
guessing among 19 HIGH-confidence candidates. Real-time cheat use is operationally impossible at
this precision level, but a patient or ML-assisted reader could theoretically correlate over time.
The next defensive layer (encryption epoch system) must eliminate content-level leakage to close this.

---

## v9–v12 Design Overview

### v9 — Encryption Epoch System

Direct response to v8's finding: structural heuristics alone give ~5% precision. Moving defence to the **content level**.

- Per-epoch key derived via `secrets.token_bytes(32)` (mock TPM seed) + epoch number fed into SHAKE-256
- Real entity `name`, `x`, `y` fields XOR-encrypted with per-field independent masks at write time
- Decoys carry **plausible-looking encrypted garbage** — random bytes in valid ranges after decryption attempt,
  but with wrong keys they decode to nonsense. Key never written to RAM — held in Python variable only.
- Reader v2 will still score these addresses HIGH (valid structure, incrementing epoch, stable address)
  but will decode only garbage from every candidate — including the real one — without the key.
- **Expected outcome:** reader precision drops to 0%. All 19 HIGH candidates return undecipherable content.

### v10 — Polymorphic Execution Layer

Integrates `secure_core.c` (from `docs/AMITF_plan2_anti_DMA_architecture.md`):

- Key derivation and epoch rotation logic executes from anonymous RWX pages via `mutate_and_run()`
- Page is written, cache-flushed, and locked RX before execution; overwritten with garbage after return
- Key pointer kept in Python variable (simulating CPU register storage), never in a scannable heap slot
- **Expected outcome:** even a DMA card that scans physical RAM during the key derivation window
  finds a garbage page — the key never exists as a stable, addressable RAM value.

### v11 — Secure IPC Bridge

Integrates `secure_ipc.c` (from `docs/AMITF_plan3_secure_userpsace_ipc_layer.md`):

- Telemetry stream between prototype and reader moves through `memfd_create()` anonymous arena (Linux)
  or unnamed `CreateFileMapping()` (Windows) — no filesystem path, invisible to scanners
- Each telemetry frame uses **per-packet SHAKE-256 rotating XOR masks** derived from `(tpm_seed + packet_id)`
- Delta-XOR attack defeated: consecutive frame XOR recovers noise, not coordinate deltas
- **Expected outcome:** a DMA card observing the IPC channel sees random bytes with no recoverable
  telemetry signal even across multiple captured frames.

### v12 — Full Integration Run

- All layers active simultaneously: encryption + polymorphic exec + secure IPC + v7 adaptive poisoning + anomaly scoring
- Run reader v2 against the full-stack prototype and measure residual precision
- Document the final noise floor: expected outcome is reader v2 achieving **0% content precision**
  with all 19 HIGH candidates returning undecipherable payloads
- This closes Phase 0 of the prototype roadmap and feeds directly into Phase 1 (Telemetry Prototype in Rust/C++)

---

## v8 Design — Smarter Reader + Anomaly Scoring (reference)

v7 closes the offensive prototype arc (v0–v7). v8 pivots to the **defensive measurement arc**:
build a smarter reader that applies the heuristics we know are exploitable, then measure how much
real signal it recovers — and use that to drive the next defensive iteration.

### Smarter Reader Upgrades (`process_reader_v2.py`)

The naive reader has three known exploitable weaknesses observed across v0–v7:

1. **Frozen-epoch pruning** — any candidate whose epoch field does not increment between consecutive
   passes is a noise false-positive (Python runtime region or stale decoy). Prune it.
2. **Coordinate-range filtering** — real entities have coordinates in `[0, 9]`. Any hit with
   coordinates outside that range (wild values like `-1837937792`) is noise. Score it down.
3. **Address-stability scoring** — decoys churn (1–2 gone per epoch). A candidate that survives
   N consecutive passes without going `<-- gone` is more likely to be real (or a long-lived decoy).
   Track per-address pass-survival count.

Together these three heuristics form a lightweight **per-candidate suspicion / confidence score**
that the reader prints alongside each hit.

### Anomaly Scoring Output in Prototype (`phase8_prototype.py`)

On the prototype side, `swap_shared` will emit a per-epoch **suspicion_score** — a scalar computed
from the telemetry ring buffer — to the console log. This mirrors what a real anti-cheat's
server-side pipeline would ingest. Signals used:

- rolling hit count over last N epochs
- mean delta stability (variance of `observer_periods`)
- poison activation count
- decoy churn rate (how many `<-- NEW` / `<-- gone` a hypothetical observer would see)

This closes the loop between the memory-defense layer and the telemetry layer and sets up
**Phase 4** (Integrated Telemetry + Memory Defense) from the broader roadmap.

---

## Broader Phase Roadmap (from `AMITF_intial_plan.md`)

| Phase | Description | Status |
|-------|-------------|:------:|
| Phase 0 — Simulation & Research | Validate architectural feasibility, synthetic memory simulator | 🔄 In progress |
| Phase 1 — Telemetry Prototype | Handle tracker, polling detector, page-access logging, anomaly scoring | ⬜ |
| Phase 2 — Runtime Fragmentation Prototype | Randomized allocator, indirect pointer layer, epoch rotation | ⬜ |
| Phase 3 — GPU-Assisted Pipeline | Async GPU transforms, batched encryption, epoch migration | ⬜ |
| Phase 4 — Integrated Telemetry + Memory Defense | Suspicious read-pattern scoring, correlation engine | ⬜ |
| Phase 5 — Controlled Red-Team Testing | Synthetic polling frameworks, semantic reconstruction attempts | ⬜ |

---

## Key Open Research Questions

1. How much semantic instability breaks practical reconstruction? ✅ **Answered (v8)** — 3 structural heuristics give ~5% precision at 19 HIGH candidates. Content-level encryption needed to close the gap.
2. How much entropy before gameplay degradation?
3. What mutation frequency maximizes instability without correctness cost?
4. Which telemetry patterns correlate most strongly with polling behaviour? ✅ **Partially answered** (v6)
5. How quickly do stale snapshots reduce cheat usefulness? ✅ **Partially answered** (v5)
6. Can decoy structures reduce reconstruction confidence to noise floor? ✅ **Answered: yes** (v3)

---

*Last updated: v8 validated. v9–v12 roadmap added: encryption epoch system → polymorphic exec → secure IPC bridge → full integration run. Phase 0 closes at v12.*
