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
| **v3** | Decoy structures — fake entity registers with valid magic headers and plausible coordinates | ✅ | ⬜ |
| **v4** | Epoch relocation — move structs to new heap addresses each epoch, invalidate old pointers | ⬜ | ⬜ |
| **v5** | Short-lived coherence windows — plaintext exists only briefly before overwrite | ⬜ | ⬜ |
| **v6** | Polling telemetry tracking — detect and fingerprint observation cadence | ⬜ | ⬜ |
| **v7** | Adaptive semantic poisoning — respond to detected polling with increased decoy density | ⬜ | ⬜ |

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
- Reader never produced “No struct found” — magic header and count field at fixed positions meant
  `decode_register` always passed the size check. Magic anchor confirmed as reader’s only foothold.

---

## v2 Validation Notes

- **Reader completely blind: 20/20 passes returned “No struct found.”** Zero hits across the entire run.
- Target buffer size range: **84B – 122B**. Reader’s fixed `block_size` of 52B is smaller than every
  observed epoch buffer, causing the entity region slice to be consistently undersized.
- Field order shuffled every epoch across all 6 permutations of `[name, x, y]`:
  observed `['x','name','y']`, `['y','name','x']`, `['name','y','x']`, `['x','y','name']`, etc.
- **Compounding effect**: v1 padding alone left the reader finding garbage structs. Adding v2 field
  shuffle collapsed `decode_register` entirely — the two layers multiply rather than add.
- The variable geometry means the reader’s fixed-size slice captures the wrong byte count for
  the entity region on every permutation, causing the size check to fail before any decode attempt.
- This is the anti-economics principle in action: cost to the reader escalated from
  “decode garbage” (v1) to “find nothing” (v2).

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

1. How much semantic instability breaks practical reconstruction?
2. How much entropy before gameplay degradation?
3. What mutation frequency maximizes instability without correctness cost?
4. Which telemetry patterns correlate most strongly with polling behaviour?
5. How quickly do stale snapshots reduce cheat usefulness?
6. Can decoy structures reduce reconstruction confidence to noise floor?

---

*Last updated: v2 randomized field ordering validated. v3 decoy structures implemented.*
