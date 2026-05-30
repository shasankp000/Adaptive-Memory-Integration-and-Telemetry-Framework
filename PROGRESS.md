# AMITF — Prototype Progress Checklist

Tracks implementation and validation status of the prototype evolution stages
defined in `docs/AMITF_supplemental_suggestions.md` and `docs/AMITF_intial_plan.md`.

---

## Prototype Stages

| Stage | Description | Implemented | Validated |
|-------|-------------|:-----------:|:---------:|
| **v0** | Stable readable state — packed ctypes structs, double-buffered register | ✅ | ✅ |
| **v1** | Fragmented layout — random noise padding between every entity field, new layout every epoch | ✅ | ✅ |
| **v2** | Randomized field ordering — shuffle which of name/x/y comes first each epoch | ⬜ | ⬜ |
| **v3** | Decoy structures — fake entity registers with valid magic headers and plausible coordinates | ⬜ | ⬜ |
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
  the 8-byte name slice partially overlaps the real name bytes. This is a known v1 limitation —
  targeted for mitigation in v3 (decoy names) and v2 (field reordering).
- Reader never produced "No struct found" — magic header and count field remain in fixed positions,
  so `decode_register` always passes the size check before unpacking garbage entity bytes.
  This confirms the magic anchor is the reader's only reliable foothold — a key target for v3 decoys.

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

*Last updated: v1 fragmented layout validated.*
