#!/usr/bin/env python3
"""
process_reader_v4.py  —  Reader v4 (for phase10_prototype.py / v10)

Inherits all v3 structural heuristics unchanged:
  - wild_coords penalty  (-30)
  - epoch_inc bonus      (+25)
  - epoch_frozen penalty (-40)
  - address stability    (+5 per pass, cap +20)
  - content_valid check  (coords in [0,9] after raw decode)

New in v4
---------
* Attempts a "timing-inference" attack on top of structural scoring:
    - Records the wall-clock timestamp of every BEST CANDIDATE selection
    - Computes inter-swap delta estimates from successive BEST CANDIDATE epochs
    - Tries to predict the next swap instant and time a read to the predicted window
    - Reports whether the timed read produced content-valid data

* Expected outcome:
    - Timing inference can detect a ~1 s cadence from epoch increments (v4 relocation
      observable via epoch field)
    - But every timed read still returns CONTENT:encrypted/garbage because:
        a) The key-derivation page is destroyed before the scrub window closes
        b) The encrypted payload is indistinguishable from random bytes at any
           scan instant within the coherence window
    - Timing-inference precision = 0 / N timed reads — confirms polymorphic exec
      provides no timing side-channel that helps content recovery

Usage
-----
    sudo python3 process_reader_v4.py
    (enter PID of phase10_prototype.py when prompted)
"""

import os
import re
import struct
import sys
import time
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Layout constants (must match phase10_prototype.py)
# ---------------------------------------------------------------------------
MAGIC        = 0x1FA1
VERSION      = 10
HEADER_SIZE  = 10
ENTITY_SIZE  = 22
EXPECTED_VER = VERSION
EXPECTED_CNT = 2
COORD_MIN    = 0
COORD_MAX    = 9

SCAN_PASSES  = 20
SCAN_DELAY   = 0.5   # seconds between passes
HIGH_THRESH  = 55    # score >= HIGH_THRESH ⇒ HIGH confidence
MED_THRESH   = 30

# ---------------------------------------------------------------------------
# /proc reader helpers
# ---------------------------------------------------------------------------
def list_rw_regions(pid: int) -> List[Tuple[int, int]]:
    regions = []
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                perms = parts[1]
                if perms != "rw-p":
                    continue
                addrs = parts[0].split("-")
                start = int(addrs[0], 16)
                end   = int(addrs[1], 16)
                regions.append((start, end))
    except Exception:
        pass
    return regions


def read_mem(pid: int, addr: int, size: int) -> Optional[bytes]:
    try:
        with open(f"/proc/{pid}/mem", "rb") as f:
            f.seek(addr)
            return f.read(size)
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Struct parsing
# ---------------------------------------------------------------------------
def try_parse_header(data: bytes) -> Optional[Tuple[int, int, int, int]]:
    """Returns (version, tick, epoch, count) or None."""
    if len(data) < HEADER_SIZE:
        return None
    magic, ver, tick = struct.unpack_from("<HBB", data, 0)
    epoch,           = struct.unpack_from("<I",   data, 4)
    count,           = struct.unpack_from("<H",   data, 8)
    if magic != MAGIC:
        return None
    if ver != EXPECTED_VER:
        return None
    if count != EXPECTED_CNT:
        return None
    return ver, tick, epoch, count


def raw_decode_entities(data: bytes, count: int) -> List[Tuple[str, int, int]]:
    """
    Attempt a naive fixed-offset decode of entity fields (as if no padding /
    no encryption).  In v10 this will always return garbage.
    """
    entities = []
    off = HEADER_SIZE
    for _ in range(count):
        if off + ENTITY_SIZE > len(data):
            break
        chunk = data[off:off + ENTITY_SIZE]
        name = chunk[0:8].rstrip(b"\x00").decode(errors="replace")
        x    = struct.unpack_from("<i", chunk, 10)[0]
        y    = struct.unpack_from("<i", chunk, 14)[0]
        entities.append((name, x, y))
        off += ENTITY_SIZE
    return entities


def content_valid(entities: List[Tuple[str, int, int]]) -> bool:
    """True only if every coord is in [COORD_MIN, COORD_MAX]."""
    for _, x, y in entities:
        if not (COORD_MIN <= x <= COORD_MAX and COORD_MIN <= y <= COORD_MAX):
            return False
    return True

# ---------------------------------------------------------------------------
# Per-address state for scoring
# ---------------------------------------------------------------------------
class AddrRecord:
    def __init__(self):
        self.seen_passes: int = 0
        self.last_epoch:  Optional[int] = None
        self.last_score:  int = 0

# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def score_candidate(
    rec:       AddrRecord,
    epoch:     int,
    entities:  List[Tuple[str, int, int]],
) -> Tuple[int, List[str]]:
    reasons = []
    score   = 0

    # Wild-coords penalty
    if not content_valid(entities):
        score   -= 30
        reasons.append("wild_coords(-30)")

    # Epoch signal
    if rec.last_epoch is None:
        reasons.append("first_seen")
    elif epoch == rec.last_epoch:
        score   -= 40
        reasons.append("epoch_frozen(-40)")
    elif epoch == rec.last_epoch + 1:
        score   += 25
        reasons.append("epoch_inc(+25)")

    # Stability bonus (cap at 4 passes = +20)
    stability = min(rec.seen_passes, 4) * 5
    if stability > 0:
        score   += stability
        reasons.append(f"stability(+{stability}, {rec.seen_passes} passes)")

    return score, reasons


def confidence_label(score: int) -> str:
    if score >= HIGH_THRESH:
        return "HIGH  "
    elif score >= MED_THRESH:
        return "MEDIUM"
    else:
        return "LOW   "

# ---------------------------------------------------------------------------
# Timing-inference attack (v4 new layer)
# ---------------------------------------------------------------------------
class TimingOracle:
    """
    Records (wall_time, epoch) pairs from BEST CANDIDATE reads.
    Estimates swap cadence and predicts next swap instant.
    On a predicted window, schedules a timed read and checks content validity.
    """
    def __init__(self):
        self._observations: List[Tuple[float, int]] = []
        self._content_valid_timed: int = 0
        self._total_timed: int = 0

    def record(self, wall_time: float, epoch: int):
        self._observations.append((wall_time, epoch))

    def estimated_cadence(self) -> Optional[float]:
        """Return estimated seconds-per-epoch from last 4 observations."""
        obs = self._observations[-5:]
        if len(obs) < 2:
            return None
        deltas = [
            (obs[i][0] - obs[i-1][0]) / max(obs[i][1] - obs[i-1][1], 1)
            for i in range(1, len(obs))
        ]
        return sum(deltas) / len(deltas)

    def predicted_next_swap(self) -> Optional[float]:
        if not self._observations:
            return None
        cadence = self.estimated_cadence()
        if cadence is None:
            return None
        last_t, _ = self._observations[-1]
        return last_t + cadence

    def attempt_timed_read(
        self,
        pid: int,
        addr: int,
        block_size: int,
        count: int,
    ) -> bool:
        """Schedule a read at the predicted swap instant. Returns content_valid."""
        predicted = self.predicted_next_swap()
        if predicted is None:
            return False
        wait = predicted - time.time()
        if wait > 0:
            time.sleep(wait)
        raw = read_mem(pid, addr, block_size + 4)  # +4 for canary
        if raw is None:
            return False
        parsed = try_parse_header(raw)
        if parsed is None:
            return False
        _, _, epoch, cnt = parsed
        ents = raw_decode_entities(raw, cnt)
        valid = content_valid(ents)
        self._total_timed += 1
        if valid:
            self._content_valid_timed += 1
        return valid

    def summary(self) -> str:
        return (
            f"Timing-inference timed reads: {self._total_timed}\n"
            f"  Content-valid timed reads:  {self._content_valid_timed}\n"
            f"  Cadence estimate:           {self.estimated_cadence():.3f}s"
            if self.estimated_cadence() else
            f"Timing-inference timed reads: {self._total_timed}\n"
            f"  Content-valid timed reads:  {self._content_valid_timed}\n"
            f"  Cadence estimate:           N/A"
        )

# ---------------------------------------------------------------------------
# Main scan loop
# ---------------------------------------------------------------------------
def main():
    pid = int(input("Enter target process pid: ").strip())

    block_size = HEADER_SIZE + EXPECTED_CNT * ENTITY_SIZE

    print(f"Starting {SCAN_PASSES} scan passes, {SCAN_DELAY}s apart...")
    print("Scanning rw-p regions only | expected count=2")
    print("NOTE: reader v4 — structural heuristics + timing-inference attack.")
    print("      Real payload fields are SHAKE-256 XOR encrypted (v9 layer).")
    print("      Key-derivation page destroyed after each epoch (v10 layer).")
    print("      Expected: timing inference yields 0 content-valid timed reads.")
    print()
    print(f"  Score guide: >={HIGH_THRESH} = high conf | {MED_THRESH}..{HIGH_THRESH-1} = medium | <{MED_THRESH} = low / noise...")

    records:    Dict[int, AddrRecord] = defaultdict(AddrRecord)
    seen_prev:  set = set()
    timing_oracle = TimingOracle()

    high_conf_count       = 0
    content_valid_count   = 0
    best_addr_overall:    Optional[int] = None
    best_score_overall:   int = -9999

    for pass_num in range(1, SCAN_PASSES + 1):
        regions   = list_rw_regions(pid)
        seen_now  = set()
        pass_hits = []

        for (start, end) in regions:
            size = end - start
            if size < block_size:
                continue

            raw = read_mem(pid, start, size)
            if raw is None:
                continue

            for offset in range(0, size - block_size + 1, 4):
                chunk = raw[offset:offset + block_size]
                parsed = try_parse_header(chunk)
                if parsed is None:
                    continue
                ver, tick, epoch, count = parsed
                addr = start + offset
                seen_now.add(addr)

                rec = records[addr]
                ents = raw_decode_entities(chunk, count)
                score, reasons = score_candidate(rec, epoch, ents)
                label = confidence_label(score)
                is_new = addr not in seen_prev
                is_gone_candidates = seen_prev - seen_now

                new_tag = "  <-- NEW" if is_new else ""
                content_tag = "CONTENT:valid" if content_valid(ents) else "CONTENT:encrypted/garbage"

                enc_flag = " [ENC?]" if not content_valid(ents) else ""
                ent_strs = ", ".join(
                    f"Entity(name='{n}', x={x}, y={y}{enc_flag})"
                    for n, x, y in ents
                )

                print(f"[pass {pass_num:02d}] 0x{addr:x} (rw-p) {new_tag} ver={ver} tick={tick} epoch={epoch} "
                      f" score={score:+d} [{label}]  {content_tag}  reasons={reasons}")
                print(f"          entities: [{ent_strs}]")

                rec.seen_passes += 1
                rec.last_epoch   = epoch
                rec.last_score   = score

                if score >= HIGH_THRESH:
                    high_conf_count += 1
                if content_valid(ents):
                    content_valid_count += 1

                pass_hits.append((score, addr, epoch, ents))

        # Report gone addresses
        for gone_addr in sorted(seen_prev - seen_now):
            print(f"[pass {pass_num:02d}]           0x{gone_addr:x}  <-- gone")

        # Best candidate this pass
        if pass_hits:
            pass_hits.sort(key=lambda t: t[0], reverse=True)
            best_score, best_addr, best_epoch, best_ents = pass_hits[0]
            best_ent_str = ", ".join(
                f"Entity(name='{n}', x={x}, y={y} [ENC?])"
                for n, x, y in best_ents
            )
            content_tag = "CONTENT:valid" if content_valid(best_ents) else "CONTENT:encrypted/garbage"
            print(f"[pass {pass_num:02d}] >> BEST CANDIDATE: 0x{best_addr:x}  score={best_score:+d}  "
                  f"epoch={best_epoch}  {content_tag}  entities=[{best_ent_str}]")

            # Update overall best
            if best_score > best_score_overall:
                best_score_overall = best_score
                best_addr_overall  = best_addr

            # Feed timing oracle
            timing_oracle.record(time.time(), best_epoch)

            # Attempt timed read on best candidate every 3 passes
            if pass_num % 3 == 0 and best_addr is not None:
                cadence = timing_oracle.estimated_cadence()
                if cadence is not None:
                    print(f"[pass {pass_num:02d}] [timing-inference] cadence={cadence:.3f}s  "
                          f"predicted_next={timing_oracle.predicted_next_swap():.3f}")
                    result = timing_oracle.attempt_timed_read(
                        pid, best_addr, block_size, EXPECTED_CNT
                    )
                    result_tag = "CONTENT:valid [BREACH]" if result else "CONTENT:encrypted/garbage [safe]"
                    print(f"[pass {pass_num:02d}] [timing-inference] timed read result: {result_tag}")

        print()
        seen_prev = seen_now
        time.sleep(SCAN_DELAY)

    # ---------------------------------------------------------------------------
    # Final summary
    # ---------------------------------------------------------------------------
    print("=" * 70)
    print("SCAN COMPLETE — Reader v4 Summary")
    print(f"  Structural HIGH-confidence candidates: {high_conf_count}")
    print(f"  Content-valid candidates (raw decode):  {content_valid_count}")
    print()
    if content_valid_count == 0:
        print("  None. ✓ All candidates returned encrypted/garbage payload.")
        print("  Content-level precision = 0/N — encryption epoch system intact.")
    else:
        print(f"  WARNING: {content_valid_count} content-valid reads detected.")
    print()
    print(timing_oracle.summary())
    print()
    if best_addr_overall is not None:
        print(f"  Best structural candidate overall: 0x{best_addr_overall:x}  score={best_score_overall:+d}")
        print(f"  Score ceiling vs HIGH threshold: {best_score_overall} / {HIGH_THRESH}")
        if best_score_overall < HIGH_THRESH:
            print("  ✓ Score ceiling below HIGH threshold — polymorphic exec layer intact.")
        else:
            print("  ! Score ceiling reached HIGH threshold — review decoy quality.")
    print("=" * 70)


if __name__ == "__main__":
    main()
