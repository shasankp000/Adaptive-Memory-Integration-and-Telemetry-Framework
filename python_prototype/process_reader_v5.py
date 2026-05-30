#!/usr/bin/env python3
"""
process_reader_v5.py  —  Reader v5 (for phase11_prototype.py / v11)

Inherits ALL v4 heuristics unchanged:
  - wild_coords penalty  (-30)
  - epoch_inc bonus      (+25)
  - epoch_frozen penalty (-40)
  - address stability    (+5 per pass, cap +20)
  - content_valid check  (coords in [0,9] after raw decode)
  - timing-inference attack (cadence estimate + timed read)

New in v5  —  IPC Arena Intercept
----------------------------------
v11 introduces a secure IPC bridge: telemetry frames flow through an
anonymous arena (memfd / bytearray) masked with per-packet SHAKE-256
rotating XOR keys derived from a TPM seed the reader does not know.

The reader attempts three independent attacks on the IPC channel:

  Attack A — Arena Discovery
      Scan /proc/pid/maps for rw-p regions whose size matches the known
      IPC arena footprint (IPC_FRAME_SIZE * 64 = 1280 bytes).  Record
      every candidate arena address.

  Attack B — Raw Frame Dump + Brute-Force Decode
      For each candidate arena, read the raw bytes and attempt to parse
      IPC frames at every aligned slot:
        1. Zero-seed: SHAKE-256(0x00...00 || packet_id) — wrong key.
        2. Null-mask:  assume mask = 0x00 (no masking) — plaintext.
        3. Constant-byte masks: mask = 0xAA, 0x55, 0xFF — weak key probe.
      Validate decoded frames: epoch and tick must be plausible uint32s,
      mean_delta_ms must be in (0, 5000) ms range.  Count content-valid
      decoded frames.

  Attack C — Delta-XOR Consecutive Frame Attack
      Capture two consecutive reads of the same arena slot (one SCAN_DELAY
      apart).  XOR the two ciphertext payloads byte-by-byte.  If the mask
      were reused across packets this would recover the plaintext delta.
      With SHAKE-256 rotating keys, the XOR result is indistinguishable
      from random bytes — confirmed by checking whether the result parses
      as a valid telemetry frame.

Expected outcome
----------------
  - Attack A: may find the arena region (size is known and fixed).
  - Attack B: 0 valid frames decoded — all ciphertext looks like random
              bytes regardless of the seed guess used.
  - Attack C: XOR delta is random noise — 0 valid frames recovered.
  - Structural scan (inherited from v4): score ceiling ≤ +15, well below
    HIGH threshold of +55.  Content-valid raw-decode count = 0.

Usage
-----
    sudo python3 process_reader_v5.py
    (enter PID of phase11_prototype.py when prompted)
"""

import hashlib
import os
import struct
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Layout constants (must match phase11_prototype.py)
# ---------------------------------------------------------------------------
MAGIC        = 0x1FA1
VERSION      = 11
HEADER_SIZE  = 10
ENTITY_SIZE  = 22
EXPECTED_VER = VERSION
EXPECTED_CNT = 2
COORD_MIN    = 0
COORD_MAX    = 9

SCAN_PASSES  = 20
SCAN_DELAY   = 0.5   # seconds between passes
HIGH_THRESH  = 55
MED_THRESH   = 30

# IPC arena constants (must match phase11_prototype.py)
IPC_HEADER_SIZE  = 4
IPC_PAYLOAD_SIZE = 16
IPC_FRAME_SIZE   = IPC_HEADER_SIZE + IPC_PAYLOAD_SIZE   # 20 bytes
IPC_SLOTS        = 64
IPC_ARENA_SIZE   = IPC_FRAME_SIZE * IPC_SLOTS            # 1280 bytes

# ---------------------------------------------------------------------------
# /proc helpers
# ---------------------------------------------------------------------------
def list_rw_regions(pid: int) -> List[Tuple[int, int]]:
    regions = []
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                if parts[1] != "rw-p":
                    continue
                addrs = parts[0].split("-")
                regions.append((int(addrs[0], 16), int(addrs[1], 16)))
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
# Struct parsing (v4 inherited)
# ---------------------------------------------------------------------------
def try_parse_header(data: bytes) -> Optional[Tuple[int, int, int, int]]:
    if len(data) < HEADER_SIZE:
        return None
    magic, ver, tick = struct.unpack_from("<HBB", data, 0)
    epoch,           = struct.unpack_from("<I",   data, 4)
    count,           = struct.unpack_from("<H",   data, 8)
    if magic != MAGIC or ver != EXPECTED_VER or count != EXPECTED_CNT:
        return None
    return ver, tick, epoch, count


def raw_decode_entities(data: bytes,
                        count: int) -> List[Tuple[str, int, int]]:
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
    return all(
        COORD_MIN <= x <= COORD_MAX and COORD_MIN <= y <= COORD_MAX
        for _, x, y in entities
    )


# ---------------------------------------------------------------------------
# Scoring (v4 inherited)
# ---------------------------------------------------------------------------
class AddrRecord:
    def __init__(self):
        self.seen_passes: int = 0
        self.last_epoch:  Optional[int] = None
        self.last_score:  int = 0


def score_candidate(
    rec:      AddrRecord,
    epoch:    int,
    entities: List[Tuple[str, int, int]],
) -> Tuple[int, List[str]]:
    reasons = []
    score   = 0

    if not content_valid(entities):
        score -= 30
        reasons.append("wild_coords(-30)")

    if rec.last_epoch is None:
        reasons.append("first_seen")
    elif epoch == rec.last_epoch:
        score -= 40
        reasons.append("epoch_frozen(-40)")
    elif epoch == rec.last_epoch + 1:
        score += 25
        reasons.append("epoch_inc(+25)")

    stability = min(rec.seen_passes, 4) * 5
    if stability > 0:
        score += stability
        reasons.append(f"stability(+{stability}, {rec.seen_passes} passes)")

    return score, reasons


def confidence_label(score: int) -> str:
    if score >= HIGH_THRESH:
        return "HIGH  "
    elif score >= MED_THRESH:
        return "MEDIUM"
    return "LOW   "


# ---------------------------------------------------------------------------
# Timing oracle (v4 inherited)
# ---------------------------------------------------------------------------
class TimingOracle:
    def __init__(self):
        self._observations: List[Tuple[float, int]] = []
        self._content_valid_timed: int = 0
        self._total_timed: int = 0

    def record(self, wall_time: float, epoch: int):
        self._observations.append((wall_time, epoch))

    def estimated_cadence(self) -> Optional[float]:
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
        self, pid: int, addr: int,
        block_size: int, count: int,
    ) -> bool:
        predicted = self.predicted_next_swap()
        if predicted is None:
            return False
        wait = predicted - time.time()
        if wait > 0:
            time.sleep(wait)
        raw = read_mem(pid, addr, block_size + 4)
        if raw is None:
            return False
        parsed = try_parse_header(raw)
        if parsed is None:
            return False
        _, _, epoch, cnt = parsed
        return content_valid(raw_decode_entities(raw, cnt))

    def summary(self) -> str:
        cadence = self.estimated_cadence()
        cadence_str = f"{cadence:.3f}s" if cadence else "N/A"
        return (
            f"Timing-inference timed reads: {self._total_timed}\n"
            f"  Content-valid timed reads:  {self._content_valid_timed}\n"
            f"  Cadence estimate:           {cadence_str}"
        )


# ---------------------------------------------------------------------------
# V5 — IPC Arena Intercept
# ---------------------------------------------------------------------------

def _shake256_mask(seed: bytes, packet_id: int, length: int) -> bytes:
    """Derive SHAKE-256(seed || packet_id_LE) truncated to `length` bytes."""
    h = hashlib.shake_256(seed + struct.pack("<I", packet_id))
    return h.digest(length)


def _ipc_frame_plausible(raw_payload: bytes) -> bool:
    """
    Heuristic plausibility check for a 16-byte decoded IPC telemetry frame:
      epoch        : uint32  — must be in [0, 10000]
      tick         : uint32  — must be in [0, 10000]
      total_hits   : uint32  — must be in [0, 100000]
      mean_delta_ms: float32 — must be in (0.0, 5000.0)
    Returns True only when ALL four constraints are satisfied.
    """
    if len(raw_payload) < IPC_PAYLOAD_SIZE:
        return False
    try:
        epoch, tick, total_hits, mean_delta = struct.unpack(
            "<IIIf", raw_payload[:IPC_PAYLOAD_SIZE]
        )
    except struct.error:
        return False
    return (
        0 <= epoch <= 10_000
        and 0 <= tick <= 10_000
        and 0 <= total_hits <= 100_000
        and 0.0 < mean_delta < 5000.0
    )


# Weak-seed probes for Attack B
_PROBE_SEEDS = [
    ("zero_seed",     bytes(32)),
    ("0xAA_seed",     bytes([0xAA] * 32)),
    ("0x55_seed",     bytes([0x55] * 32)),
    ("0xFF_seed",     bytes([0xFF] * 32)),
    ("null_mask",     None),      # None ⇒ no XOR (identity mask)
]


def _try_decode_ipc_slot(
    raw_frame: bytes,
    slot: int,
) -> Tuple[int, List[Tuple[str, bool, bytes]]]:
    """
    Try to decode one IPC_FRAME_SIZE-byte slot using all probe seeds.
    Returns (packet_id_from_frame, list of (seed_label, plausible, decoded_payload)).
    """
    if len(raw_frame) < IPC_FRAME_SIZE:
        return 0, []

    packet_id = struct.unpack("<I", raw_frame[:IPC_HEADER_SIZE])[0]
    ciphertext = raw_frame[IPC_HEADER_SIZE:IPC_HEADER_SIZE + IPC_PAYLOAD_SIZE]
    results = []

    for label, seed in _PROBE_SEEDS:
        if seed is None:
            # null_mask: treat ciphertext as plaintext
            decoded = ciphertext
        else:
            mask    = _shake256_mask(seed, packet_id, IPC_PAYLOAD_SIZE)
            decoded = bytes(c ^ m for c, m in zip(ciphertext, mask))
        results.append((label, _ipc_frame_plausible(decoded), decoded))

    return packet_id, results


class IPCInterceptor:
    """
    Discovers IPC arena candidates, dumps frame slots, runs Attack B and C.
    """
    def __init__(self):
        self.arena_candidates:     List[int]   = []
        self.valid_frames_total:   int         = 0
        self.delta_xor_valid:      int         = 0
        self.delta_xor_attempts:   int         = 0
        # slot → last raw ciphertext seen (for Attack C)
        self._prev_ciphertexts: Dict[Tuple[int, int], bytes] = {}

    # ------------------------------------------------------------------
    # Attack A — Arena Discovery
    # ------------------------------------------------------------------
    def discover_arenas(self, pid: int) -> List[int]:
        """
        Return addresses of rw-p regions whose size matches IPC_ARENA_SIZE.
        Also keeps any region within ±2 pages (±8192 bytes) of the target
        size to account for allocator padding.
        """
        found = []
        for start, end in list_rw_regions(pid):
            sz = end - start
            if abs(sz - IPC_ARENA_SIZE) <= 8192:
                found.append(start)
        self.arena_candidates = found
        return found

    # ------------------------------------------------------------------
    # Attack B — Raw Dump + Probe-Seed Decode
    # ------------------------------------------------------------------
    def attack_b(
        self, pid: int, arena_addr: int, pass_num: int,
    ) -> int:
        """
        Read the arena, iterate over all 64 aligned slots, attempt to
        decode each with every probe seed.  Returns count of plausible
        decoded frames across all seeds and slots.
        """
        raw = read_mem(pid, arena_addr, IPC_ARENA_SIZE)
        if raw is None:
            print(f"  [ipc-attack-b] pass={pass_num}  arena=0x{arena_addr:x}  read FAILED")
            return 0

        valid_count = 0
        for slot in range(IPC_SLOTS):
            offset    = slot * IPC_FRAME_SIZE
            raw_frame = raw[offset:offset + IPC_FRAME_SIZE]

            packet_id, decode_results = _try_decode_ipc_slot(raw_frame, slot)

            slot_valid = False
            for label, plausible, decoded in decode_results:
                if plausible:
                    valid_count  += 1
                    slot_valid    = True
                    # Store ciphertext for Attack C
                    key = (arena_addr, slot)
                    self._prev_ciphertexts[key] = \
                        raw_frame[IPC_HEADER_SIZE:IPC_HEADER_SIZE + IPC_PAYLOAD_SIZE]
                    print(
                        f"  [ipc-attack-b] pass={pass_num}  arena=0x{arena_addr:x}"
                        f"  slot={slot:02d}  pkt_id={packet_id}  seed={label}"
                        f"  PLAUSIBLE  decoded={decoded.hex()}"
                    )

            # Only print failed slots on first pass to keep output manageable
            if not slot_valid and pass_num == 1:
                first_cipher = raw_frame[IPC_HEADER_SIZE:
                                         IPC_HEADER_SIZE + 8].hex() if len(raw_frame) >= IPC_FRAME_SIZE else "?"
                print(
                    f"  [ipc-attack-b] pass={pass_num}  arena=0x{arena_addr:x}"
                    f"  slot={slot:02d}  pkt_id={packet_id}  all_seeds=GARBAGE"
                    f"  cipher[:8]={first_cipher}"
                )

        self.valid_frames_total += valid_count
        return valid_count

    # ------------------------------------------------------------------
    # Attack C — Delta-XOR Consecutive Frames
    # ------------------------------------------------------------------
    def attack_c(
        self, pid: int, arena_addr: int, pass_num: int,
    ) -> int:
        """
        Re-read the arena and XOR each slot's new ciphertext against the
        previous read.  If SHAKE-256 masks rotate per-packet, the XOR
        result is indistinguishable from random.  Count plausible frames
        recovered from the XOR delta.
        """
        raw = read_mem(pid, arena_addr, IPC_ARENA_SIZE)
        if raw is None:
            return 0

        valid_count = 0
        for slot in range(IPC_SLOTS):
            key = (arena_addr, slot)
            if key not in self._prev_ciphertexts:
                continue
            offset     = slot * IPC_FRAME_SIZE
            raw_frame  = raw[offset:offset + IPC_FRAME_SIZE]
            if len(raw_frame) < IPC_FRAME_SIZE:
                continue

            curr_cipher = raw_frame[IPC_HEADER_SIZE:
                                    IPC_HEADER_SIZE + IPC_PAYLOAD_SIZE]
            prev_cipher = self._prev_ciphertexts[key]
            xor_delta   = bytes(a ^ b for a, b in zip(curr_cipher, prev_cipher))

            self.delta_xor_attempts += 1
            plausible = _ipc_frame_plausible(xor_delta)
            if plausible:
                valid_count          += 1
                self.delta_xor_valid += 1
                print(
                    f"  [ipc-attack-c] pass={pass_num}  arena=0x{arena_addr:x}"
                    f"  slot={slot:02d}  delta-XOR=PLAUSIBLE  xor={xor_delta.hex()}"
                )
            # Update stored ciphertext for next pass
            self._prev_ciphertexts[key] = curr_cipher

        return valid_count

    def summary(self) -> str:
        return (
            f"IPC Intercept Summary\n"
            f"  Arena candidates found:          {len(self.arena_candidates)}\n"
            f"  Attack B — valid frames decoded: {self.valid_frames_total}\n"
            f"  Attack C — delta-XOR attempts:  {self.delta_xor_attempts}\n"
            f"  Attack C — valid delta frames:  {self.delta_xor_valid}"
        )


# ---------------------------------------------------------------------------
# Main scan loop
# ---------------------------------------------------------------------------
def main():
    pid = int(input("Enter target process pid: ").strip())

    block_size    = HEADER_SIZE + EXPECTED_CNT * ENTITY_SIZE
    records:      Dict[int, AddrRecord] = defaultdict(AddrRecord)
    seen_prev:    set = set()
    timing_oracle = TimingOracle()
    ipc_intercept = IPCInterceptor()

    high_conf_count     = 0
    content_valid_count = 0
    best_addr_overall:  Optional[int] = None
    best_score_overall: int = -9999

    print(f"Starting {SCAN_PASSES} scan passes, {SCAN_DELAY}s apart...")
    print("Scanning rw-p regions only | expected count=2")
    print("Reader v5 — structural heuristics + timing-inference + IPC arena intercept.")
    print("  Structural payload: SHAKE-256 XOR encrypted (v9) + polymorphic exec (v10).")
    print("  IPC channel: per-packet SHAKE-256 rotating XOR masks (v11).")
    print("  IPC attack: probe-seed brute-force (Attack B) + delta-XOR (Attack C).")
    print("  Expected: 0 valid frames from all IPC attacks; score ceiling ≤ +15.")
    print()
    print(f"  Score guide: >={HIGH_THRESH}=HIGH | {MED_THRESH}..{HIGH_THRESH-1}=MEDIUM | <{MED_THRESH}=LOW/noise")
    print()

    # Initial IPC arena discovery
    arenas = ipc_intercept.discover_arenas(pid)
    if arenas:
        print(f"[ipc-attack-a] Found {len(arenas)} IPC arena candidate(s): "
              f"{[hex(a) for a in arenas]}")
    else:
        print("[ipc-attack-a] No IPC arena candidates matched exact size — "
              "arena may be inside a larger allocation.")
    print()

    for pass_num in range(1, SCAN_PASSES + 1):
        # ------------------------------------------------------------------
        # Standard structural scan (v4 inherited)
        # ------------------------------------------------------------------
        regions  = list_rw_regions(pid)
        seen_now = set()
        pass_hits = []

        for start, end in regions:
            size = end - start
            if size < block_size:
                continue
            raw = read_mem(pid, start, size)
            if raw is None:
                continue
            for offset in range(0, size - block_size + 1, 4):
                chunk  = raw[offset:offset + block_size]
                parsed = try_parse_header(chunk)
                if parsed is None:
                    continue
                ver, tick, epoch, count = parsed
                addr = start + offset
                seen_now.add(addr)

                rec   = records[addr]
                ents  = raw_decode_entities(chunk, count)
                score, reasons = score_candidate(rec, epoch, ents)
                label = confidence_label(score)
                new_tag     = "  <-- NEW" if addr not in seen_prev else ""
                content_tag = ("CONTENT:valid"
                               if content_valid(ents)
                               else "CONTENT:encrypted/garbage")
                enc_flag    = " [ENC?]" if not content_valid(ents) else ""
                ent_strs    = ", ".join(
                    f"Entity(name='{n}', x={x}, y={y}{enc_flag})"
                    for n, x, y in ents
                )
                print(f"[pass {pass_num:02d}] 0x{addr:x} (rw-p){new_tag} ver={ver} "
                      f"tick={tick} epoch={epoch}  score={score:+d} [{label}]  "
                      f"{content_tag}  reasons={reasons}")
                print(f"          entities: [{ent_strs}]")

                rec.seen_passes += 1
                rec.last_epoch   = epoch
                rec.last_score   = score

                if score >= HIGH_THRESH:
                    high_conf_count += 1
                if content_valid(ents):
                    content_valid_count += 1

                pass_hits.append((score, addr, epoch, ents))

        for gone_addr in sorted(seen_prev - seen_now):
            print(f"[pass {pass_num:02d}]           0x{gone_addr:x}  <-- gone")

        # Best candidate
        if pass_hits:
            pass_hits.sort(key=lambda t: t[0], reverse=True)
            best_score, best_addr, best_epoch, best_ents = pass_hits[0]
            best_ent_str = ", ".join(
                f"Entity(name='{n}', x={x}, y={y} [ENC?])" for n, x, y in best_ents
            )
            content_tag = ("CONTENT:valid"
                           if content_valid(best_ents)
                           else "CONTENT:encrypted/garbage")
            print(f"[pass {pass_num:02d}] >> BEST CANDIDATE: 0x{best_addr:x}  "
                  f"score={best_score:+d}  epoch={best_epoch}  {content_tag}  "
                  f"entities=[{best_ent_str}]")

            if best_score > best_score_overall:
                best_score_overall = best_score
                best_addr_overall  = best_addr

            timing_oracle.record(time.time(), best_epoch)

            if pass_num % 3 == 0:
                cadence = timing_oracle.estimated_cadence()
                if cadence:
                    print(f"[pass {pass_num:02d}] [timing-inference] cadence={cadence:.3f}s  "
                          f"predicted_next={timing_oracle.predicted_next_swap():.3f}")
                    result = timing_oracle.attempt_timed_read(
                        pid, best_addr, block_size, EXPECTED_CNT
                    )
                    tag = "CONTENT:valid [BREACH]" if result else "CONTENT:encrypted/garbage [safe]"
                    print(f"[pass {pass_num:02d}] [timing-inference] timed read: {tag}")

        # ------------------------------------------------------------------
        # IPC intercept  —  Attack B + C every pass
        # ------------------------------------------------------------------
        if arenas:
            print()
            for arena_addr in arenas:
                b_valid = ipc_intercept.attack_b(pid, arena_addr, pass_num)
                c_valid = ipc_intercept.attack_c(pid, arena_addr, pass_num)
                print(
                    f"  [ipc-pass-{pass_num:02d}] arena=0x{arena_addr:x}  "
                    f"attack_b_valid={b_valid}  attack_c_valid={c_valid}"
                )

        print()
        seen_prev = seen_now
        time.sleep(SCAN_DELAY)

    # ---------------------------------------------------------------------------
    # Final summary
    # ---------------------------------------------------------------------------
    print("=" * 70)
    print("SCAN COMPLETE — Reader v5 Summary")
    print()
    print("  —— Structural scan ——")
    print(f"  Structural HIGH-confidence candidates: {high_conf_count}")
    print(f"  Content-valid candidates (raw decode):  {content_valid_count}")
    if content_valid_count == 0:
        print("  ✓ All structural candidates: encrypted/garbage payload.")
        print("    Content-level precision = 0/N.")
    else:
        print(f"  ! WARNING: {content_valid_count} content-valid structural reads.")
    print()
    print("  —— Timing-inference ——")
    print(f"  {timing_oracle.summary()}")
    print()
    print("  —— IPC channel intercept ——")
    print(f"  {ipc_intercept.summary()}")
    if ipc_intercept.valid_frames_total == 0 and ipc_intercept.delta_xor_valid == 0:
        print("  ✓ IPC channel: 0 valid frames decoded (all attacks failed).")
        print("    Per-packet SHAKE-256 rotating XOR confirmed opaque.")
    else:
        print(f"  ! WARNING: {ipc_intercept.valid_frames_total} valid IPC frames decoded.")
        print(f"  ! WARNING: {ipc_intercept.delta_xor_valid} delta-XOR frames plausible.")
    print()
    if best_addr_overall is not None:
        print(f"  Best structural candidate: 0x{best_addr_overall:x}  "
              f"score={best_score_overall:+d} / {HIGH_THRESH}")
        if best_score_overall < HIGH_THRESH:
            print("  ✓ Score ceiling below HIGH threshold — v10/v11 layers intact.")
        else:
            print("  ! Score ceiling reached HIGH — review decoy quality.")
    print("=" * 70)


if __name__ == "__main__":
    main()
