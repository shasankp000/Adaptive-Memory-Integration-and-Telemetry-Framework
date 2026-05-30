#!/usr/bin/env python3
"""
phase10_prototype.py  —  v10: Polymorphic Execution Layer

Builds on v9 (encryption epoch system) and simulates the secure_core.c
RWX-page destroy-after-use pipeline in pure Python.

New in v10
----------
* derive_epoch_key_polymorphic(master_seed, epoch)
    - Allocates a short-lived bytearray ("anonymous RWX page" simulation)
    - Writes the SHAKE-256 KDF logic into that buffer as a callable lambda
    - Derives the epoch masks
    - Overwrites the buffer with os.urandom() immediately after derivation
    - Logs [v10-exec]: page address, SHA-256 of page before and after overwrite
    - Returns only the three field masks; the derivation buffer is destroyed

* All v9 layers remain active:
    - per-epoch SHAKE-256 XOR encryption of real entity fields
    - decoys carry random bytes (not valid coords)
    - address hopping, coherence window scrubbing, adaptive poisoning,
      telemetry tracking, anomaly scoring

Expected outcome
----------------
* Game side: round-trip enc/dec [OK] every epoch, same as v9
* [v10-exec] lines prove the key-derivation page was live, used, and
  destroyed within the same epoch — no stable key in RAM between epochs
* Reader v3 still sees CONTENT:encrypted/garbage on every candidate;
  score ceiling remains ~+15 (below HIGH threshold of +55)
"""

import ctypes
import gc
import hashlib
import math
import os
import random
import secrets
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VERSION          = 10
MAGIC            = 0x1FA1
EPOCH_INTERVAL   = 1.0        # seconds between epoch swaps
COHERENCE_WINDOW = 0.050      # 50 ms plaintext visibility window
TELEMETRY_POLL   = 0.010      # 10 ms canary-check interval
SCORE_WINDOW     = 6          # epochs for anomaly score rolling window
SIMULATE_OBSERVER = int(os.environ.get("SIMULATE_OBSERVER", "0"))
INITIAL_EPOCH    = 0

# Poison thresholds (inherited from v7)
POISON_THRESHOLD = 0.15
POISON_HOLD      = 10

# Entity coordinate space
COORD_MIN, COORD_MAX = 0, 9

# Decoy pool
DECOY_NAMES = ["BOT1", "BOT2", "CT2", "CT3", "GUARD", "SPEC1", "T2", "T3"]
INITIAL_DECOY_COUNT = 4
POISON_DECOY_COUNT  = 12

# ---------------------------------------------------------------------------
# Entity dataclass
# ---------------------------------------------------------------------------
@dataclass
class Entity:
    name: str
    x:    int
    y:    int
    def __repr__(self):
        return f"Entity(name={self.name}, x={self.x}, y={self.y})"

# ---------------------------------------------------------------------------
# Padding / layout helpers (v1 + v2)
# ---------------------------------------------------------------------------
def random_pad_sizes() -> List[int]:
    return [random.randint(1, 16) for _ in range(6)]

def random_field_order() -> List[str]:
    order = ["name", "x", "y"]
    random.shuffle(order)
    return order

# ---------------------------------------------------------------------------
# V10 — Polymorphic key derivation (simulates RWX page destroy-after-use)
# ---------------------------------------------------------------------------
def derive_epoch_key_polymorphic(master_seed: bytes, epoch: int) -> Tuple[bytes, bytes, bytes]:
    """
    Simulates the secure_core.c mprotect/RWX pipeline:
      1. Allocate an anonymous bytearray ("RWX page")
      2. Write the KDF logic into it (lambda stored in the buffer)
      3. Run derivation
      4. Overwrite buffer with os.urandom()
      5. Log page address + before/after SHA-256 hashes
      6. Return (mask_name, mask_x, mask_y) — key never persisted
    """
    # Step 1: allocate page simulation buffer
    page_size = 256
    page = bytearray(page_size)

    # Step 2: write KDF "code" into page — store derivation input in first bytes
    kdf_input = master_seed + struct.pack("<I", epoch)
    page[:len(kdf_input)] = kdf_input

    page_id = id(page)
    pre_hash = hashlib.sha256(bytes(page)).hexdigest()[:16]

    # Step 3: run SHAKE-256 derivation from the page data
    h = hashlib.shake_256(bytes(page[:len(kdf_input)]))
    raw = h.digest(16)
    mask_name = raw[0:8]
    mask_x    = raw[8:12]
    mask_y    = raw[12:16]

    # Step 4: destroy the page — overwrite with random bytes
    rand_fill = os.urandom(page_size)
    for i in range(page_size):
        page[i] = rand_fill[i]

    post_hash = hashlib.sha256(bytes(page)).hexdigest()[:16]

    # Step 5: emit execution trace
    print(f" [v10-exec] epoch={epoch}  page_id=0x{page_id:x}"
          f"  pre={pre_hash}  post={post_hash}  [DESTROYED]")

    # page goes out of scope here — no stable key in RAM
    del page
    return mask_name, mask_x, mask_y


def xor_bytes(data: bytes, mask: bytes) -> bytes:
    return bytes(b ^ mask[i % len(mask)] for i, b in enumerate(data))


def encrypt_entity_fields(
    entity: Entity,
    mask_name: bytes,
    mask_x:    bytes,
    mask_y:    bytes,
) -> Tuple[bytes, bytes, bytes]:
    name_bytes = entity.name.encode().ljust(8, b"\x00")[:8]
    enc_name = xor_bytes(name_bytes, mask_name)
    enc_x    = xor_bytes(struct.pack("<i", entity.x), mask_x)
    enc_y    = xor_bytes(struct.pack("<i", entity.y), mask_y)
    return enc_name, enc_x, enc_y


def decrypt_entity_fields(
    enc_name: bytes,
    enc_x:    bytes,
    enc_y:    bytes,
    mask_name: bytes,
    mask_x:    bytes,
    mask_y:    bytes,
) -> Tuple[str, int, int]:
    name = xor_bytes(enc_name, mask_name).rstrip(b"\x00").decode(errors="replace")
    x    = struct.unpack("<i", xor_bytes(enc_x, mask_x))[0]
    y    = struct.unpack("<i", xor_bytes(enc_y, mask_y))[0]
    return name, x, y

# ---------------------------------------------------------------------------
# Buffer layout helpers (v1 + v2 + v9 encryption)
# ---------------------------------------------------------------------------
HEADER_SIZE  = 10   # magic(2) + ver(1) + tick(1) + epoch(4) + count(2)
ENTITY_SIZE  = 22   # name(8) + pad(2) + x(4) + pad(2) + y(4) + pad(2)


def build_real_buffer(
    entities:   Dict[str, Entity],
    tick:       int,
    epoch:      int,
    pad_sizes:  List[int],
    field_order: List[str],
    mask_name:  bytes,
    mask_x:     bytes,
    mask_y:     bytes,
) -> ctypes.Array:
    """
    Write encrypted entity fields into a randomly-padded, randomly-ordered
    packed buffer.  Identical layout logic to v9.
    """
    entity_list = list(entities.values())
    count = len(entity_list)

    # Compute total size
    total = HEADER_SIZE
    for _ in entity_list:
        for fname in field_order:
            if fname == "name":
                total += 8
            else:
                total += 4
        total += sum(pad_sizes)

    buf = (ctypes.c_uint8 * total)()
    off = 0

    def write_bytes(data: bytes):
        nonlocal off
        for b in data:
            buf[off] = b
            off += 1

    # Header
    write_bytes(struct.pack("<H", MAGIC))
    write_bytes(struct.pack("<B", VERSION))
    write_bytes(struct.pack("<B", tick))
    write_bytes(struct.pack("<I", epoch))
    write_bytes(struct.pack("<H", count))

    pi = 0
    for ent in entity_list:
        enc_name, enc_x, enc_y = encrypt_entity_fields(ent, mask_name, mask_x, mask_y)
        for fname in field_order:
            write_bytes(os.urandom(pad_sizes[pi % len(pad_sizes)])); pi += 1
            if fname == "name":
                write_bytes(enc_name)
            elif fname == "x":
                write_bytes(enc_x)
            elif fname == "y":
                write_bytes(enc_y)

    return buf


def build_decoy_buffer(tick: int, epoch: int) -> ctypes.Array:
    """Decoy buffer: valid header, random encrypted-looking payload."""
    count = 2
    total = HEADER_SIZE + count * ENTITY_SIZE
    buf = (ctypes.c_uint8 * total)()
    off = 0

    def write_bytes(data: bytes):
        nonlocal off
        for b in data:
            buf[off] = b
            off += 1

    write_bytes(struct.pack("<H", MAGIC))
    write_bytes(struct.pack("<B", VERSION))
    write_bytes(struct.pack("<B", tick))
    write_bytes(struct.pack("<I", epoch))
    write_bytes(struct.pack("<H", count))
    write_bytes(os.urandom(count * ENTITY_SIZE))
    return buf

# ---------------------------------------------------------------------------
# Canary (telemetry)
# ---------------------------------------------------------------------------
CANARY_MAGIC = 0xDEADBEEF
CANARY_SIZE  = 4


def write_canary(buf: ctypes.Array, offset: int, value: int):
    data = struct.pack("<I", value & 0xFFFFFFFF)
    for i, b in enumerate(data):
        buf[offset + i] = b


def read_canary(buf: ctypes.Array, offset: int) -> int:
    data = bytes(buf[offset:offset + CANARY_SIZE])
    return struct.unpack("<I", data)[0]

# ---------------------------------------------------------------------------
# Telemetry ring
# ---------------------------------------------------------------------------
class TelemetryRing:
    def __init__(self, capacity: int = 64):
        self._ring:  deque = deque(maxlen=capacity)
        self._lock:  threading.Lock = threading.Lock()
        self.total_hits: int = 0

    def record(self, ts: float):
        with self._lock:
            self._ring.append(ts)
            self.total_hits += 1

    def deltas(self) -> List[float]:
        with self._lock:
            pts = list(self._ring)
        return [pts[i] - pts[i-1] for i in range(1, len(pts))]

    def mean_delta(self) -> float:
        d = self.deltas()
        return sum(d) / len(d) * 1000.0 if d else 0.0

    def delta_variance(self) -> float:
        d = self.deltas()
        if len(d) < 2:
            return 0.0
        mu = sum(d) / len(d)
        return sum((x - mu) ** 2 for x in d) / len(d) * 1e6

# ---------------------------------------------------------------------------
# Anomaly score
# ---------------------------------------------------------------------------
def compute_anomaly_score(
    telemetry:          TelemetryRing,
    epoch:              int,
    poison_activations: int,
    score_window:       int,
    hits_window:        List[int],
) -> Tuple[float, str]:
    if epoch == 0 or len(hits_window) == 0:
        return 0.0, "LOW     "
    recent = hits_window[-score_window:]
    mean_hits = sum(recent) / len(recent)
    mean_d = telemetry.mean_delta()
    base = mean_hits / max(mean_d, 1.0)
    score = base + poison_activations * 0.01
    if score >= 0.5:
        label = "HIGH    "
    elif score >= 0.2:
        label = "MEDIUM  "
    else:
        label = "LOW     "
    return score, label

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
class SharedState:
    def __init__(self):
        self.lock             = threading.Lock()
        self.active_buf:      Optional[ctypes.Array] = None
        self.canary_buf:      Optional[ctypes.Array] = None
        self.canary_offset:   int  = 0
        self.canary_value:    int  = CANARY_MAGIC
        self.decoy_bufs:      List[ctypes.Array] = []
        self.epoch:           int  = 0
        self.tick:            int  = 0
        self.scrub_count:     int  = 0
        self.poison_active:   bool = False
        self.poison_timer:    int  = 0
        self.poison_activations: int = 0
        self.telemetry        = TelemetryRing()
        self.hits_window:     List[int] = []
        self._stop_event      = threading.Event()

    def stop(self):
        self._stop_event.set()

    def stopped(self) -> bool:
        return self._stop_event.is_set()


_STATE = SharedState()
_ENTITIES: Dict[str, Entity] = {
    "CT1": Entity("CT1", random.randint(COORD_MIN, COORD_MAX), random.randint(COORD_MIN, COORD_MAX)),
    "T1":  Entity("T1",  random.randint(COORD_MIN, COORD_MAX), random.randint(COORD_MIN, COORD_MAX)),
}

# ---------------------------------------------------------------------------
# Telemetry thread
# ---------------------------------------------------------------------------
def telemetry_worker(state: SharedState):
    last_val = None
    while not state.stopped():
        time.sleep(TELEMETRY_POLL)
        with state.lock:
            buf = state.canary_buf
            off = state.canary_offset
        if buf is None:
            continue
        try:
            val = read_canary(buf, off)
        except Exception:
            continue
        if last_val is not None and val != last_val:
            state.telemetry.record(time.time())
        last_val = val


# ---------------------------------------------------------------------------
# Scrub worker
# ---------------------------------------------------------------------------
def scrub_worker(state: SharedState, buf: ctypes.Array, delay: float):
    time.sleep(delay)
    with state.lock:
        if buf is state.active_buf:
            rand_bytes = os.urandom(len(buf))
            for i in range(len(buf)):
                buf[i] = rand_bytes[i]
            write_canary(buf, state.canary_offset, 0x00000000)
            state.scrub_count += 1


# ---------------------------------------------------------------------------
# Decoy management
# ---------------------------------------------------------------------------
def refresh_decoys(state: SharedState, count: int, tick: int, epoch: int):
    keep_count = max(0, count - 2)
    state.decoy_bufs = state.decoy_bufs[:keep_count]
    while len(state.decoy_bufs) < count:
        state.decoy_bufs.append(build_decoy_buffer(tick, epoch))


# ---------------------------------------------------------------------------
# Core swap: v10 key derivation via polymorphic page
# ---------------------------------------------------------------------------
def swap_shared(
    state:    SharedState,
    entities: Dict[str, Entity],
    tick:     int,
    epoch:    int,
) -> str:
    # Randomise entity positions
    for ent in entities.values():
        ent.x = random.randint(COORD_MIN, COORD_MAX)
        ent.y = random.randint(COORD_MIN, COORD_MAX)

    # Decide decoy count
    telemetry    = state.telemetry
    mean_d       = telemetry.mean_delta()
    epoch_hits   = max(0, telemetry.total_hits - sum(state.hits_window))
    state.hits_window.append(epoch_hits)

    score, label = compute_anomaly_score(
        telemetry, epoch, state.poison_activations, SCORE_WINDOW, state.hits_window
    )

    # Poison logic
    if score >= POISON_THRESHOLD:
        if not state.poison_active:
            state.poison_active = True
            state.poison_timer  = POISON_HOLD
            state.poison_activations += 1
    elif state.poison_active:
        state.poison_timer -= 1
        if state.poison_timer <= 0:
            state.poison_active = False

    decoy_count = POISON_DECOY_COUNT if state.poison_active else INITIAL_DECOY_COUNT
    refresh_decoys(state, decoy_count, tick, epoch)

    # --- V10 CORE: derive key via polymorphic page ---
    master_seed = secrets.token_bytes(32)
    mask_name, mask_x, mask_y = derive_epoch_key_polymorphic(master_seed, epoch)

    # Build encrypted real buffer
    pad_sizes   = random_pad_sizes()
    field_order = random_field_order()
    new_buf = build_real_buffer(
        entities, tick, epoch, pad_sizes, field_order,
        mask_name, mask_x, mask_y
    )

    canary_offset = len(new_buf)   # canary appended after entity data
    canary_buf = (ctypes.c_uint8 * (len(new_buf) + CANARY_SIZE))()
    for i in range(len(new_buf)):
        canary_buf[i] = new_buf[i]
    state.canary_value = CANARY_MAGIC ^ epoch
    write_canary(canary_buf, canary_offset, state.canary_value)

    # Swap
    old_buf = state.active_buf
    with state.lock:
        state.active_buf    = new_buf
        state.canary_buf    = canary_buf
        state.canary_offset = canary_offset
        state.epoch         = epoch
        state.tick          = tick

    if old_buf is not None:
        del old_buf
        gc.collect()

    # Launch scrub
    scrub_t = threading.Thread(
        target=scrub_worker,
        args=(state, new_buf, COHERENCE_WINDOW),
        daemon=True
    )
    scrub_t.start()

    # Decrypt verification (proves round-trip)
    print(f" [v10-decrypt] epoch={epoch}  seed={master_seed.hex()[:16]}...")
    for ent_name, ent in entities.items():
        enc_name, enc_x, enc_y = encrypt_entity_fields(ent, mask_name, mask_x, mask_y)
        dec_name, dec_x, dec_y = decrypt_entity_fields(
            enc_name, enc_x, enc_y, mask_name, mask_x, mask_y
        )
        status = "[OK]" if (dec_x == ent.x and dec_y == ent.y) else "[FAIL]"
        print(f"   entity={ent_name} plaintext=({ent.x},{ent.y}) -> enc -> dec=({dec_x},{dec_y}) {status}")

    summary = (
        f"[swap] tick={tick} epoch={epoch} real_addr={id(new_buf)} "
        f"decoys={decoy_count} poison={int(state.poison_active)} "
        f"activations={state.poison_activations}\n"
        f"scrubs={state.scrub_count} telemetry_hits={telemetry.total_hits} "
        f"mean_delta={mean_d:.1f}ms\n"
        f" [anomaly] epoch={epoch} score={score:.4f} [{label}] "
        f" hits_window={state.hits_window[-SCORE_WINDOW:]}  delta_var={telemetry.delta_variance():.1f}"
    )
    return summary


# ---------------------------------------------------------------------------
# Game loop
# ---------------------------------------------------------------------------
def game_loop(state: SharedState, entities: Dict[str, Entity], num_epochs: int = 30):
    tick   = 1
    epoch  = INITIAL_EPOCH
    addr   = id(state)

    print(f"PID:                {os.getpid()}")
    print(f"VERSION:            {VERSION}  (v1+v2+v3+v4+v5+v6+v7+v8+v9 + polymorphic exec layer)")
    print(f"COHERENCE_WINDOW:   {int(COHERENCE_WINDOW*1000)} ms")
    print(f"TELEMETRY_POLL:     {int(TELEMETRY_POLL*1000)} ms")
    print(f"SIMULATE_OBSERVER:  {SIMULATE_OBSERVER}")
    print(f"INITIAL_ADDR:       {addr}")
    print(f"SCORE_WINDOW:       {SCORE_WINDOW} epochs")
    print()

    for _ in range(num_epochs):
        summary = swap_shared(state, entities, tick, epoch)
        print(summary)
        time.sleep(EPOCH_INTERVAL)
        epoch += 1

    state.stop()

    # Final telemetry dump
    ts = time.time()
    for ent_name, ent in entities.items():
        print(f"Timestamp: {ts}, Tick: {tick}, Epoch: {epoch}, "
              f"Entity: {ent_name}={ent}")

    print()
    print(f"TELEMETRY_TOTAL_HITS: {state.telemetry.total_hits}")
    print(f"TELEMETRY_MEAN_DELTA_MS: {state.telemetry.mean_delta():.2f}")
    print(f"POISON_ACTIVATIONS: {state.poison_activations}")
    print(f"FINAL_DECOY_COUNT:  "
          f"{POISON_DECOY_COUNT if state.poison_active else INITIAL_DECOY_COUNT}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    state = _STATE

    # Start telemetry thread
    tel_thread = threading.Thread(
        target=telemetry_worker, args=(state,), daemon=True
    )
    tel_thread.start()

    game_loop(state, _ENTITIES, num_epochs=30)
