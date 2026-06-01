#!/usr/bin/env python3
"""
phase1_prototype.py  —  Phase 1: Reactive Observer Hunter Integration

Builds directly on the v12 full-integration stack and adds the
Phase 1 ObserverHunter daemon thread from phase1_tracker.py.

What is new in Phase 1
----------------------
* ObserverHunter thread spawned at startup — IDLE by default.
* swap_shared() calls hunter.notify_score(score, epoch) each epoch.
  The hunter wakes when anomaly score >= MEDIUM (>= 0.20).
* While active, the hunter scans /proc/*/fd every 2.3 s for open
  file descriptors pointing to /proc/<our_pid>/mem (the primary
  signal of an external reader process).
* For each suspect PID the hunter builds an attribution dossier:
    pid, exe, cmdline, uid, gid, loginuid, environ_keys, session_type
  and emits it as a SHAKE-256 masked JSON packet into IPC arena slot 63.
* Full hunter summary appended to the end-of-run report.

All v1–v11 defensive layers remain fully active (identical to v12).

Expected behaviour
------------------
  No reader running     → hunter stays IDLE for the full run.
                          HUNTER_TRIGGER_COUNT = 0.
  Reader v5 started     → anomaly crosses MEDIUM at epoch 1;
  concurrently            hunter wakes, scans, finds /proc/<pid>/mem
                          handle held by the reader, emits dossier.
                          HUNTER_TRIGGER_COUNT = 1.
                          Dossier: exe=python, cmdline contains
                          process_reader_v5.py, loginuid = test user.
  Reader exits          → anomaly drops to LOW; hunter returns to IDLE
                          after HUNTER_IDLE_AFTER consecutive LOW epochs.
"""

import ctypes
import gc
import hashlib
import mmap
import os
import random
import secrets
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Phase 1 hunter
from phase1_tracker import ObserverHunter, HunterConfig

# ---------------------------------------------------------------------------
# Constants  (unchanged from v12)
# ---------------------------------------------------------------------------
VERSION           = "1.0"        # Phase 1
PHASE             = 1
MAGIC             = 0x1FA1
EPOCH_INTERVAL    = 1.0
COHERENCE_WINDOW  = 0.050
TELEMETRY_POLL    = 0.010
SCORE_WINDOW      = 6
SIMULATE_OBSERVER = int(os.environ.get("SIMULATE_OBSERVER", "0"))
INITIAL_EPOCH     = 0

POISON_THRESHOLD  = 0.15
POISON_HOLD       = 10

COORD_MIN, COORD_MAX = 0, 9

DECOY_NAMES         = ["BOT1", "BOT2", "CT2", "CT3", "GUARD", "SPEC1", "T2", "T3"]
INITIAL_DECOY_COUNT = 4
POISON_DECOY_COUNT  = 12

IPC_HEADER_SIZE  = 4
IPC_PAYLOAD_SIZE = 16
IPC_FRAME_SIZE   = IPC_HEADER_SIZE + IPC_PAYLOAD_SIZE   # 20 bytes

READER_SCRIPT    = os.path.join(os.path.dirname(__file__), "process_reader_v2.py")
READER_PASSES    = 3
READER_GAP_S     = 0.5


# ---------------------------------------------------------------------------
# Entity
# ---------------------------------------------------------------------------
@dataclass
class Entity:
    name: str
    x:    int
    y:    int
    def __repr__(self):
        return f"Entity(name={self.name}, x={self.x}, y={self.y})"


# ---------------------------------------------------------------------------
# Layout helpers (v1/v2)
# ---------------------------------------------------------------------------
def random_pad_sizes() -> List[int]:
    return [random.randint(1, 16) for _ in range(6)]

def random_field_order() -> List[str]:
    order = ["name", "x", "y"]
    random.shuffle(order)
    return order


# ---------------------------------------------------------------------------
# V11 — Secure IPC Arena  (unchanged from v12)
# ---------------------------------------------------------------------------
class SecureIPCArena:
    def __init__(self, size: int = IPC_FRAME_SIZE * 64):
        self._size    = size
        self._fd      = None
        self._map     = None
        self._buf     = None
        self._lock    = threading.Lock()
        self._use_mfd = False

        if sys.platform == "linux":
            try:
                import ctypes as _ct
                libc = _ct.CDLL("libc.so.6", use_errno=True)
                fd = libc.memfd_create(b"amitf_ipc", 1)
                if fd >= 0:
                    os.ftruncate(fd, size)
                    self._map = mmap.mmap(fd, size, mmap.MAP_SHARED,
                                          mmap.PROT_READ | mmap.PROT_WRITE)
                    self._fd      = fd
                    self._use_mfd = True
            except Exception:
                pass

        if not self._use_mfd:
            self._buf = bytearray(size)

    @property
    def address(self) -> int:
        return id(self._map if self._use_mfd else self._buf)

    def write(self, offset: int, data: bytes):
        with self._lock:
            if self._use_mfd:
                self._map.seek(offset)
                self._map.write(data)
            else:
                self._buf[offset:offset + len(data)] = data

    def read(self, offset: int, length: int) -> bytes:
        with self._lock:
            if self._use_mfd:
                self._map.seek(offset)
                return self._map.read(length)
            else:
                return bytes(self._buf[offset:offset + length])

    def close(self):
        if self._map is not None:
            self._map.close()
        if self._fd is not None:
            os.close(self._fd)


# ---------------------------------------------------------------------------
# IPC frame encode / decode  (unchanged from v12)
# ---------------------------------------------------------------------------
def _ipc_derive_mask(tpm_seed: bytes, packet_id: int, length: int) -> bytes:
    h = hashlib.shake_256(tpm_seed + struct.pack("<I", packet_id))
    return h.digest(length)

def ipc_encode_frame(epoch, tick, total_hits, mean_delta_ms):
    return struct.pack("<IIIf", epoch, tick, total_hits, mean_delta_ms)

def ipc_decode_frame(raw):
    return struct.unpack("<IIIf", raw)

def ipc_write_frame(arena, packet_id, plaintext, tpm_seed, offset=0):
    mask       = _ipc_derive_mask(tpm_seed, packet_id, len(plaintext))
    ciphertext = bytes(p ^ m for p, m in zip(plaintext, mask))
    frame      = struct.pack("<I", packet_id) + ciphertext
    arena.write(offset, frame)
    return ciphertext

def ipc_read_frame(arena, expected_packet_id, tpm_seed,
                   payload_size=IPC_PAYLOAD_SIZE, offset=0):
    raw        = arena.read(offset, IPC_HEADER_SIZE + payload_size)
    packet_id  = struct.unpack("<I", raw[:IPC_HEADER_SIZE])[0]
    if packet_id != expected_packet_id:
        return None
    ciphertext = raw[IPC_HEADER_SIZE:]
    mask       = _ipc_derive_mask(tpm_seed, packet_id, payload_size)
    return bytes(c ^ m for c, m in zip(ciphertext, mask))


# ---------------------------------------------------------------------------
# V10 — Polymorphic key derivation  (unchanged from v12)
# ---------------------------------------------------------------------------
def derive_epoch_key_polymorphic(master_seed, epoch):
    page_size = 256
    page      = bytearray(page_size)
    kdf_input = master_seed + struct.pack("<I", epoch)
    page[:len(kdf_input)] = kdf_input
    page_id   = id(page)
    pre_hash  = hashlib.sha256(bytes(page)).hexdigest()[:16]
    h         = hashlib.shake_256(bytes(page[:len(kdf_input)]))
    raw       = h.digest(16)
    mask_name = raw[0:8]
    mask_x    = raw[8:12]
    mask_y    = raw[12:16]
    rand_fill = os.urandom(page_size)
    for i in range(page_size):
        page[i] = rand_fill[i]
    post_hash = hashlib.sha256(bytes(page)).hexdigest()[:16]
    print(f" [v10-exec] epoch={epoch}  page_id=0x{page_id:x}"
          f"  pre={pre_hash}  post={post_hash}  [DESTROYED]")
    del page
    return mask_name, mask_x, mask_y

def xor_bytes(data, mask):
    return bytes(b ^ mask[i % len(mask)] for i, b in enumerate(data))

def encrypt_entity_fields(entity, mask_name, mask_x, mask_y):
    name_bytes = entity.name.encode().ljust(8, b"\x00")[:8]
    return (
        xor_bytes(name_bytes, mask_name),
        xor_bytes(struct.pack("<i", entity.x), mask_x),
        xor_bytes(struct.pack("<i", entity.y), mask_y),
    )

def decrypt_entity_fields(enc_name, enc_x, enc_y, mask_name, mask_x, mask_y):
    name = xor_bytes(enc_name, mask_name).rstrip(b"\x00").decode(errors="replace")
    x    = struct.unpack("<i", xor_bytes(enc_x, mask_x))[0]
    y    = struct.unpack("<i", xor_bytes(enc_y, mask_y))[0]
    return name, x, y


# ---------------------------------------------------------------------------
# Buffer construction  (unchanged from v12)
# ---------------------------------------------------------------------------
HEADER_SIZE = 10
ENTITY_SIZE = 22

def build_real_buffer(entities, tick, epoch, pad_sizes, field_order,
                      mask_name, mask_x, mask_y):
    entity_list = list(entities.values())
    count = len(entity_list)
    total = HEADER_SIZE
    for _ in entity_list:
        for fname in field_order:
            total += 8 if fname == "name" else 4
        total += sum(pad_sizes)
    buf = (ctypes.c_uint8 * total)()
    off = 0
    def wb(data):
        nonlocal off
        for b in data: buf[off] = b; off += 1
    wb(struct.pack("<H", MAGIC))
    wb(struct.pack("<B", 12))          # keep VERSION=12 in binary header
    wb(struct.pack("<B", tick))
    wb(struct.pack("<I", epoch))
    wb(struct.pack("<H", count))
    pi = 0
    for ent in entity_list:
        enc_name, enc_x, enc_y = encrypt_entity_fields(
            ent, mask_name, mask_x, mask_y)
        for fname in field_order:
            wb(os.urandom(pad_sizes[pi % len(pad_sizes)])); pi += 1
            if fname == "name":  wb(enc_name)
            elif fname == "x":   wb(enc_x)
            elif fname == "y":   wb(enc_y)
    return buf

def build_decoy_buffer(tick, epoch):
    count = 2
    total = HEADER_SIZE + count * ENTITY_SIZE
    buf   = (ctypes.c_uint8 * total)()
    off   = 0
    def wb(data):
        nonlocal off
        for b in data: buf[off] = b; off += 1
    wb(struct.pack("<H", MAGIC))
    wb(struct.pack("<B", 12))
    wb(struct.pack("<B", tick))
    wb(struct.pack("<I", epoch))
    wb(struct.pack("<H", count))
    wb(os.urandom(count * ENTITY_SIZE))
    return buf


# ---------------------------------------------------------------------------
# Canary
# ---------------------------------------------------------------------------
CANARY_MAGIC = 0xDEADBEEF
CANARY_SIZE  = 4

def write_canary(buf, offset, value):
    data = struct.pack("<I", value & 0xFFFFFFFF)
    for i, b in enumerate(data): buf[offset + i] = b

def read_canary(buf, offset):
    return struct.unpack("<I", bytes(buf[offset:offset + CANARY_SIZE]))[0]


# ---------------------------------------------------------------------------
# Telemetry ring
# ---------------------------------------------------------------------------
class TelemetryRing:
    def __init__(self, capacity=64):
        self._ring  = deque(maxlen=capacity)
        self._lock  = threading.Lock()
        self.total_hits = 0

    def record(self, ts):
        with self._lock:
            self._ring.append(ts)
            self.total_hits += 1

    def deltas(self):
        with self._lock:
            pts = list(self._ring)
        return [pts[i] - pts[i-1] for i in range(1, len(pts))]

    def mean_delta(self):
        d = self.deltas()
        return sum(d) / len(d) * 1000.0 if d else 0.0

    def delta_variance(self):
        d = self.deltas()
        if len(d) < 2: return 0.0
        mu = sum(d) / len(d)
        return sum((x - mu)**2 for x in d) / len(d) * 1e6


# ---------------------------------------------------------------------------
# Anomaly score
# ---------------------------------------------------------------------------
def compute_anomaly_score(telemetry, epoch, poison_activations,
                           score_window, hits_window):
    if epoch == 0 or not hits_window:
        return 0.0, "LOW     "
    recent    = hits_window[-score_window:]
    mean_hits = sum(recent) / len(recent)
    mean_d    = telemetry.mean_delta()
    score     = mean_hits / max(mean_d, 1.0) + poison_activations * 0.01
    label = "HIGH    " if score >= 0.5 else ("MEDIUM  " if score >= 0.2 else "LOW     ")
    return score, label


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
class SharedState:
    def __init__(self):
        self.lock                = threading.Lock()
        self.active_buf          = None
        self.canary_buf          = None
        self.canary_offset       = 0
        self.canary_value        = CANARY_MAGIC
        self.decoy_bufs          = []
        self.epoch               = 0
        self.tick                = 0
        self.scrub_count         = 0
        self.poison_active       = False
        self.poison_timer        = 0
        self.poison_activations  = 0
        self.telemetry           = TelemetryRing()
        self.hits_window         = []
        self._stop_event         = threading.Event()
        self.ipc_arena           = None
        self.ipc_tpm_seed        = secrets.token_bytes(32)
        self.ipc_packet_id       = 0
        # Phase 1
        self.hunter: Optional[ObserverHunter] = None

    def stop(self):    self._stop_event.set()
    def stopped(self): return self._stop_event.is_set()


_STATE = SharedState()
_ENTITIES: Dict[str, Entity] = {
    "CT1": Entity("CT1",
                  random.randint(COORD_MIN, COORD_MAX),
                  random.randint(COORD_MIN, COORD_MAX)),
    "T1":  Entity("T1",
                  random.randint(COORD_MIN, COORD_MAX),
                  random.randint(COORD_MIN, COORD_MAX)),
}


# ---------------------------------------------------------------------------
# Telemetry thread
# ---------------------------------------------------------------------------
def telemetry_worker(state):
    last_val = None
    while not state.stopped():
        time.sleep(TELEMETRY_POLL)
        with state.lock:
            buf = state.canary_buf
            off = state.canary_offset
        if buf is None: continue
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
def scrub_worker(state, canary_buf, canary_offset, delay):
    time.sleep(delay)
    with state.lock:
        if canary_buf is state.canary_buf:
            rand_bytes = os.urandom(len(canary_buf))
            for i in range(len(canary_buf)):
                canary_buf[i] = rand_bytes[i]
            write_canary(canary_buf, canary_offset, 0x00000000)
            state.scrub_count += 1


# ---------------------------------------------------------------------------
# Decoy management
# ---------------------------------------------------------------------------
def refresh_decoys(state, count, tick, epoch):
    keep = max(0, count - 2)
    state.decoy_bufs = state.decoy_bufs[:keep]
    while len(state.decoy_bufs) < count:
        state.decoy_bufs.append(build_decoy_buffer(tick, epoch))


# ---------------------------------------------------------------------------
# Core swap  (v1–v11 layers + Phase 1 hunter notification)
# ---------------------------------------------------------------------------
def swap_shared(state, entities, tick, epoch):
    # V4 relocation
    for ent in entities.values():
        ent.x = random.randint(COORD_MIN, COORD_MAX)
        ent.y = random.randint(COORD_MIN, COORD_MAX)

    # V6/V7/V8 telemetry + anomaly
    telemetry  = state.telemetry
    mean_d     = telemetry.mean_delta()
    epoch_hits = max(0, telemetry.total_hits - sum(state.hits_window))
    state.hits_window.append(epoch_hits)

    score, label = compute_anomaly_score(
        telemetry, epoch, state.poison_activations,
        SCORE_WINDOW, state.hits_window
    )

    # Phase 1 — notify hunter of current score
    if state.hunter is not None:
        state.hunter.notify_score(score, epoch)

    if score >= POISON_THRESHOLD:
        if not state.poison_active:
            state.poison_active      = True
            state.poison_timer       = POISON_HOLD
            state.poison_activations += 1
    elif state.poison_active:
        state.poison_timer -= 1
        if state.poison_timer <= 0:
            state.poison_active = False

    # V3 decoys
    decoy_count = POISON_DECOY_COUNT if state.poison_active else INITIAL_DECOY_COUNT
    refresh_decoys(state, decoy_count, tick, epoch)

    # V10 polymorphic key derivation
    master_seed = secrets.token_bytes(32)
    mask_name, mask_x, mask_y = derive_epoch_key_polymorphic(master_seed, epoch)

    # V1/V2 fragmented layout
    pad_sizes   = random_pad_sizes()
    field_order = random_field_order()

    # V9 encrypted buffer
    new_buf = build_real_buffer(
        entities, tick, epoch, pad_sizes, field_order,
        mask_name, mask_x, mask_y
    )

    # V5 canary + coherence-window scrub
    canary_offset = len(new_buf)
    canary_buf    = (ctypes.c_uint8 * (canary_offset + CANARY_SIZE))()
    for i in range(canary_offset):
        canary_buf[i] = new_buf[i]
    state.canary_value = CANARY_MAGIC ^ epoch
    write_canary(canary_buf, canary_offset, state.canary_value)

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

    threading.Thread(
        target=scrub_worker,
        args=(state, canary_buf, canary_offset, COHERENCE_WINDOW),
        daemon=True,
    ).start()

    # V11 IPC telemetry frame
    ipc_log = ""
    if state.ipc_arena is not None:
        pkt_id    = state.ipc_packet_id
        plaintext = ipc_encode_frame(epoch, tick,
                                     telemetry.total_hits, mean_d)
        ciphertext = ipc_write_frame(
            state.ipc_arena, pkt_id, plaintext,
            state.ipc_tpm_seed,
            offset=(pkt_id % 64) * IPC_FRAME_SIZE
        )
        recovered = ipc_read_frame(
            state.ipc_arena, pkt_id,
            state.ipc_tpm_seed,
            offset=(pkt_id % 64) * IPC_FRAME_SIZE
        )
        status  = "[OK]" if recovered == plaintext else "[FAIL]"
        ipc_log = (
            f" [v11-ipc] epoch={epoch}  pkt_id={pkt_id}"
            f"  arena=0x{state.ipc_arena.address:x}"
            f"  enc[:8]={ciphertext[:8].hex()}"
            f"  plain[:8]={plaintext[:8].hex()}"
            f"  readback={status}"
        )
        state.ipc_packet_id += 1

    # V9/V10 round-trip verification
    print(f" [v10-exec already logged above]")
    print(f" [v12-decrypt] epoch={epoch}  seed={master_seed.hex()[:16]}...")
    for ent_name, ent in entities.items():
        en, ex, ey = encrypt_entity_fields(ent, mask_name, mask_x, mask_y)
        dn, dx, dy = decrypt_entity_fields(
            en, ex, ey, mask_name, mask_x, mask_y)
        ok = "[OK]" if (dx == ent.x and dy == ent.y) else "[FAIL]"
        print(f"   entity={ent_name} plaintext=({ent.x},{ent.y})"
              f" -> enc -> dec=({dx},{dy}) {ok}")

    if ipc_log:
        print(ipc_log)

    return (
        f"[swap] tick={tick} epoch={epoch} real_addr={id(new_buf)} "
        f"decoys={decoy_count} poison={int(state.poison_active)} "
        f"activations={state.poison_activations}\n"
        f"scrubs={state.scrub_count} telemetry_hits={telemetry.total_hits} "
        f"mean_delta={mean_d:.1f}ms\n"
        f" [anomaly] epoch={epoch} score={score:.4f} [{label}] "
        f" hits_window={state.hits_window[-SCORE_WINDOW:]}  "
        f"delta_var={telemetry.delta_variance():.1f}"
    )


# ---------------------------------------------------------------------------
# V12 integration check  (unchanged from v12)
# ---------------------------------------------------------------------------
def run_integration_check(pid):
    result = {
        "passes_completed": 0,
        "total_candidates": 0,
        "high_confidence":  0,
        "content_valid":    0,
        "precision_pct":    0.0,
        "raw_lines":        [],
        "error":            None,
    }
    if not os.path.isfile(READER_SCRIPT):
        result["error"] = f"reader script not found: {READER_SCRIPT}"
        return result
    for pass_num in range(1, READER_PASSES + 1):
        try:
            completed = subprocess.run(
                [sys.executable, READER_SCRIPT, str(pid)],
                capture_output=True, text=True, timeout=15
            )
            lines = completed.stdout.splitlines()
            result["raw_lines"].extend(
                [f"[reader-pass-{pass_num}] {ln}" for ln in lines])
            result["passes_completed"] += 1
            for ln in lines:
                ln_l = ln.lower()
                if "0x" in ln and ("score" in ln_l or "addr" in ln_l or "hit" in ln_l):
                    result["total_candidates"] += 1
                if "high" in ln_l and "score" in ln_l:
                    result["high_confidence"] += 1
                import re
                coord_hits = re.findall(r"(?:x|y)\s*=\s*(-?\d+)", ln_l)
                for v in coord_hits:
                    iv = int(v)
                    if COORD_MIN <= iv <= COORD_MAX:
                        result["content_valid"] += 1
        except subprocess.TimeoutExpired:
            result["raw_lines"].append(f"[reader-pass-{pass_num}] TIMEOUT")
        except Exception as exc:
            result["raw_lines"].append(f"[reader-pass-{pass_num}] ERROR: {exc}")
        if pass_num < READER_PASSES:
            time.sleep(READER_GAP_S)
    if result["high_confidence"] > 0:
        result["precision_pct"] = (
            result["content_valid"] / result["high_confidence"] * 100.0)
    return result


# ---------------------------------------------------------------------------
# Game loop
# ---------------------------------------------------------------------------
def game_loop(state, entities, num_epochs=300):
    tick  = 1
    epoch = INITIAL_EPOCH

    # V11 IPC arena
    state.ipc_arena = SecureIPCArena(size=IPC_FRAME_SIZE * 64)
    backend = "memfd" if state.ipc_arena._use_mfd else "bytearray"

    # Phase 1 — hunter (arena must exist before hunter is created)
    hunter_cfg   = HunterConfig()
    state.hunter = ObserverHunter(
        hunter_cfg, state.ipc_arena, state.ipc_tpm_seed)
    state.hunter.start()

    print("=" * 70)
    print(f"  AMITF — phase1_prototype.py   (Phase 1: Observer Hunter)")
    print("=" * 70)
    print(f"  PID:               {os.getpid()}")
    print(f"  VERSION:           {VERSION}")
    print(f"  Active layers:     v1 v2 v3 v4 v5 v6 v7 v8 v9 v10 v11 + Phase1-Hunter")
    print(f"  COHERENCE_WINDOW:  {int(COHERENCE_WINDOW*1000)} ms")
    print(f"  TELEMETRY_POLL:    {int(TELEMETRY_POLL*1000)} ms")
    print(f"  SIMULATE_OBSERVER: {SIMULATE_OBSERVER}")
    print(f"  SCORE_WINDOW:      {SCORE_WINDOW} epochs")
    print(f"  IPC_BACKEND:       {backend}"
          f"  arena_addr=0x{state.ipc_arena.address:x}"
          f"  frame_size={IPC_FRAME_SIZE}B  slots=64")
    print(f"  HUNTER_TRIGGER:    score >= {hunter_cfg.trigger_score:.2f} (MEDIUM)")
    print(f"  HUNTER_INTERVAL:   {hunter_cfg.hunter_interval}s")
    print(f"  HUNTER_IDLE_AFTER: {hunter_cfg.idle_after_epochs} LOW epochs")
    print(f"  HUNTER_IPC_SLOT:   {hunter_cfg.ipc_slot}")
    print(f"  NUM_EPOCHS:        {num_epochs}  (~{num_epochs}s run time)")
    print("=" * 70)
    print()

    for _ in range(num_epochs):
        print(swap_shared(state, entities, tick, epoch))
        time.sleep(EPOCH_INTERVAL)
        epoch += 1

    state.stop()
    state.hunter.stop()
    state.ipc_arena.close()

    ts = time.time()
    for ent_name, ent in entities.items():
        print(f"Timestamp: {ts}, Tick: {tick}, Epoch: {epoch}, "
              f"Entity: {ent_name}={ent}")

    print()
    print("=" * 70)
    print("  PHASE 1 FULL-STACK TELEMETRY SUMMARY")
    print("=" * 70)
    print(f"  TELEMETRY_TOTAL_HITS:    {state.telemetry.total_hits}")
    print(f"  TELEMETRY_MEAN_DELTA_MS: {state.telemetry.mean_delta():.2f}")
    print(f"  POISON_ACTIVATIONS:      {state.poison_activations}")
    print(f"  IPC_PACKETS_SENT:        {state.ipc_packet_id}")
    print(f"  SCRUB_COUNT:             {state.scrub_count}")
    print(f"  FINAL_DECOY_COUNT:       "
          f"{POISON_DECOY_COUNT if state.poison_active else INITIAL_DECOY_COUNT}")
    print()
    print("  PHASE 1 OBSERVER HUNTER SUMMARY")
    print(state.hunter.summary())

    # V12 integration check
    print()
    print("=" * 70)
    print("  INTEGRATION CHECK — reader_v2 residual precision")
    print("=" * 70)
    ic = run_integration_check(os.getpid())
    if ic["error"]:
        print(f"  [SKIPPED] {ic['error']}")
    else:
        for ln in ic["raw_lines"]:
            print(f"  {ln}")
        print()
        print(f"  Passes completed:   {ic['passes_completed']} / {READER_PASSES}")
        print(f"  Total candidates:   {ic['total_candidates']}")
        print(f"  HIGH-confidence:    {ic['high_confidence']}")
        print(f"  Content-valid:      {ic['content_valid']}")
        print(f"  Residual precision: {ic['precision_pct']:.1f} %")
        if ic["content_valid"] == 0:
            print("  [PASS] content_valid = 0 — full-stack precision = 0 %.")
        else:
            print(f"  [NOTE] {ic['content_valid']} content-valid coord(s) detected.")

    print("=" * 70)
    print("  Phase 1 prototype run COMPLETE")
    print("  Test: run process_reader_v5.py concurrently and observe hunter output")
    print("=" * 70)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    state = _STATE
    threading.Thread(
        target=telemetry_worker, args=(state,), daemon=True).start()
    game_loop(state, _ENTITIES, num_epochs=300)
