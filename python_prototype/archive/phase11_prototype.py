#!/usr/bin/env python3
"""
phase11_prototype.py  —  v11: Secure IPC Bridge

Builds on v10 (polymorphic execution layer) and adds the Secure IPC Bridge
simulating secure_ipc.c from docs/AMITF_plan3_secure_userpsace_ipc_layer.md.

New in v11
----------
* SecureIPCArena
    - On Linux: allocates an anonymous file descriptor via memfd_create(2)
      (no filesystem path, invisible to directory scanners), then mmap()s it
      as a shared read/write arena.
    - Fallback (non-Linux / no memfd): uses a plain bytearray as the backing
      store so the prototype runs on any OS.
    - Arena layout:  [4-byte packet_id LE][N-byte payload]

* ipc_write_frame(arena, packet_id, plaintext, tpm_seed)
    - Derives a per-packet SHAKE-256 mask: SHAKE-256(tpm_seed || packet_id_LE)
      truncated to len(plaintext) bytes.
    - XOR-masks the plaintext and writes [packet_id || ciphertext] to the arena.
    - Delta-XOR attack defeated: XOR of two consecutive frames recovers
      SHAKE-256 key material, not coordinate/telemetry deltas.

* ipc_read_frame(arena, packet_id, tpm_seed)
    - Reads [packet_id || ciphertext] from the arena.
    - Re-derives the same per-packet mask and decrypts.
    - Returns the plaintext bytes.  Returns None on packet_id mismatch.

* Telemetry frames now flow through the IPC arena:
    - Each swap_shared() call encodes a telemetry record
      (epoch, tick, telemetry_hits, mean_delta_ms) as a fixed 16-byte struct
      and writes it through ipc_write_frame().
    - [v11-ipc] log line per epoch: packet_id, arena address, pre/post XOR
      sample (first 8 bytes of ciphertext hex) proving the frame is masked.
    - process_reader_v5.py (companion reader) attempts to intercept the IPC
      arena and decode frames without the tpm_seed — expected: all reads
      return garbage / frame-id mismatch.

* All v10 layers remain active:
    - polymorphic key derivation (RWX page destroy-after-use)
    - per-epoch SHAKE-256 XOR encryption of real entity fields
    - decoys, address hopping, coherence window scrubbing
    - adaptive poisoning, telemetry tracking, anomaly scoring

Expected outcome
----------------
* Game side: round-trip enc/dec [OK] every epoch (same as v9/v10).
* [v11-ipc] lines confirm per-packet mask is unique and non-zero.
* IPC frame read-back (same process, correct tpm_seed) — all [OK].
* Reader v5 (external, no tpm_seed): 0 valid frames decoded; all
  content tagged CONTENT:ipc_garbage.
* Telemetry stats consistent with v6–v10 baselines (~500 ms mean delta).

IPC frame format (16 bytes)
---------------------------
  offset 0  : uint32 LE  epoch
  offset 4  : uint32 LE  tick
  offset 8  : uint32 LE  total_telemetry_hits
  offset 12 : float32 LE mean_delta_ms
"""

import ctypes
import gc
import hashlib
import mmap
import os
import random
import secrets
import struct
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VERSION           = 11
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

# IPC arena constants
IPC_HEADER_SIZE  = 4          # packet_id (uint32 LE)
IPC_PAYLOAD_SIZE = 16         # telemetry frame (see docstring)
IPC_FRAME_SIZE   = IPC_HEADER_SIZE + IPC_PAYLOAD_SIZE   # 20 bytes total

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
# V11 — Secure IPC Arena
# ---------------------------------------------------------------------------
class SecureIPCArena:
    """
    Anonymous shared-memory arena for the telemetry IPC channel.

    On Linux with memfd_create available, allocates a true anonymous
    file-backed mapping with no filesystem path.  Falls back to a plain
    bytearray on other platforms.
    """

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
                # memfd_create(name, flags=MFD_CLOEXEC=1)
                fd = libc.memfd_create(b"amitf_ipc", 1)
                if fd >= 0:
                    os.ftruncate(fd, size)
                    self._map = mmap.mmap(fd, size, mmap.MAP_SHARED,
                                          mmap.PROT_READ | mmap.PROT_WRITE)
                    self._fd       = fd
                    self._use_mfd  = True
            except Exception:
                pass  # fall through to bytearray

        if not self._use_mfd:
            self._buf = bytearray(size)

    @property
    def address(self) -> int:
        """Nominal address for logging (id of backing object)."""
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
# IPC frame encode / decode
# ---------------------------------------------------------------------------
def _ipc_derive_mask(tpm_seed: bytes, packet_id: int, length: int) -> bytes:
    """SHAKE-256(tpm_seed || packet_id_LE) truncated to `length` bytes."""
    h = hashlib.shake_256(tpm_seed + struct.pack("<I", packet_id))
    return h.digest(length)


def ipc_encode_frame(epoch: int, tick: int,
                     total_hits: int, mean_delta_ms: float) -> bytes:
    """Pack a 16-byte telemetry frame."""
    return struct.pack("<IIIf", epoch, tick, total_hits, mean_delta_ms)


def ipc_decode_frame(raw: bytes) -> Tuple[int, int, int, float]:
    """Unpack a 16-byte telemetry frame."""
    return struct.unpack("<IIIf", raw)


def ipc_write_frame(arena: SecureIPCArena, packet_id: int,
                    plaintext: bytes, tpm_seed: bytes,
                    offset: int = 0) -> bytes:
    """
    Mask plaintext with per-packet SHAKE-256 key and write
    [packet_id (4B) || ciphertext (N B)] to arena at `offset`.
    Returns the ciphertext for logging.
    """
    mask       = _ipc_derive_mask(tpm_seed, packet_id, len(plaintext))
    ciphertext = bytes(p ^ m for p, m in zip(plaintext, mask))
    frame      = struct.pack("<I", packet_id) + ciphertext
    arena.write(offset, frame)
    return ciphertext


def ipc_read_frame(arena: SecureIPCArena, expected_packet_id: int,
                   tpm_seed: bytes, payload_size: int = IPC_PAYLOAD_SIZE,
                   offset: int = 0) -> Optional[bytes]:
    """
    Read IPC_FRAME_SIZE bytes from arena at `offset`.
    Verify packet_id matches, derive the same mask, decrypt and return
    plaintext.  Returns None on packet_id mismatch.
    """
    raw        = arena.read(offset, IPC_HEADER_SIZE + payload_size)
    packet_id  = struct.unpack("<I", raw[:IPC_HEADER_SIZE])[0]
    if packet_id != expected_packet_id:
        return None
    ciphertext = raw[IPC_HEADER_SIZE:]
    mask       = _ipc_derive_mask(tpm_seed, packet_id, payload_size)
    return bytes(c ^ m for c, m in zip(ciphertext, mask))


# ---------------------------------------------------------------------------
# V10 — Polymorphic key derivation (unchanged)
# ---------------------------------------------------------------------------
def derive_epoch_key_polymorphic(master_seed: bytes,
                                  epoch: int) -> Tuple[bytes, bytes, bytes]:
    page_size = 256
    page      = bytearray(page_size)

    kdf_input          = master_seed + struct.pack("<I", epoch)
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


def xor_bytes(data: bytes, mask: bytes) -> bytes:
    return bytes(b ^ mask[i % len(mask)] for i, b in enumerate(data))


def encrypt_entity_fields(
    entity: Entity,
    mask_name: bytes, mask_x: bytes, mask_y: bytes,
) -> Tuple[bytes, bytes, bytes]:
    name_bytes = entity.name.encode().ljust(8, b"\x00")[:8]
    return (
        xor_bytes(name_bytes, mask_name),
        xor_bytes(struct.pack("<i", entity.x), mask_x),
        xor_bytes(struct.pack("<i", entity.y), mask_y),
    )


def decrypt_entity_fields(
    enc_name: bytes, enc_x: bytes, enc_y: bytes,
    mask_name: bytes, mask_x: bytes, mask_y: bytes,
) -> Tuple[str, int, int]:
    name = xor_bytes(enc_name, mask_name).rstrip(b"\x00").decode(errors="replace")
    x    = struct.unpack("<i", xor_bytes(enc_x, mask_x))[0]
    y    = struct.unpack("<i", xor_bytes(enc_y, mask_y))[0]
    return name, x, y


# ---------------------------------------------------------------------------
# Buffer construction
# ---------------------------------------------------------------------------
HEADER_SIZE = 10
ENTITY_SIZE = 22


def build_real_buffer(
    entities: Dict[str, Entity],
    tick: int, epoch: int,
    pad_sizes: List[int], field_order: List[str],
    mask_name: bytes, mask_x: bytes, mask_y: bytes,
) -> ctypes.Array:
    entity_list = list(entities.values())
    count = len(entity_list)

    total = HEADER_SIZE
    for _ in entity_list:
        for fname in field_order:
            total += 8 if fname == "name" else 4
        total += sum(pad_sizes)

    buf = (ctypes.c_uint8 * total)()
    off = 0

    def wb(data: bytes):
        nonlocal off
        for b in data:
            buf[off] = b; off += 1

    wb(struct.pack("<H", MAGIC))
    wb(struct.pack("<B", VERSION))
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


def build_decoy_buffer(tick: int, epoch: int) -> ctypes.Array:
    count = 2
    total = HEADER_SIZE + count * ENTITY_SIZE
    buf   = (ctypes.c_uint8 * total)()
    off   = 0

    def wb(data: bytes):
        nonlocal off
        for b in data:
            buf[off] = b; off += 1

    wb(struct.pack("<H", MAGIC))
    wb(struct.pack("<B", VERSION))
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


def write_canary(buf: ctypes.Array, offset: int, value: int):
    data = struct.pack("<I", value & 0xFFFFFFFF)
    for i, b in enumerate(data):
        buf[offset + i] = b


def read_canary(buf: ctypes.Array, offset: int) -> int:
    return struct.unpack("<I", bytes(buf[offset:offset + CANARY_SIZE]))[0]


# ---------------------------------------------------------------------------
# Telemetry ring
# ---------------------------------------------------------------------------
class TelemetryRing:
    def __init__(self, capacity: int = 64):
        self._ring  = deque(maxlen=capacity)
        self._lock  = threading.Lock()
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
    telemetry: TelemetryRing,
    epoch: int, poison_activations: int,
    score_window: int, hits_window: List[int],
) -> Tuple[float, str]:
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
        self.active_buf:         Optional[ctypes.Array] = None
        self.canary_buf:         Optional[ctypes.Array] = None
        self.canary_offset:      int  = 0
        self.canary_value:       int  = CANARY_MAGIC
        self.decoy_bufs:         List[ctypes.Array] = []
        self.epoch:              int  = 0
        self.tick:               int  = 0
        self.scrub_count:        int  = 0
        self.poison_active:      bool = False
        self.poison_timer:       int  = 0
        self.poison_activations: int  = 0
        self.telemetry           = TelemetryRing()
        self.hits_window:        List[int] = []
        self._stop_event         = threading.Event()
        # V11: IPC arena and master TPM seed (shared within this process only)
        self.ipc_arena:          Optional[SecureIPCArena] = None
        self.ipc_tpm_seed:       bytes = secrets.token_bytes(32)
        self.ipc_packet_id:      int   = 0

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
def scrub_worker(state: SharedState, canary_buf: ctypes.Array,
                 canary_offset: int, delay: float):
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
def refresh_decoys(state: SharedState, count: int, tick: int, epoch: int):
    keep = max(0, count - 2)
    state.decoy_bufs = state.decoy_bufs[:keep]
    while len(state.decoy_bufs) < count:
        state.decoy_bufs.append(build_decoy_buffer(tick, epoch))


# ---------------------------------------------------------------------------
# Core swap  (v11: adds IPC telemetry frame write)
# ---------------------------------------------------------------------------
def swap_shared(
    state: SharedState,
    entities: Dict[str, Entity],
    tick: int, epoch: int,
) -> str:
    for ent in entities.values():
        ent.x = random.randint(COORD_MIN, COORD_MAX)
        ent.y = random.randint(COORD_MIN, COORD_MAX)

    telemetry  = state.telemetry
    mean_d     = telemetry.mean_delta()
    epoch_hits = max(0, telemetry.total_hits - sum(state.hits_window))
    state.hits_window.append(epoch_hits)

    score, label = compute_anomaly_score(
        telemetry, epoch, state.poison_activations,
        SCORE_WINDOW, state.hits_window
    )

    if score >= POISON_THRESHOLD:
        if not state.poison_active:
            state.poison_active      = True
            state.poison_timer       = POISON_HOLD
            state.poison_activations += 1
    elif state.poison_active:
        state.poison_timer -= 1
        if state.poison_timer <= 0:
            state.poison_active = False

    decoy_count = POISON_DECOY_COUNT if state.poison_active else INITIAL_DECOY_COUNT
    refresh_decoys(state, decoy_count, tick, epoch)

    # V10: polymorphic key derivation
    master_seed = secrets.token_bytes(32)
    mask_name, mask_x, mask_y = derive_epoch_key_polymorphic(master_seed, epoch)

    pad_sizes   = random_pad_sizes()
    field_order = random_field_order()
    new_buf = build_real_buffer(
        entities, tick, epoch, pad_sizes, field_order,
        mask_name, mask_x, mask_y
    )

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

    # ----------------------------------------------------------------
    # V11: write telemetry frame to IPC arena
    # ----------------------------------------------------------------
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
        # Read back and verify
        recovered = ipc_read_frame(
            state.ipc_arena, pkt_id,
            state.ipc_tpm_seed,
            offset=(pkt_id % 64) * IPC_FRAME_SIZE
        )
        status = "[OK]" if recovered == plaintext else "[FAIL]"
        ipc_log = (
            f" [v11-ipc] epoch={epoch}  pkt_id={pkt_id}"
            f"  arena=0x{state.ipc_arena.address:x}"
            f"  enc[:8]={ciphertext[:8].hex()}"
            f"  plain[:8]={plaintext[:8].hex()}"
            f"  readback={status}"
        )
        state.ipc_packet_id += 1

    # Round-trip entity verification
    print(f" [v10-exec already logged above]")
    print(f" [v11-decrypt] epoch={epoch}  seed={master_seed.hex()[:16]}...")
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
# Game loop
# ---------------------------------------------------------------------------
def game_loop(state: SharedState,
              entities: Dict[str, Entity],
              num_epochs: int = 30):
    tick  = 1
    epoch = INITIAL_EPOCH
    addr  = id(state)

    # Initialise IPC arena
    state.ipc_arena = SecureIPCArena(size=IPC_FRAME_SIZE * 64)
    backend = "memfd" if state.ipc_arena._use_mfd else "bytearray"

    print(f"PID:                {os.getpid()}")
    print(f"VERSION:            {VERSION}  "
          f"(v1+v2+v3+v4+v5+v6+v7+v8+v9+v10 + secure IPC bridge)")
    print(f"COHERENCE_WINDOW:   {int(COHERENCE_WINDOW*1000)} ms")
    print(f"TELEMETRY_POLL:     {int(TELEMETRY_POLL*1000)} ms")
    print(f"SIMULATE_OBSERVER:  {SIMULATE_OBSERVER}")
    print(f"INITIAL_ADDR:       {addr}")
    print(f"SCORE_WINDOW:       {SCORE_WINDOW} epochs")
    print(f"IPC_BACKEND:        {backend}"
          f"  arena_addr=0x{state.ipc_arena.address:x}"
          f"  frame_size={IPC_FRAME_SIZE}B  slots=64")
    print()

    for _ in range(num_epochs):
        print(swap_shared(state, entities, tick, epoch))
        time.sleep(EPOCH_INTERVAL)
        epoch += 1

    state.stop()
    state.ipc_arena.close()

    ts = time.time()
    for ent_name, ent in entities.items():
        print(f"Timestamp: {ts}, Tick: {tick}, Epoch: {epoch}, "
              f"Entity: {ent_name}={ent}")

    print()
    print(f"TELEMETRY_TOTAL_HITS:    {state.telemetry.total_hits}")
    print(f"TELEMETRY_MEAN_DELTA_MS: {state.telemetry.mean_delta():.2f}")
    print(f"POISON_ACTIVATIONS:      {state.poison_activations}")
    print(f"IPC_PACKETS_SENT:        {state.ipc_packet_id}")
    print(f"FINAL_DECOY_COUNT:       "
          f"{POISON_DECOY_COUNT if state.poison_active else INITIAL_DECOY_COUNT}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    state = _STATE
    threading.Thread(
        target=telemetry_worker, args=(state,), daemon=True).start()
    game_loop(state, _ENTITIES, num_epochs=30)
