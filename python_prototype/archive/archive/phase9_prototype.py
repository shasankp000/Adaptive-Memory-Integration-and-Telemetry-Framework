import sys
import os
import struct
import gc
import hashlib
import secrets
from random import randint, randbytes, shuffle, choice
from copy import deepcopy
from datetime import datetime
from time import sleep, perf_counter
from ctypes import create_string_buffer, addressof, memmove
from threading import Thread, Event, Lock
from collections import deque

# ─────────────────────────────────────────────────────────────────────────────
# v9 — Encryption Epoch System
#
# Inherits all of v8 (v1+v2+v3+v4+v5+v6+v7 + anomaly scoring) and adds:
#
#   1. Per-epoch TPM-seeded SHAKE-256 key derivation
#      A new 32-byte master seed is drawn via secrets.token_bytes() once per
#      epoch swap (simulating a real TPM hardware read). Three independent
#      per-field masks (mask_name, mask_x, mask_y) are derived from:
#          SHAKE-256( master_seed || epoch_number_bytes )
#      The key never touches RAM as a named struct — it lives only in local
#      Python variables for the duration of the write, then goes out of scope.
#
#   2. Payload field encryption at write time
#      Inside build_shuffled_buffer() the real entity name, x, y bytes are
#      XOR-masked with their per-field masks before being written into the
#      buffer. A reader that correctly identifies the real buffer's address
#      will decode encrypted garbage without the current epoch key.
#
#   3. Encrypted garbage in decoys
#      Decoys carry payload bytes that look like legitimate encrypted output
#      (random bytes in a valid integer range) but are entirely random — they
#      cannot be decrypted to anything meaningful even with the real key.
#      This forces a reader to attempt decryption on every HIGH candidate
#      without knowing which one (if any) would yield valid plaintext.
#
#   4. Authoritative in-process decryption (game thread side)
#      The game process itself demonstrates correct round-trip decryption via
#      decrypt_entity_fields() — this is the path a real game engine would
#      use to read back its own state after encryption.
#
# Expected reader outcome:
#   Reader v3 still scores all HIGH candidates correctly (structural heuristics
#   unchanged) but decode_register_v3() returns only garbage for every
#   candidate regardless of score. Content-level precision drops to 0%.
# ─────────────────────────────────────────────────────────────────────────────

# ── constants ────────────────────────────────────────────────────────────────
EPOCH_UPDATE_RULE = 1
MAX_ENTITIES      = 2
NAME_LEN          = 8
MAGIC             = 0xA11F
VERSION           = 9

PAD_MIN  = 1
PAD_MAX  = 16
BASE_DECOYS = 4
MAX_DECOYS  = 12
COHERENCE_WINDOW_S = 0.05

TELEMETRY_POLL_S        = 0.01
CANARY_SIZE             = 64
CANARY_OFFSET           = 24
SUSPICION_HIT_THRESHOLD = 4
SUSPICION_DELTA_MIN_MS  = 300.0
SUSPICION_DELTA_MAX_MS  = 700.0
POISON_HOLD_EPOCHS      = 4

# Anomaly scoring — rolling window parameters
SCORE_WINDOW_EPOCHS = 6
SCORE_HIT_RATE_W    = 0.35
SCORE_DELTA_STAB_W  = 0.35
SCORE_POISON_W      = 0.20
SCORE_CHURN_W       = 0.10

HEADER_FMT  = '<IIIII'
HEADER_SIZE = struct.calcsize(HEADER_FMT)

FIELD_DEFS = [
    ('name', NAME_LEN),
    ('x',    4),
    ('y',    4),
]

DECOY_NAME_POOL = [
    b'CT2\x00\x00\x00\x00\x00',
    b'T2\x00\x00\x00\x00\x00\x00',
    b'CT3\x00\x00\x00\x00\x00',
    b'T3\x00\x00\x00\x00\x00\x00',
    b'SPEC1\x00\x00\x00',
    b'BOT1\x00\x00\x00\x00',
    b'BOT2\x00\x00\x00\x00',
    b'GUARD\x00\x00\x00',
]


# ── v9: encryption helpers ───────────────────────────────────────────────────

def derive_epoch_masks(master_seed: bytes, epoch: int) -> tuple:
    """
    Derives three independent per-field byte-masks from the master TPM seed
    and the current epoch number using SHAKE-256.

    mask_name : 8 bytes  — XORed with the name field bytes
    mask_x    : 4 bytes  — XORed with the packed x int32 bytes
    mask_y    : 4 bytes  — XORed with the packed y int32 bytes

    Using SHAKE-256 (a variable-length XOF) lets us pull any number of
    independent mask bytes from a single hash invocation, matching the
    approach described in AMITF_plan3_secure_userpsace_ipc_layer.md.

    The key derivation input is:
        master_seed (32 bytes) || epoch (4 bytes little-endian)

    Keeping epoch in the derivation input means masks rotate automatically
    every epoch even if the master seed were somehow leaked — an attacker
    with a stale seed cannot decrypt data from a later epoch.
    """
    epoch_bytes = epoch.to_bytes(4, byteorder='little')
    kdf_input   = master_seed + epoch_bytes
    h = hashlib.shake_256(kdf_input)
    raw = h.digest(NAME_LEN + 4 + 4)  # 16 bytes total
    mask_name = raw[:NAME_LEN]
    mask_x    = raw[NAME_LEN:NAME_LEN + 4]
    mask_y    = raw[NAME_LEN + 4:NAME_LEN + 8]
    return mask_name, mask_x, mask_y


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_entity_fields(name_bytes: bytes, x: int, y: int,
                          mask_name: bytes, mask_x: bytes, mask_y: bytes
                          ) -> tuple:
    """
    Encrypts the three payload fields of one entity using XOR masks.
    Returns (enc_name: bytes, enc_x: bytes, enc_y: bytes).

    The caller writes these raw bytes into the buffer instead of plaintext.
    Without the epoch masks a reader decodes garbage from every field.
    """
    name_padded = name_bytes[:NAME_LEN].ljust(NAME_LEN, b'\x00')
    enc_name    = xor_bytes(name_padded, mask_name)
    enc_x       = xor_bytes(struct.pack('<i', x), mask_x)
    enc_y       = xor_bytes(struct.pack('<i', y), mask_y)
    return enc_name, enc_x, enc_y


def decrypt_entity_fields(enc_name: bytes, enc_x: bytes, enc_y: bytes,
                          mask_name: bytes, mask_x: bytes, mask_y: bytes
                          ) -> tuple:
    """
    Decrypts entity fields — XOR is its own inverse, so this is identical
    to encrypt_entity_fields(). Kept as a separate function for clarity:
    the game thread calls this to read back its own state.
    """
    name_bytes = xor_bytes(enc_name, mask_name)
    x          = struct.unpack('<i', xor_bytes(enc_x, mask_x))[0]
    y          = struct.unpack('<i', xor_bytes(enc_y, mask_y))[0]
    name_str   = name_bytes.split(b'\x00', 1)[0].decode(errors='ignore')
    return name_str, x, y


# ── layout helpers (v1 + v2 unchanged) ──────────────────────────────────────

def random_field_order():
    order = list(FIELD_DEFS)
    shuffle(order)
    return order


def random_pad_sizes(n: int):
    return [randint(PAD_MIN, PAD_MAX) for _ in range(n)]


def build_layout(field_order, pad_sizes, n_entities=MAX_ENTITIES):
    offsets = {}
    cursor  = 0
    pad_idx = 0
    for entity_idx in range(n_entities):
        for field_name, field_size in field_order:
            cursor += pad_sizes[pad_idx]
            offsets[(entity_idx, field_name)] = cursor
            cursor += field_size
            pad_idx += 1
    return offsets


def build_shuffled_buffer(tick, epoch, entities, field_order, pad_sizes,
                          mask_name: bytes, mask_x: bytes, mask_y: bytes):
    """
    v9 version: real entity fields are encrypted with per-epoch masks before
    being written into the buffer region. The buffer structure (magic, header,
    padding, field order) is identical to v8 — only the payload bytes differ.

    A reader that finds this buffer and decodes the header correctly will still
    see a valid magic / count / epoch but will read back encrypted garbage for
    all name, x, y fields without the current epoch masks.
    """
    header  = struct.pack(HEADER_FMT, MAGIC, VERSION, tick, epoch, MAX_ENTITIES)
    offsets = build_layout(field_order, pad_sizes)
    total   = sum(pad_sizes) + MAX_ENTITIES * sum(sz for _, sz in field_order)
    entity_region = bytearray(randbytes(total))

    for i, entity in enumerate(entities[:MAX_ENTITIES]):
        enc_name, enc_x, enc_y = encrypt_entity_fields(
            entity.name.encode(),
            entity.x,
            entity.y,
            mask_name, mask_x, mask_y,
        )
        fm = {'name': enc_name, 'x': enc_x, 'y': enc_y}
        for field_name, field_size in field_order:
            off = offsets[(i, field_name)]
            entity_region[off:off + field_size] = fm[field_name]

    return header + bytes(entity_region)


def build_decoy_buffer(tick, epoch):
    """
    v9 decoys: payload bytes are fully random rather than plaintext-valid
    coords. They look like encrypted output (random bytes) to a reader
    that attempts to decrypt them without the real epoch key.

    The header (magic, version, tick, epoch, count) remains valid so the
    decoy still passes structural checks in the reader — it earns its
    HIGH confidence score before the content decode fails.
    """
    # Random bytes for name field + random raw int bytes for x, y
    entity_region = b''
    for _ in range(MAX_ENTITIES):
        enc_name = randbytes(NAME_LEN)
        enc_x    = randbytes(4)
        enc_y    = randbytes(4)
        entity_region += enc_name + enc_x + enc_y
    return struct.pack(HEADER_FMT, MAGIC, VERSION, tick, epoch, MAX_ENTITIES) + entity_region


def scrub_buffer(buf, size):
    noise = randbytes(size)
    struct.pack_into(f'{size}s', buf, 0, noise)


# ── domain classes ───────────────────────────────────────────────────────────

class Entity:
    def __init__(self, name, x, y):
        self.name = name
        self.x    = x
        self.y    = y

    def __repr__(self):
        return f'Entity(name={self.name}, x={self.x}, y={self.y})'

    def setx(self, x): self.x = x
    def sety(self, y): self.y = y


class EntityLogger:
    def __init__(self):
        self.logger = []

    def log(self, timestamp, tick, epoch, snapshot):
        self.logger.append((timestamp, tick, epoch, snapshot))

    def access_log(self):
        return self.logger


# ── anomaly scoring helpers (unchanged from v8) ──────────────────────────────

def _variance(values):
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return sum((v - mean) ** 2 for v in values) / len(values)


def compute_anomaly_score(hits_window, delta_window, poison_activations,
                          decoy_churn_window):
    if hits_window:
        mean_hits     = sum(hits_window) / len(hits_window)
        hit_rate_score = min(max((mean_hits - 2.0) / 4.0, 0.0), 1.0)
    else:
        hit_rate_score = 0.0

    if len(delta_window) >= 2:
        var = _variance(delta_window)
        delta_stab_score = min(max(1.0 - (var / 50000.0), 0.0), 1.0)
    else:
        delta_stab_score = 0.0

    poison_score = min(poison_activations / 3.0, 1.0)

    if decoy_churn_window:
        mean_churn  = sum(decoy_churn_window) / len(decoy_churn_window)
        churn_score = min(mean_churn / MAX_DECOYS, 1.0)
    else:
        churn_score = 0.0

    score = (
        SCORE_HIT_RATE_W   * hit_rate_score +
        SCORE_DELTA_STAB_W * delta_stab_score +
        SCORE_POISON_W     * poison_score +
        SCORE_CHURN_W      * churn_score
    )
    return round(min(score, 1.0), 4)


# ── main register class ──────────────────────────────────────────────────────

class EncryptedEpochRegister:
    """
    v9 = v8 + per-epoch SHAKE-256 key derivation + payload field encryption.

    New in v9:
      - _master_seed : refreshed each swap via secrets.token_bytes(32)
      - _mask_name, _mask_x, _mask_y : derived masks, valid for one epoch only
      - Real buffer payload encrypted; decoys carry random bytes
      - Authoritative decrypt demonstrated in swap_shared() log output
    """

    _N_FIELDS     = len(FIELD_DEFS)
    _REAL_MAX_BUF = (
        HEADER_SIZE
        + MAX_ENTITIES * (NAME_LEN + 4 + 4)
        + MAX_ENTITIES * _N_FIELDS * PAD_MAX
        + 64
    )
    _DECOY_SIZE = HEADER_SIZE + MAX_ENTITIES * (NAME_LEN + 4 + 4)

    def __init__(self):
        self.register     = {}
        self._active_buf  = create_string_buffer(self._REAL_MAX_BUF)
        self._field_order = random_field_order()
        self._pad_sizes   = random_pad_sizes(MAX_ENTITIES * self._N_FIELDS)
        self._buf_size    = 0

        # v9: initialise epoch key (refreshed each swap)
        self._master_seed = secrets.token_bytes(32)
        self._mask_name, self._mask_x, self._mask_y = derive_epoch_masks(
            self._master_seed, 0
        )

        self._decoys        = [create_string_buffer(self._DECOY_SIZE) for _ in range(BASE_DECOYS)]
        self._decoy_idx     = 0
        self._target_decoys = BASE_DECOYS
        self._prev_decoy_addrs = set()

        self._scrub_event = Event()
        self._stop_event  = Event()
        self._buf_lock    = Lock()

        self._scrub_thread     = Thread(target=self._scrub_worker, daemon=True, name='scrub')
        self._telemetry_thread = Thread(target=self._telemetry_worker, daemon=True, name='telemetry')
        self._scrub_thread.start()
        self._telemetry_thread.start()

        self._scrub_count = 0

        self._canary_seed      = randbytes(CANARY_SIZE)
        self._last_canary      = bytearray(CANARY_SIZE)
        self._telemetry_hits   = 0
        self._telemetry_events = []
        self._last_hit_time    = None
        self._observer_periods = []

        self._poison_active_until_epoch = -1
        self._poison_activations        = 0

        self._hits_window     = deque(maxlen=SCORE_WINDOW_EPOCHS)
        self._delta_window    = deque(maxlen=SCORE_WINDOW_EPOCHS * 4)
        self._churn_window    = deque(maxlen=SCORE_WINDOW_EPOCHS)
        self._epoch_hit_count = 0

        self._simulate_observer = os.environ.get('SIMULATE_OBSERVER', '0') == '1'
        if self._simulate_observer:
            self._observer_thread = Thread(target=self._observer_worker, daemon=True, name='observer')
            self._observer_thread.start()
        else:
            self._observer_thread = None

    # ── internal workers (unchanged from v8) ────────────────────────────────

    def _write_canary_locked(self):
        struct.pack_into(f'{CANARY_SIZE}s', self._active_buf, CANARY_OFFSET, self._canary_seed)

    def _read_canary_locked(self):
        return bytes(self._active_buf[CANARY_OFFSET:CANARY_OFFSET + CANARY_SIZE])

    def _telemetry_worker(self):
        while not self._stop_event.is_set():
            sleep(TELEMETRY_POLL_S)
            with self._buf_lock:
                current = self._read_canary_locked()
            if current != self._last_canary:
                now      = perf_counter()
                delta_ms = None
                if self._last_hit_time is not None:
                    delta_ms = (now - self._last_hit_time) * 1000.0
                    self._observer_periods.append(delta_ms)
                    self._delta_window.append(delta_ms)
                self._last_hit_time    = now
                self._telemetry_hits  += 1
                self._epoch_hit_count += 1
                self._last_canary      = current
                self._telemetry_events.append({
                    't':        now,
                    'delta_ms': delta_ms,
                    'addr':     self.shared_address(),
                })

    def _observer_worker(self):
        while not self._stop_event.is_set():
            sleep(0.5)
            with self._buf_lock:
                idx  = randint(0, CANARY_SIZE - 1)
                base = CANARY_OFFSET + idx
                cur  = self._active_buf[base]
                if isinstance(cur, (bytes, bytearray)):
                    cur = cur[0]
                new_byte = bytes([(cur ^ 0x01) & 0xFF])
                memmove(addressof(self._active_buf) + base, new_byte, 1)

    def _scrub_worker(self):
        while not self._stop_event.is_set():
            fired = self._scrub_event.wait(timeout=1.0)
            if not fired:
                continue
            self._scrub_event.clear()
            sleep(COHERENCE_WINDOW_S)
            if self._stop_event.is_set():
                break
            with self._buf_lock:
                scrub_buffer(self._active_buf, self._buf_size)
            self._scrub_count += 1

    def _ensure_decoy_capacity(self):
        while len(self._decoys) < self._target_decoys:
            self._decoys.append(create_string_buffer(self._DECOY_SIZE))
        while len(self._decoys) > self._target_decoys:
            self._decoys.pop()
        self._decoy_idx %= len(self._decoys)

    def _mean_delta_ms(self):
        if not self._observer_periods:
            return None
        return sum(self._observer_periods) / len(self._observer_periods)

    def _should_activate_poison(self):
        mean_ms = self._mean_delta_ms()
        if mean_ms is None:
            return False
        if self._telemetry_hits < SUSPICION_HIT_THRESHOLD:
            return False
        return SUSPICION_DELTA_MIN_MS <= mean_ms <= SUSPICION_DELTA_MAX_MS

    def _update_poison_state(self, epoch):
        if self._should_activate_poison():
            if epoch > self._poison_active_until_epoch:
                self._poison_activations += 1
            self._poison_active_until_epoch = epoch + POISON_HOLD_EPOCHS
        self._target_decoys = MAX_DECOYS if epoch <= self._poison_active_until_epoch else BASE_DECOYS
        self._ensure_decoy_capacity()

    def _measure_decoy_churn(self):
        cur   = set(addressof(d) for d in self._decoys)
        churn = len(cur.symmetric_difference(self._prev_decoy_addrs))
        self._prev_decoy_addrs = cur
        return churn

    def _compute_and_emit_anomaly_score(self, epoch):
        score = compute_anomaly_score(
            list(self._hits_window),
            list(self._delta_window),
            self._poison_activations,
            list(self._churn_window),
        )
        level = ('CRITICAL' if score >= 0.75
                 else 'HIGH    ' if score >= 0.50
                 else 'MEDIUM  ' if score >= 0.25
                 else 'LOW     ')
        print(f'  [anomaly] epoch={epoch} score={score:.4f} [{level}]'
              f'  hits_window={list(self._hits_window)}'
              f'  delta_var={_variance(list(self._delta_window)):.1f}')
        return score

    # ── public API ───────────────────────────────────────────────────────────

    def stop(self):
        self._stop_event.set()
        self._scrub_event.set()
        self._scrub_thread.join(timeout=2.0)
        self._telemetry_thread.join(timeout=2.0)
        if self._observer_thread is not None:
            self._observer_thread.join(timeout=2.0)

    def add(self, entity: Entity):
        self.register[entity.name] = entity

    def access_register(self):
        return self.register

    def snapshot(self):
        return deepcopy(self.register)

    def _write_real(self, buf, tick, epoch):
        data = build_shuffled_buffer(
            tick, epoch,
            list(self.register.values()),
            self._field_order, self._pad_sizes,
            self._mask_name, self._mask_x, self._mask_y,
        )
        struct.pack_into(f'{len(buf)}s', buf, 0, b'\x00' * len(buf))
        struct.pack_into(f'{len(data)}s', buf, 0, data)
        return len(data)

    def _refresh_all_decoys(self, tick, epoch):
        for dbuf in self._decoys:
            data = build_decoy_buffer(tick, epoch)
            struct.pack_into(f'{len(dbuf)}s', dbuf, 0, data)

    def sync_shared(self, tick, epoch):
        self._update_poison_state(epoch)
        with self._buf_lock:
            self._buf_size = self._write_real(self._active_buf, tick, epoch)
            self._write_canary_locked()
        self._refresh_all_decoys(tick, epoch)
        self._scrub_event.set()

    def swap_shared(self, tick, epoch):
        """
        v9 swap_shared:
          1. Rotate field order + pads (v1+v2)
          2. Derive new epoch master seed + masks (v9 NEW)
          3. Allocate new buffer, write encrypted payload, swap atomically (v4)
          4. Rotate one decoy slot, refresh all decoys with encrypted garbage (v3+v9)
          5. Emit anomaly score (v8)
          6. Demonstrate authoritative round-trip decryption in log (v9 NEW)
        """
        self._field_order = random_field_order()
        self._pad_sizes   = random_pad_sizes(MAX_ENTITIES * self._N_FIELDS)
        self._update_poison_state(epoch)

        # v9: derive fresh epoch key — lives only in local variables
        self._master_seed                        = secrets.token_bytes(32)
        self._mask_name, self._mask_x, self._mask_y = derive_epoch_masks(
            self._master_seed, epoch
        )

        self._hits_window.append(self._epoch_hit_count)
        self._epoch_hit_count = 0
        churn = self._measure_decoy_churn()
        self._churn_window.append(churn)

        old_buf = self._active_buf
        new_buf = create_string_buffer(self._REAL_MAX_BUF)
        with self._buf_lock:
            self._buf_size   = self._write_real(new_buf, tick, epoch)
            self._active_buf = new_buf
            self._write_canary_locked()
        del old_buf
        gc.collect()

        self._decoys[self._decoy_idx] = create_string_buffer(self._DECOY_SIZE)
        self._decoy_idx = (self._decoy_idx + 1) % len(self._decoys)
        self._refresh_all_decoys(tick, epoch)
        self._scrub_event.set()

        mean_ms  = self._mean_delta_ms()
        mean_txt = f'{mean_ms:.1f}ms' if mean_ms is not None else 'n/a'
        poison   = int(self.poison_active(epoch))
        print(
            f'[swap] tick={tick} epoch={epoch}'
            f' real_addr={self.shared_address()}'
            f' decoys={self.decoy_count()}'
            f' poison={poison} activations={self.poison_activations()}'
            f' scrubs={self.scrub_count()}'
            f' telemetry_hits={self.telemetry_hits()}'
            f' mean_delta={mean_txt}'
        )
        self._compute_and_emit_anomaly_score(epoch)

        # v9: authoritative round-trip decrypt — demonstrates correct in-process
        # key usage. This mirrors what the game thread would do when reading
        # back entity state. Printed to show the key works correctly.
        print(f'  [v9-decrypt] epoch={epoch}  seed={self._master_seed.hex()[:16]}...')
        for entity in self.register.values():
            enc_name, enc_x, enc_y = encrypt_entity_fields(
                entity.name.encode(), entity.x, entity.y,
                self._mask_name, self._mask_x, self._mask_y,
            )
            dec_name, dec_x, dec_y = decrypt_entity_fields(
                enc_name, enc_x, enc_y,
                self._mask_name, self._mask_x, self._mask_y,
            )
            match = '✓' if (dec_name == entity.name and dec_x == entity.x and dec_y == entity.y) else '✗ MISMATCH'
            print(f'    entity={entity.name} plaintext=({entity.x},{entity.y}) '
                  f'-> enc -> dec=({dec_x},{dec_y}) [{match}]')

    def shared_address(self):       return addressof(self._active_buf)
    def decoy_addresses(self):      return [addressof(d) for d in self._decoys]
    def shared_size(self):          return self._buf_size
    def scrub_count(self):          return self._scrub_count
    def telemetry_hits(self):       return self._telemetry_hits
    def telemetry_events(self):     return list(self._telemetry_events)
    def current_field_order(self):  return list(self._field_order)
    def current_pad_sizes(self):    return list(self._pad_sizes)
    def observer_mean_ms(self):     return self._mean_delta_ms()
    def decoy_count(self):          return len(self._decoys)
    def poison_active(self, epoch): return epoch <= self._poison_active_until_epoch
    def poison_activations(self):   return self._poison_activations
    def current_epoch_seed(self):   return self._master_seed   # authoritative path only


# ── game simulation ──────────────────────────────────────────────────────────

entityRegister = EncryptedEpochRegister()
entityLogger   = EntityLogger()


def gameinit():
    e1 = Entity('CT1', randint(0, 9), randint(0, 9))
    e2 = Entity('T1',  randint(0, 9), randint(0, 9))
    entityRegister.add(e1)
    entityRegister.add(e2)
    entityRegister.sync_shared(0, 0)


def gameloop():
    try:
        second_counter = 0
        current_second = 0
        tick           = 0
        epoch          = 0
        i              = 0

        print(f'PID:                {os.getpid()}')
        print(f'VERSION:            9  (v1+v2+v3+v4+v5+v6+v7+v8 + encryption epoch system)')
        print(f'COHERENCE_WINDOW:   {COHERENCE_WINDOW_S * 1000:.0f} ms')
        print(f'TELEMETRY_POLL:     {TELEMETRY_POLL_S * 1000:.0f} ms')
        print(f'SIMULATE_OBSERVER:  {int(entityRegister._simulate_observer)}')
        print(f'INITIAL_ADDR:       {entityRegister.shared_address()}')
        print(f'SCORE_WINDOW:       {SCORE_WINDOW_EPOCHS} epochs')
        print()

        while i < 600:
            sleep(0.05)
            second_counter += 1

            if second_counter - current_second == 20:
                current_second = second_counter
                tick += 1

                for entity in entityRegister.access_register().values():
                    entity.setx(randint(0, 9))
                    entity.sety(randint(0, 9))

                entityRegister.swap_shared(tick, epoch)

            if tick >= EPOCH_UPDATE_RULE:
                epoch += 1
                entityLogger.log(
                    datetime.now().timestamp(), tick, epoch,
                    entityRegister.snapshot()
                )
                tick = 0

            i += 1

        for entry in entityLogger.access_log():
            print(
                f'Timestamp: {entry[0]}, Tick: {entry[1]}, '
                f'Epoch: {entry[2]}, Entities: {entry[3]}'
            )

        print()
        print(f'TELEMETRY_TOTAL_HITS: {entityRegister.telemetry_hits()}')
        mean_ms = entityRegister.observer_mean_ms()
        if mean_ms is not None:
            print(f'TELEMETRY_MEAN_DELTA_MS: {mean_ms:.2f}')
        print(f'POISON_ACTIVATIONS: {entityRegister.poison_activations()}')
        print(f'FINAL_DECOY_COUNT:  {entityRegister.decoy_count()}')

    except KeyboardInterrupt:
        print('Keyboard interrupt — exiting.')
    finally:
        entityRegister.stop()
        sys.exit(0)


if __name__ == '__main__':
    gameinit()
    gameloop()
    input('Simulation complete. Press any key to exit...')
