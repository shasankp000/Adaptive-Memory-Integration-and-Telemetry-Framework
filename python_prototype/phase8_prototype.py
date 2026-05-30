import sys
import os
import struct
import gc
import math
from random import randint, randbytes, shuffle, choice
from copy import deepcopy
from datetime import datetime
from time import sleep, perf_counter
from ctypes import create_string_buffer, addressof, memmove
from threading import Thread, Event, Lock
from collections import deque

# ── constants ────────────────────────────────────────────────────────────────
EPOCH_UPDATE_RULE = 1
MAX_ENTITIES      = 2
NAME_LEN          = 8
MAGIC             = 0xA11F
VERSION           = 8

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
SCORE_WINDOW_EPOCHS  = 6    # how many recent epochs to score over
SCORE_HIT_RATE_W     = 0.35 # weight: hits-per-epoch rate
SCORE_DELTA_STAB_W   = 0.35 # weight: delta stability (low variance = high score)
SCORE_POISON_W       = 0.20 # weight: poison activation count (normalised)
SCORE_CHURN_W        = 0.10 # weight: decoy churn rate

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


def build_shuffled_buffer(tick, epoch, entities, field_order, pad_sizes):
    header  = struct.pack(HEADER_FMT, MAGIC, VERSION, tick, epoch, MAX_ENTITIES)
    offsets = build_layout(field_order, pad_sizes)
    total   = sum(pad_sizes) + MAX_ENTITIES * sum(sz for _, sz in field_order)
    entity_region = bytearray(randbytes(total))
    for i, entity in enumerate(entities[:MAX_ENTITIES]):
        fm = {
            'name': entity.name.encode()[:NAME_LEN].ljust(NAME_LEN, b'\x00'),
            'x':    struct.pack('<i', entity.x),
            'y':    struct.pack('<i', entity.y),
        }
        for field_name, field_size in field_order:
            off = offsets[(i, field_name)]
            entity_region[off:off + field_size] = fm[field_name]
    return header + bytes(entity_region)


def build_decoy_buffer(tick, epoch):
    decoy_entity_fmt = f'<{NAME_LEN}sii'
    entities_bytes   = b''
    for _ in range(MAX_ENTITIES):
        entities_bytes += struct.pack(
            decoy_entity_fmt,
            choice(DECOY_NAME_POOL),
            randint(0, 9),
            randint(0, 9),
        )
    return struct.pack(HEADER_FMT, MAGIC, VERSION, tick, epoch, MAX_ENTITIES) + entities_bytes


def scrub_buffer(buf, size):
    noise = randbytes(size)
    struct.pack_into(f'{size}s', buf, 0, noise)


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


# ── anomaly scoring helpers ──────────────────────────────────────────────────────
def _variance(values):
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return sum((v - mean) ** 2 for v in values) / len(values)


def compute_anomaly_score(
    hits_window,          # list of hit counts per recent epoch
    delta_window,         # list of inter-hit deltas (ms) from recent epochs
    poison_activations,   # total poison activation count
    decoy_churn_window,   # list of (new+gone) decoy address changes per epoch
):
    """
    Returns a float in [0.0, 1.0] representing observer suspicion level.
    0.0 = no anomaly detected, 1.0 = highly suspicious polling behaviour.

    Components:
      hit_rate_score:   normalise hits/epoch against expected self-write cadence (2/epoch)
      delta_stab_score: low variance in inter-hit delta ⇒ stable cadence ⇒ higher score
      poison_score:     any poison activations ⇒ non-zero contribution
      churn_score:      high decoy churn rate relative to decoy pool size ⇒ reader is tracking
    """
    # Hit rate component: expected self-write = 2 hits/epoch; anything higher is suspicious
    if hits_window:
        mean_hits = sum(hits_window) / len(hits_window)
        # 2 hits/epoch = baseline self-writes; scale so 4+ hits = score 1.0
        hit_rate_score = min(max((mean_hits - 2.0) / 4.0, 0.0), 1.0)
    else:
        hit_rate_score = 0.0

    # Delta stability component: low variance across a stable 500ms cadence = suspicious
    if len(delta_window) >= 2:
        var = _variance(delta_window)
        # variance < 5000 ms² (i.e. std < ~70ms) around a 500ms mean is suspicious
        delta_stab_score = min(max(1.0 - (var / 50000.0), 0.0), 1.0)
    else:
        delta_stab_score = 0.0

    # Poison activation component
    poison_score = min(poison_activations / 3.0, 1.0)

    # Churn rate component: high churn per epoch = reader is repeatedly refreshing its map
    if decoy_churn_window:
        mean_churn = sum(decoy_churn_window) / len(decoy_churn_window)
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


class AnomalyScoringRegister:
    """
    v8 = v7 + per-epoch anomaly score emitted to console.

    The anomaly score is a composite [0,1] scalar built from:
      - telemetry hit rate over the last SCORE_WINDOW_EPOCHS epochs
      - inter-hit delta variance (stable cadence = high score)
      - poison activation count
      - decoy address churn rate

    This mirrors what a server-side trust pipeline would ingest as a
    behavioural signal and closes the loop between memory defence and telemetry.
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

        # rolling windows for anomaly scoring
        self._hits_window  = deque(maxlen=SCORE_WINDOW_EPOCHS)
        self._delta_window = deque(maxlen=SCORE_WINDOW_EPOCHS * 4)
        self._churn_window = deque(maxlen=SCORE_WINDOW_EPOCHS)
        self._epoch_hit_count = 0  # hits accumulated since last swap

        self._simulate_observer = os.environ.get('SIMULATE_OBSERVER', '0') == '1'
        if self._simulate_observer:
            self._observer_thread = Thread(target=self._observer_worker, daemon=True, name='observer')
            self._observer_thread.start()
        else:
            self._observer_thread = None

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
                self._last_hit_time   = now
                self._telemetry_hits += 1
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
        if epoch <= self._poison_active_until_epoch:
            self._target_decoys = MAX_DECOYS
        else:
            self._target_decoys = BASE_DECOYS
        self._ensure_decoy_capacity()

    def _measure_decoy_churn(self):
        cur = set(addressof(d) for d in self._decoys)
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
        self._field_order = random_field_order()
        self._pad_sizes   = random_pad_sizes(MAX_ENTITIES * self._N_FIELDS)
        self._update_poison_state(epoch)

        # snapshot epoch-level telemetry before rolling window update
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

    def shared_address(self):      return addressof(self._active_buf)
    def decoy_addresses(self):     return [addressof(d) for d in self._decoys]
    def shared_size(self):         return self._buf_size
    def scrub_count(self):         return self._scrub_count
    def telemetry_hits(self):      return self._telemetry_hits
    def telemetry_events(self):    return list(self._telemetry_events)
    def current_field_order(self): return list(self._field_order)
    def current_pad_sizes(self):   return list(self._pad_sizes)
    def observer_mean_ms(self):    return self._mean_delta_ms()
    def decoy_count(self):         return len(self._decoys)
    def poison_active(self, epoch): return epoch <= self._poison_active_until_epoch
    def poison_activations(self):  return self._poison_activations
    def last_anomaly_score(self):  return self._compute_and_emit_anomaly_score


entityRegister = AnomalyScoringRegister()
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
        print(f'VERSION:            8  (v1+v2+v3+v4+v5+v6+v7 + anomaly scoring)')
        print(f'COHERENCE_WINDOW:   {COHERENCE_WINDOW_S*1000:.0f} ms')
        print(f'TELEMETRY_POLL:     {TELEMETRY_POLL_S*1000:.0f} ms')
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
