import sys
import os
import struct
import gc
from random import randint, randbytes, shuffle, choice
from copy import deepcopy
from datetime import datetime
from time import sleep, perf_counter
from ctypes import create_string_buffer, addressof, memmove
from threading import Thread, Event, Lock

# ── constants ────────────────────────────────────────────────────────────────
EPOCH_UPDATE_RULE = 1
MAX_ENTITIES      = 2
NAME_LEN          = 8
MAGIC             = 0xA11F
VERSION           = 6

PAD_MIN  = 1
PAD_MAX  = 16
N_DECOYS = 4
COHERENCE_WINDOW_S = 0.05

TELEMETRY_POLL_S     = 0.01
CANARY_SIZE          = 64
CANARY_OFFSET        = 24

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


# ── layout helpers ─────────────────────────────────────────────────────────
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
            decoy_entity_fmt, choice(DECOY_NAME_POOL),
            randint(0, 9), randint(0, 9)
        )
    return struct.pack(HEADER_FMT, MAGIC, VERSION, tick, epoch, MAX_ENTITIES) + entities_bytes


def scrub_buffer(buf, size):
    noise = randbytes(size)
    struct.pack_into(f'{size}s', buf, 0, noise)


# ── domain model ───────────────────────────────────────────────────────────────
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


# ── v6 register ───────────────────────────────────────────────────────────────
class PollTelemetryRegister:
    """
    v5 + polling telemetry canary.

    A 64-byte canary is embedded inside the real buffer at CANARY_OFFSET.
    The game never touches the canary after writing it.  A background telemetry
    thread reads the canary every TELEMETRY_POLL_S seconds.  Any change is an
    anomaly event: timestamp, inter-event delta, and current epoch are recorded.

    In production this approach detects in-process corruption or a co-resident
    writer.  For the prototype we supply SIMULATE_OBSERVER=1 which spawns a
    thread that flips one canary byte every 500 ms, giving a demonstrable
    500 ms cadence fingerprint in the telemetry output.

    Lock discipline:
      _buf_lock is held by the CALLER before calling _write_canary_locked() or
      _read_canary_locked().  Those two helpers must never acquire the lock
      themselves to prevent reentrant deadlock.
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
        self._decoys      = [create_string_buffer(self._DECOY_SIZE) for _ in range(N_DECOYS)]
        self._decoy_idx   = 0

        self._scrub_event = Event()
        self._stop_event  = Event()
        self._buf_lock    = Lock()

        self._scrub_thread     = Thread(target=self._scrub_worker, daemon=True, name='scrub')
        self._telemetry_thread = Thread(target=self._telemetry_worker, daemon=True, name='telemetry')
        self._scrub_thread.start()
        self._telemetry_thread.start()

        self._scrub_count = 0

        # v6 telemetry state (no lock needed — only written by telemetry thread,
        # read by main thread only after stop())
        self._canary_seed      = randbytes(CANARY_SIZE)
        self._last_canary      = bytearray(CANARY_SIZE)   # starts all-zero → first write triggers hit
        self._telemetry_hits   = 0
        self._telemetry_events = []
        self._last_hit_time    = None
        self._observer_periods = []

        self._simulate_observer = os.environ.get('SIMULATE_OBSERVER', '0') == '1'
        if self._simulate_observer:
            self._observer_thread = Thread(target=self._observer_worker, daemon=True, name='observer')
            self._observer_thread.start()
        else:
            self._observer_thread = None

    # ——— lock-free internal helpers (caller must hold _buf_lock) ————————————
    def _write_canary_locked(self):
        struct.pack_into(f'{CANARY_SIZE}s', self._active_buf, CANARY_OFFSET, self._canary_seed)

    def _read_canary_locked(self):
        return bytes(self._active_buf[CANARY_OFFSET:CANARY_OFFSET + CANARY_SIZE])

    # ——— background threads ———————————————————————————————————————————
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
                self._last_hit_time  = now
                self._telemetry_hits += 1
                self._last_canary     = current
                self._telemetry_events.append({
                    't':         now,
                    'delta_ms':  delta_ms,
                    'addr':      self.shared_address(),
                    'epoch':     self._read_epoch_hint(),
                })

    def _observer_worker(self):
        """Prototype-only: simulates a polling actor mutating the canary every 500 ms."""
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

    def _read_epoch_hint(self):
        try:
            raw = bytes(self._active_buf[:HEADER_SIZE])
            _, _, _tick, epoch, _ = struct.unpack(HEADER_FMT, raw)
            return epoch
        except Exception:
            return -1

    def stop(self):
        self._stop_event.set()
        self._scrub_event.set()
        self._scrub_thread.join(timeout=2.0)
        self._telemetry_thread.join(timeout=2.0)
        if self._observer_thread is not None:
            self._observer_thread.join(timeout=2.0)

    # ——— public API ————————————————————————————————————————————————
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
        with self._buf_lock:
            self._buf_size = self._write_real(self._active_buf, tick, epoch)
            self._write_canary_locked()
        self._refresh_all_decoys(tick, epoch)
        self._scrub_event.set()

    def swap_shared(self, tick, epoch):
        self._field_order = random_field_order()
        self._pad_sizes   = random_pad_sizes(MAX_ENTITIES * self._N_FIELDS)

        old_buf = self._active_buf
        new_buf = create_string_buffer(self._REAL_MAX_BUF)
        with self._buf_lock:
            self._buf_size   = self._write_real(new_buf, tick, epoch)
            self._active_buf = new_buf
            self._write_canary_locked()
        del old_buf
        gc.collect()

        self._decoys[self._decoy_idx] = create_string_buffer(self._DECOY_SIZE)
        self._decoy_idx = (self._decoy_idx + 1) % N_DECOYS
        self._refresh_all_decoys(tick, epoch)
        self._scrub_event.set()

    def shared_address(self):      return addressof(self._active_buf)
    def decoy_addresses(self):     return [addressof(d) for d in self._decoys]
    def shared_size(self):         return self._buf_size
    def scrub_count(self):         return self._scrub_count
    def telemetry_hits(self):      return self._telemetry_hits
    def telemetry_events(self):    return list(self._telemetry_events)
    def current_field_order(self): return list(self._field_order)
    def current_pad_sizes(self):   return list(self._pad_sizes)

    def observer_mean_ms(self):
        if not self._observer_periods:
            return None
        return sum(self._observer_periods) / len(self._observer_periods)


# ── globals ───────────────────────────────────────────────────────────────
entityRegister = PollTelemetryRegister()
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

        print(f"PID:                {os.getpid()}")
        print(f"VERSION:            6  (v1+v2+v3+v4+v5 + polling telemetry)")
        print(f"COHERENCE_WINDOW:   {COHERENCE_WINDOW_S*1000:.0f} ms")
        print(f"TELEMETRY_POLL:     {TELEMETRY_POLL_S*1000:.0f} ms")
        print(f"SIMULATE_OBSERVER:  {int(entityRegister._simulate_observer)}")
        print(f"INITIAL_ADDR:       {entityRegister.shared_address()}")
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

                mean_ms  = entityRegister.observer_mean_ms()
                mean_txt = f"{mean_ms:.1f}ms" if mean_ms is not None else "n/a"
                print(
                    f"[swap] tick={tick} epoch={epoch} "
                    f"real_addr={entityRegister.shared_address()} "
                    f"scrubs={entityRegister.scrub_count()} "
                    f"telemetry_hits={entityRegister.telemetry_hits()} "
                    f"mean_delta={mean_txt}"
                )

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
                f"Timestamp: {entry[0]}, Tick: {entry[1]}, "
                f"Epoch: {entry[2]}, Entities: {entry[3]}"
            )

        print()
        print(f"TELEMETRY_TOTAL_HITS: {entityRegister.telemetry_hits()}")
        mean_ms = entityRegister.observer_mean_ms()
        if mean_ms is not None:
            print(f"TELEMETRY_MEAN_DELTA_MS: {mean_ms:.2f}")
        for idx, ev in enumerate(entityRegister.telemetry_events()[-10:], 1):
            print(
                f"[telemetry {idx:02d}] addr={hex(ev['addr'])} "
                f"epoch={ev['epoch']} delta_ms={ev['delta_ms']}"
            )

    except KeyboardInterrupt:
        print('Keyboard interrupt — exiting.')
    finally:
        entityRegister.stop()
        sys.exit(0)


if __name__ == '__main__':
    gameinit()
    gameloop()
    input('Simulation complete. Press any key to exit...')
