import sys
import os
import struct
import gc
from random import randint, randbytes, shuffle, choice
from copy import deepcopy
from datetime import datetime
from time import sleep, perf_counter
from ctypes import create_string_buffer, addressof, c_char, memmove
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

# v6 telemetry tuning
TELEMETRY_POLL_S       = 0.01   # sample cadence for canary inspection
CANARY_SIZE            = 64
CANARY_OFFSET          = 24     # after header, inside the real buffer body
SUSPICIOUS_THRESHOLD   = 1      # one unexpected mutation = suspicious

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
            decoy_entity_fmt, choice(DECOY_NAME_POOL),
            randint(0, 9), randint(0, 9)
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


class PollTelemetryRegister:
    """
    v6 = v5 + polling telemetry canary.

    We place a 64-byte canary blob inside the real buffer body. The game never
    touches it after writing. A background telemetry thread snapshots the canary
    every 10 ms and checks for unexpected mutation.

    This does NOT detect a normal read (Linux userland cannot directly observe
    remote reads of its own pages without kernel support), so this is an
    approximation layer for the prototype: it fingerprints *interference* with
    the buffer region and records cadence of observed mutations. This is enough
    to prototype the control plane for v6 and feed v7 later.

    To make the telemetry demonstrable in the prototype, optionally enable the
    built-in "simulated observer" thread with SIMULATE_OBSERVER=1. That thread
    flips one canary byte every 500 ms, imitating a polling actor touching the
    buffer at a regular cadence.
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

        self._scrub_thread     = Thread(target=self._scrub_worker, daemon=True)
        self._telemetry_thread = Thread(target=self._telemetry_worker, daemon=True)
        self._scrub_thread.start()
        self._telemetry_thread.start()

        self._last_write_time = 0.0
        self._scrub_count     = 0

        # v6 telemetry state
        self._canary_seed       = randbytes(CANARY_SIZE)
        self._last_canary       = self._canary_seed
        self._telemetry_hits    = 0
        self._telemetry_events  = []
        self._last_hit_time     = None
        self._observer_periods  = []

        self._simulate_observer = os.environ.get('SIMULATE_OBSERVER', '0') == '1'
        self._observer_thread   = None
        if self._simulate_observer:
            self._observer_thread = Thread(target=self._observer_worker, daemon=True)
            self._observer_thread.start()

    def _write_canary(self):
        with self._buf_lock:
            struct.pack_into(f'{CANARY_SIZE}s', self._active_buf, CANARY_OFFSET, self._canary_seed)
            self._last_canary = self._canary_seed

    def _read_canary(self):
        with self._buf_lock:
            raw = bytes(self._active_buf[CANARY_OFFSET:CANARY_OFFSET + CANARY_SIZE])
        return raw

    def _telemetry_worker(self):
        while not self._stop_event.is_set():
            sleep(TELEMETRY_POLL_S)
            current = self._read_canary()
            if current != self._last_canary:
                now = perf_counter()
                delta_ms = None
                if self._last_hit_time is not None:
                    delta_ms = (now - self._last_hit_time) * 1000.0
                    self._observer_periods.append(delta_ms)
                self._last_hit_time = now
                self._telemetry_hits += 1
                self._telemetry_events.append({
                    't': now,
                    'delta_ms': delta_ms,
                    'addr': self.shared_address(),
                    'epoch_hint': self.current_epoch_hint(),
                })
                self._last_canary = current

    def _observer_worker(self):
        """
        Prototype-only demonstrator: every 500 ms, mutate one byte in the canary
        to imitate a regular polling actor perturbing the region.
        """
        while not self._stop_event.is_set():
            sleep(0.5)
            with self._buf_lock:
                idx = randint(0, CANARY_SIZE - 1)
                base = CANARY_OFFSET + idx
                cur = self._active_buf[base]
                if isinstance(cur, bytes):
                    cur = cur[0]
                new = bytes([(cur ^ 0x01) & 0xFF])
                memmove(addressof(self._active_buf) + base, new, 1)

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
        with self._buf_lock:
            self._buf_size = self._write_real(self._active_buf, tick, epoch)
            self._write_canary()
        self._refresh_all_decoys(tick, epoch)
        self._last_write_time = perf_counter()
        self._scrub_event.set()

    def swap_shared(self, tick, epoch):
        self._field_order = random_field_order()
        self._pad_sizes   = random_pad_sizes(MAX_ENTITIES * self._N_FIELDS)

        old_buf = self._active_buf
        new_buf = create_string_buffer(self._REAL_MAX_BUF)
        with self._buf_lock:
            self._buf_size   = self._write_real(new_buf, tick, epoch)
            self._active_buf = new_buf
            self._write_canary()
        del old_buf
        gc.collect()

        self._decoys[self._decoy_idx] = create_string_buffer(self._DECOY_SIZE)
        self._decoy_idx = (self._decoy_idx + 1) % N_DECOYS
        self._refresh_all_decoys(tick, epoch)

        self._last_write_time = perf_counter()
        self._scrub_event.set()

    def shared_address(self):
        return addressof(self._active_buf)

    def decoy_addresses(self):
        return [addressof(d) for d in self._decoys]

    def shared_size(self):
        return self._buf_size

    def scrub_count(self):
        return self._scrub_count

    def current_field_order(self):
        return list(self._field_order)

    def current_pad_sizes(self):
        return list(self._pad_sizes)

    def telemetry_hits(self):
        return self._telemetry_hits

    def telemetry_events(self):
        return list(self._telemetry_events)

    def current_epoch_hint(self):
        try:
            with self._buf_lock:
                raw = bytes(self._active_buf[:HEADER_SIZE])
            _, _, tick, epoch, _ = struct.unpack(HEADER_FMT, raw)
            return epoch
        except Exception:
            return -1

    def observer_mean_ms(self):
        if not self._observer_periods:
            return None
        return sum(self._observer_periods) / len(self._observer_periods)


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

                mean_ms = entityRegister.observer_mean_ms()
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
        for idx, ev in enumerate(entityRegister.telemetry_events()[-10:], start=1):
            print(
                f"[telemetry {idx}] addr={hex(ev['addr'])} "
                f"epoch_hint={ev['epoch_hint']} delta_ms={ev['delta_ms']}"
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
