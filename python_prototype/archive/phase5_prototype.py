import sys
import os
import struct
import gc
from random import randint, randbytes, shuffle, choice
from typing import List
from copy import deepcopy
from datetime import datetime
from time import sleep, perf_counter
from ctypes import create_string_buffer, addressof
from threading import Thread, Event

# ── constants ────────────────────────────────────────────────────────────────
EPOCH_UPDATE_RULE = 1
MAX_ENTITIES      = 2
NAME_LEN          = 8
MAGIC             = 0xA11F
VERSION           = 5

PAD_MIN  = 1
PAD_MAX  = 16
N_DECOYS = 4

# ── v5 coherence window ──────────────────────────────────────────────────────
# How long (seconds) the plaintext entity data is allowed to exist in the
# active buffer before it is scrubbed back to random noise.
# The game loop writes real data, uses it internally for its own tick, then
# the scrub thread overwrites after this window expires.
# A reader polling at 0.5s intervals needs to land within this window to
# have any chance of reading valid data — and even then v1+v2+v3+v4 still
# apply, so the data is fragmented and at an unknown relocated address.
COHERENCE_WINDOW_S = 0.05   # 50 ms — matches one game tick (0.05s sleep)

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


# ── layout helpers (unchanged from v4) ─────────────────────────────────────
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
    """
    Overwrite the first `size` bytes of buf with random noise.
    The magic bytes in the header are destroyed, so the reader’s scanner
    can no longer find this buffer at all — even if it had the address.
    """
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


# ── v5 register ───────────────────────────────────────────────────────────────
class CoherenceWindowRegister:
    """
    v4 + short-lived coherence windows.

    After swap_shared() writes real (fragmented+shuffled) data into the
    new active buffer, a background thread waits COHERENCE_WINDOW_S seconds
    then calls scrub_buffer() to overwrite the entity region with random
    noise — destroying the magic bytes so the scanner can’t find the buffer
    and destroying the entity data so even a direct read gets garbage.

    The game loop reads entity state from self.register (Python objects in
    normal heap memory) — the shared buffer is write-only from the game’s
    perspective after the scrub. Only a reader that polls WITHIN the
    coherence window has any chance of seeing a magic-valid buffer, and
    even then all v1+v2+v3+v4 defences are still active.

    Decoys are NOT scrubbed — they remain readable forever, so the reader
    still gets flooded with plausible-looking garbage on every pass.
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
        self._decoys      = [
            create_string_buffer(self._DECOY_SIZE) for _ in range(N_DECOYS)
        ]
        self._decoy_idx   = 0
        self._scrub_event = Event()   # signals the scrub thread to fire
        self._stop_event  = Event()   # signals the scrub thread to exit
        self._scrub_thread = Thread(target=self._scrub_worker, daemon=True)
        self._scrub_thread.start()
        self._last_write_time = 0.0
        self._scrub_count     = 0

    def _scrub_worker(self):
        """
        Background thread: waits for scrub_event, then sleeps
        COHERENCE_WINDOW_S, then scrubs the active buffer.
        """
        while not self._stop_event.is_set():
            fired = self._scrub_event.wait(timeout=1.0)
            if not fired:
                continue
            self._scrub_event.clear()
            sleep(COHERENCE_WINDOW_S)
            if self._stop_event.is_set():
                break
            scrub_buffer(self._active_buf, self._buf_size)
            self._scrub_count += 1

    def stop(self):
        self._stop_event.set()
        self._scrub_event.set()
        self._scrub_thread.join(timeout=2.0)

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
        self._buf_size = self._write_real(self._active_buf, tick, epoch)
        self._refresh_all_decoys(tick, epoch)
        self._last_write_time = perf_counter()
        self._scrub_event.set()   # start coherence countdown immediately

    def swap_shared(self, tick, epoch):
        self._field_order = random_field_order()
        self._pad_sizes   = random_pad_sizes(MAX_ENTITIES * self._N_FIELDS)

        # Relocate: new buffer, drop old
        old_buf          = self._active_buf
        new_buf          = create_string_buffer(self._REAL_MAX_BUF)
        self._buf_size   = self._write_real(new_buf, tick, epoch)
        self._active_buf = new_buf
        del old_buf
        gc.collect()   # eliminate GC lag observed in v4

        # Rotate one decoy slot
        self._decoys[self._decoy_idx] = create_string_buffer(self._DECOY_SIZE)
        self._decoy_idx = (self._decoy_idx + 1) % N_DECOYS
        self._refresh_all_decoys(tick, epoch)

        self._last_write_time = perf_counter()
        self._scrub_event.set()   # start coherence countdown for new buffer

    def shared_address(self):     return addressof(self._active_buf)
    def decoy_addresses(self):    return [addressof(d) for d in self._decoys]
    def shared_size(self):        return self._buf_size
    def scrub_count(self):        return self._scrub_count
    def current_field_order(self): return list(self._field_order)
    def current_pad_sizes(self):  return list(self._pad_sizes)


# ── globals ───────────────────────────────────────────────────────────────
entityRegister = CoherenceWindowRegister()
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

        print(f"PID:              {os.getpid()}")
        print(f"VERSION:          5  (v1+v2+v3+v4 + coherence window)")
        print(f"COHERENCE_WINDOW: {COHERENCE_WINDOW_S*1000:.0f} ms")
        print(f"READER_INTERVAL:  500 ms  (10x the coherence window)")
        print(f"PAD_RANGE:        [{PAD_MIN}, {PAD_MAX}] bytes")
        print(f"N_DECOYS:         {N_DECOYS} (one rotated per epoch)")
        print(f"INITIAL_ADDR:     {entityRegister.shared_address()}")
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

                print(
                    f"[swap] tick={tick} epoch={epoch} "
                    f"real_addr={entityRegister.shared_address()} "
                    f"size={entityRegister.shared_size()}B "
                    f"window={COHERENCE_WINDOW_S*1000:.0f}ms "
                    f"scrubs={entityRegister.scrub_count()} "
                    f"order={[f for f,_ in entityRegister.current_field_order()]}"
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

    except KeyboardInterrupt:
        print('Keyboard interrupt — exiting.')
    finally:
        entityRegister.stop()
        sys.exit(0)


if __name__ == '__main__':
    gameinit()
    gameloop()
    input('Simulation complete. Press any key to exit...')
