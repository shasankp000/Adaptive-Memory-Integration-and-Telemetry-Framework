import sys
import os
import struct
from random import randint, randbytes, shuffle, choice
from typing import List
from copy import deepcopy
from datetime import datetime
from time import sleep
from ctypes import create_string_buffer, addressof

# ── constants ────────────────────────────────────────────────────────────────
EPOCH_UPDATE_RULE = 1
MAX_ENTITIES      = 2
NAME_LEN          = 8
MAGIC             = 0xA11F
VERSION           = 4

PAD_MIN  = 1
PAD_MAX  = 16
N_DECOYS = 4

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


# ── layout helpers (v2/v3 identical) ─────────────────────────────────────────
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


# ── v4 register ───────────────────────────────────────────────────────────────
class RelocatingEntityRegister:
    """
    v3 + epoch relocation.

    Every swap_shared() call:
      1. Allocates a brand-new ctypes buffer for the next active slot.
      2. Writes the real (fragmented + shuffled) data into it.
      3. Drops the reference to the OLD active buffer — the OS reclaims
         its memory, the address disappears from /proc/pid/maps.
      4. Rotates the decoy pool: retire one old decoy, allocate one new one
         at a fresh address, so the decoy address set also churns.

    Effect on reader:
      - Real buffer address changes every epoch — no stable ghost address.
      - Decoy addresses rotate so a reader that builds a list of "known"
        addresses will have stale entries that disappear and new ones it
        hasn’t seen before appearing, making it impossible to build a reliable
        allowlist or blocklist.
    """

    _N_FIELDS    = len(FIELD_DEFS)
    _REAL_MAX_BUF = (
        HEADER_SIZE
        + MAX_ENTITIES * (NAME_LEN + 4 + 4)
        + MAX_ENTITIES * _N_FIELDS * PAD_MAX
        + 64
    )
    _DECOY_SIZE = HEADER_SIZE + MAX_ENTITIES * (NAME_LEN + 4 + 4)

    def __init__(self):
        self.register     = {}
        # Real buffer: single live allocation, replaced each epoch
        self._active_buf  = create_string_buffer(self._REAL_MAX_BUF)
        self._field_order = random_field_order()
        self._pad_sizes   = random_pad_sizes(MAX_ENTITIES * self._N_FIELDS)
        self._buf_size    = 0
        # Decoy pool: N_DECOYS live allocations, one rotated per epoch
        self._decoys      = [
            create_string_buffer(self._DECOY_SIZE) for _ in range(N_DECOYS)
        ]
        self._decoy_idx   = 0   # index of next decoy to rotate

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
        """Initial write — no relocation yet."""
        self._buf_size = self._write_real(self._active_buf, tick, epoch)
        self._refresh_all_decoys(tick, epoch)

    def swap_shared(self, tick, epoch):
        """
        Relocate: allocate new buffer, write new data, drop old buffer.
        Also rotate one decoy slot to a new allocation.
        """
        self._field_order = random_field_order()
        self._pad_sizes   = random_pad_sizes(MAX_ENTITIES * self._N_FIELDS)

        # Allocate fresh real buffer at a new heap address
        new_buf          = create_string_buffer(self._REAL_MAX_BUF)
        self._buf_size   = self._write_real(new_buf, tick, epoch)
        self._active_buf = new_buf   # old buffer dereferenced → GC-eligible

        # Rotate one decoy: replace it with a new allocation
        self._decoys[self._decoy_idx] = create_string_buffer(self._DECOY_SIZE)
        self._decoy_idx = (self._decoy_idx + 1) % N_DECOYS

        # Refresh all decoy contents
        self._refresh_all_decoys(tick, epoch)

    def shared_address(self):    return addressof(self._active_buf)
    def decoy_addresses(self):   return [addressof(d) for d in self._decoys]
    def shared_size(self):        return self._buf_size
    def current_pad_sizes(self):  return list(self._pad_sizes)
    def current_field_order(self): return list(self._field_order)


# ── globals ───────────────────────────────────────────────────────────────
entityRegister = RelocatingEntityRegister()
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

        print(f"PID:           {os.getpid()}")
        print(f"INITIAL_ADDR:  {entityRegister.shared_address()}")
        print(f"INITIAL_DECOYS:{entityRegister.decoy_addresses()}")
        print(f"VERSION:       4  (v1+v2+v3 + epoch relocation)")
        print(f"PAD_RANGE:     [{PAD_MIN}, {PAD_MAX}] bytes per gap")
        print(f"N_DECOYS:      {N_DECOYS} (one rotated per epoch)")
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
                    f"order={[f for f,_ in entityRegister.current_field_order()]} "
                    f"decoys={entityRegister.decoy_addresses()}"
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
        sys.exit(0)


if __name__ == '__main__':
    gameinit()
    gameloop()
    input('Simulation complete. Press any key to exit...')
