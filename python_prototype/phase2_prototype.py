import sys
import os
import struct
from random import randint, randbytes, shuffle
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
VERSION           = 2          # bumped: v2 layout

PAD_MIN = 1
PAD_MAX = 16

HEADER_FMT  = '<IIIII'        # magic, version, tick, epoch, count
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# Canonical field descriptors: (field_name, byte_size)
FIELD_DEFS = [
    ('name', NAME_LEN),
    ('x',    4),
    ('y',    4),
]


# ── layout helpers ──────────────────────────────────────────────────────────
def random_field_order() -> list[tuple[str, int]]:
    """
    Return a shuffled copy of FIELD_DEFS.  The order of fields within each
    entity changes every epoch — e.g. [y, name, x] instead of [name, x, y].
    """
    order = list(FIELD_DEFS)
    shuffle(order)
    return order


def random_pad_sizes(n: int) -> list[int]:
    """One random pad size per field slot across all entities."""
    return [randint(PAD_MIN, PAD_MAX) for _ in range(n)]


def build_layout(field_order: list[tuple[str, int]], pad_sizes: list[int]) -> dict:
    """
    Build a complete offset map for MAX_ENTITIES entities given:
      - field_order : shuffled list of (field_name, size) for one entity
      - pad_sizes   : flat list of leading-pad sizes, length =
                      MAX_ENTITIES * len(field_order)

    Returns dict keyed by (entity_idx, field_name) -> byte offset from end
    of header.
    """
    offsets = {}
    cursor  = 0
    pad_idx = 0
    for entity_idx in range(MAX_ENTITIES):
        for field_name, field_size in field_order:
            cursor += pad_sizes[pad_idx]
            offsets[(entity_idx, field_name)] = cursor
            cursor += field_size
            pad_idx += 1
    return offsets


def build_shuffled_buffer(
    tick: int,
    epoch: int,
    entities: list,
    field_order: list[tuple[str, int]],
    pad_sizes: list[int],
) -> bytes:
    """
    Serialise the register with:
      1. clean 20-byte header (magic still findable)
      2. entity fields written in shuffled order with random noise padding
         between every field, entire entity region filled with randbytes first
    """
    header  = struct.pack(HEADER_FMT, MAGIC, VERSION, tick, epoch, MAX_ENTITIES)
    offsets = build_layout(field_order, pad_sizes)

    # Total entity region size
    total = sum(pad_sizes) + MAX_ENTITIES * sum(sz for _, sz in field_order)
    entity_region = bytearray(randbytes(total))

    for i, entity in enumerate(entities[:MAX_ENTITIES]):
        field_map = {
            'name': entity.name.encode()[:NAME_LEN].ljust(NAME_LEN, b'\x00'),
            'x':    struct.pack('<i', entity.x),
            'y':    struct.pack('<i', entity.y),
        }
        for field_name, field_size in field_order:
            off  = offsets[(i, field_name)]
            data = field_map[field_name]
            entity_region[off:off + field_size] = data

    return header + bytes(entity_region)


# ── domain model ───────────────────────────────────────────────────────────────
class Entity:
    def __init__(self, name: str, x: int, y: int):
        self.name = name
        self.x    = x
        self.y    = y

    def __repr__(self):
        return f'Entity(name={self.name}, x={self.x}, y={self.y})'

    def setx(self, x: int): self.x = x
    def sety(self, y: int): self.y = y


class EntityLogger:
    def __init__(self):
        self.logger = []

    def log(self, timestamp, tick, epoch, snapshot):
        self.logger.append((timestamp, tick, epoch, snapshot))

    def access_log(self) -> List:
        return self.logger


# ── v2 register ───────────────────────────────────────────────────────────────
class ShuffledEntityRegister:
    """
    Double-buffered register with both random noise padding (v1) AND
    randomized field ordering (v2).  Both the padding sizes and the field
    order are regenerated every epoch.

    A naive reader that assumes [name, x, y] order will read the wrong field
    type into each slot even if it somehow guesses the correct offsets.
    """

    _N_FIELDS = len(FIELD_DEFS)  # 3 fields per entity
    _MAX_BUF  = (
        HEADER_SIZE
        + MAX_ENTITIES * (NAME_LEN + 4 + 4)   # field data
        + MAX_ENTITIES * _N_FIELDS * PAD_MAX   # worst-case padding
        + 64                                   # safety margin
    )

    def __init__(self):
        self.register    = {}
        self._buf_a      = create_string_buffer(self._MAX_BUF)
        self._buf_b      = create_string_buffer(self._MAX_BUF)
        self._active     = self._buf_a
        self._backup     = self._buf_b
        self._field_order = random_field_order()
        self._pad_sizes  = random_pad_sizes(MAX_ENTITIES * self._N_FIELDS)
        self._buf_size   = 0

    def add(self, entity: Entity):
        self.register[entity.name] = entity

    def access_register(self):
        return self.register

    def snapshot(self):
        return deepcopy(self.register)

    def _write_buffer(self, buf, tick: int, epoch: int) -> int:
        data = build_shuffled_buffer(
            tick, epoch,
            list(self.register.values()),
            self._field_order,
            self._pad_sizes,
        )
        struct.pack_into(f'{len(buf)}s', buf, 0, b'\x00' * len(buf))
        struct.pack_into(f'{len(data)}s', buf, 0, data)
        return len(data)

    def sync_shared(self, tick: int, epoch: int):
        self._buf_size = self._write_buffer(self._active, tick, epoch)

    def swap_shared(self, tick: int, epoch: int):
        """Regenerate both field order AND pad sizes, write to backup, flip."""
        self._field_order = random_field_order()
        self._pad_sizes   = random_pad_sizes(MAX_ENTITIES * self._N_FIELDS)
        self._buf_size    = self._write_buffer(self._backup, tick, epoch)
        self._active, self._backup = self._backup, self._active

    def shared_address(self):
        return addressof(self._active)

    def shared_addresses(self):
        return {
            'active': addressof(self._active),
            'buf_a':  addressof(self._buf_a),
            'buf_b':  addressof(self._buf_b),
        }

    def shared_size(self):    return self._buf_size
    def current_pad_sizes(self): return list(self._pad_sizes)
    def current_field_order(self): return list(self._field_order)
    def current_offsets(self):
        return build_layout(self._field_order, self._pad_sizes)


# ── globals ───────────────────────────────────────────────────────────────
entityRegister = ShuffledEntityRegister()
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

        addrs = entityRegister.shared_addresses()
        print(f"PID:           {os.getpid()}")
        print(f"BUF_A_ADDR:    {addrs['buf_a']}")
        print(f"BUF_B_ADDR:    {addrs['buf_b']}")
        print(f"ACTIVE_ADDR:   {addrs['active']}  (starts as buf_a)")
        print(f"HEADER_SIZE:   {HEADER_SIZE}  (magic+version+tick+epoch+count)")
        print(f"VERSION:       2  (v1 padding + v2 field shuffle)")
        print(f"PAD_RANGE:     [{PAD_MIN}, {PAD_MAX}] bytes per gap")
        print(f"Initial order: {[f for f, _ in entityRegister.current_field_order()]}")
        print(f"Initial pads:  {entityRegister.current_pad_sizes()}")
        print(f"Initial offs:  {entityRegister.current_offsets()}")
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

                active_now = entityRegister.shared_address()
                label = 'A' if active_now == addrs['buf_a'] else 'B'
                order_str = str([f for f, _ in entityRegister.current_field_order()])
                print(
                    f"[swap] tick={tick} epoch={epoch} "
                    f"active=buf_{label} addr={active_now} "
                    f"size={entityRegister.shared_size()}B "
                    f"order={order_str} "
                    f"pads={entityRegister.current_pad_sizes()}"
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
