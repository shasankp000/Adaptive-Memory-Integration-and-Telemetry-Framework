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
VERSION           = 3          # bumped: v3 layout

PAD_MIN    = 1
PAD_MAX    = 16
N_DECOYS   = 4   # number of fake registers injected per epoch

HEADER_FMT  = '<IIIII'
HEADER_SIZE = struct.calcsize(HEADER_FMT)

FIELD_DEFS = [
    ('name', NAME_LEN),
    ('x',    4),
    ('y',    4),
]

# Plausible-looking decoy names — chosen to look like real entity names
# so a reader that filters by name string still can't easily dismiss them.
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


# ── layout helpers (identical to v2) ───────────────────────────────────────
def random_field_order() -> list[tuple[str, int]]:
    order = list(FIELD_DEFS)
    shuffle(order)
    return order


def random_pad_sizes(n: int) -> list[int]:
    return [randint(PAD_MIN, PAD_MAX) for _ in range(n)]


def build_layout(
    field_order: list[tuple[str, int]],
    pad_sizes: list[int],
    n_entities: int = MAX_ENTITIES,
) -> dict:
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


def build_shuffled_buffer(
    tick: int,
    epoch: int,
    entities: list,
    field_order: list[tuple[str, int]],
    pad_sizes: list[int],
    version: int = VERSION,
) -> bytes:
    header  = struct.pack(HEADER_FMT, MAGIC, version, tick, epoch, MAX_ENTITIES)
    offsets = build_layout(field_order, pad_sizes)
    total   = sum(pad_sizes) + MAX_ENTITIES * sum(sz for _, sz in field_order)
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


# ── decoy builder ──────────────────────────────────────────────────────────────
def build_decoy_buffer(tick: int, epoch: int) -> bytes:
    """
    Build a single decoy register buffer.

    A decoy has:
    - valid magic (0xA11F) so the reader's scanner finds it
    - valid version field (VERSION) so the version check passes
    - valid count=2 so the count check passes
    - plausible-looking entity names from DECOY_NAME_POOL
    - coordinates in [0, 9] just like real entities
    - the entities are written at the PACKED offset (no padding, no shuffle)
      so that the naive reader's fixed-offset decode actually SUCCEEDS and
      returns a plausible-looking result — indistinguishable from real data

    This is the key difference from the real struct: decoys are EASY to read
    but semantically wrong. The reader gets confident garbage.
    """
    # Decoy entities written packed at fixed offsets — reader will decode them cleanly
    decoy_entity_fmt = f'<{NAME_LEN}sii'
    entities_bytes   = b''
    for _ in range(MAX_ENTITIES):
        name  = choice(DECOY_NAME_POOL)
        x     = randint(0, 9)
        y     = randint(0, 9)
        entities_bytes += struct.pack(decoy_entity_fmt, name, x, y)

    header = struct.pack(HEADER_FMT, MAGIC, VERSION, tick, epoch, MAX_ENTITIES)
    return header + entities_bytes


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


# ── v3 register ───────────────────────────────────────────────────────────────
class DecoyEntityRegister:
    """
    v2 register + N_DECOYS fake registers injected into the heap.

    Decoys are:
    - allocated as separate ctypes buffers (distinct heap addresses)
    - written with valid magic + version + count so the reader finds them
    - packed at fixed offsets so the reader decodes them successfully
    - populated with plausible names and coordinates in [0,9]
    - refreshed every epoch with new names and coordinates

    The real register uses v1+v2 (fragmented + shuffled) so the reader
    can't find it. The decoys are intentionally easy to find and decode
    so the reader gets N_DECOYS confident-looking but wrong results.
    """

    _N_FIELDS = len(FIELD_DEFS)
    _REAL_MAX_BUF = (
        HEADER_SIZE
        + MAX_ENTITIES * (NAME_LEN + 4 + 4)
        + MAX_ENTITIES * _N_FIELDS * PAD_MAX
        + 64
    )
    _DECOY_BUF_SIZE = HEADER_SIZE + MAX_ENTITIES * (NAME_LEN + 4 + 4)  # packed

    def __init__(self):
        self.register     = {}
        # Real double-buffer
        self._buf_a       = create_string_buffer(self._REAL_MAX_BUF)
        self._buf_b       = create_string_buffer(self._REAL_MAX_BUF)
        self._active      = self._buf_a
        self._backup      = self._buf_b
        self._field_order = random_field_order()
        self._pad_sizes   = random_pad_sizes(MAX_ENTITIES * self._N_FIELDS)
        self._buf_size    = 0
        # Decoy buffers — fixed size, always packed
        self._decoys      = [
            create_string_buffer(self._DECOY_BUF_SIZE)
            for _ in range(N_DECOYS)
        ]

    def add(self, entity: Entity):
        self.register[entity.name] = entity

    def access_register(self):
        return self.register

    def snapshot(self):
        return deepcopy(self.register)

    def _write_real(self, buf, tick: int, epoch: int) -> int:
        data = build_shuffled_buffer(
            tick, epoch,
            list(self.register.values()),
            self._field_order,
            self._pad_sizes,
        )
        struct.pack_into(f'{len(buf)}s', buf, 0, b'\x00' * len(buf))
        struct.pack_into(f'{len(data)}s', buf, 0, data)
        return len(data)

    def _refresh_decoys(self, tick: int, epoch: int):
        for dbuf in self._decoys:
            data = build_decoy_buffer(tick, epoch)
            struct.pack_into(f'{len(dbuf)}s', dbuf, 0, data)

    def sync_shared(self, tick: int, epoch: int):
        self._buf_size = self._write_real(self._active, tick, epoch)
        self._refresh_decoys(tick, epoch)

    def swap_shared(self, tick: int, epoch: int):
        self._field_order = random_field_order()
        self._pad_sizes   = random_pad_sizes(MAX_ENTITIES * self._N_FIELDS)
        self._buf_size    = self._write_real(self._backup, tick, epoch)
        self._active, self._backup = self._backup, self._active
        self._refresh_decoys(tick, epoch)

    def shared_address(self):    return addressof(self._active)
    def shared_addresses(self):
        return {
            'active': addressof(self._active),
            'buf_a':  addressof(self._buf_a),
            'buf_b':  addressof(self._buf_b),
        }
    def decoy_addresses(self):   return [addressof(d) for d in self._decoys]
    def shared_size(self):        return self._buf_size
    def current_pad_sizes(self):  return list(self._pad_sizes)
    def current_field_order(self): return list(self._field_order)
    def current_offsets(self):
        return build_layout(self._field_order, self._pad_sizes)


# ── globals ───────────────────────────────────────────────────────────────
entityRegister = DecoyEntityRegister()
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
        decoy_addrs = entityRegister.decoy_addresses()
        print(f"PID:            {os.getpid()}")
        print(f"BUF_A_ADDR:     {addrs['buf_a']}")
        print(f"BUF_B_ADDR:     {addrs['buf_b']}")
        print(f"ACTIVE_ADDR:    {addrs['active']}  (starts as buf_a)")
        print(f"DECOY_ADDRS:    {decoy_addrs}")
        print(f"N_DECOYS:       {N_DECOYS}")
        print(f"VERSION:        3  (v1 padding + v2 shuffle + v3 decoys)")
        print(f"PAD_RANGE:      [{PAD_MIN}, {PAD_MAX}] bytes per gap")
        print(f"Initial order:  {[f for f, _ in entityRegister.current_field_order()]}")
        print(f"Initial pads:   {entityRegister.current_pad_sizes()}")
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
                    f"active=buf_{label} size={entityRegister.shared_size()}B "
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
