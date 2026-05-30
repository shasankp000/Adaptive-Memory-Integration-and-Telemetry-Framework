import sys
import os
import struct
from random import randint, randbytes
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
VERSION           = 1

# Padding range per gap (bytes). Reader has no way to know these.
PAD_MIN = 1
PAD_MAX = 16

HEADER_FMT = '<IIIII'          # magic, version, tick, epoch, count
HEADER_SIZE = struct.calcsize(HEADER_FMT)


# ── offset map ───────────────────────────────────────────────────────────────
def make_offset_map(pad_sizes: list[int]) -> dict:
    """
    Given a flat list of 6 padding sizes (one before each of the 6 entity
    fields across 2 entities: name0, x0, y0, name1, x1, y1), return a dict
    mapping field keys to their byte offsets from the START of the entity
    data region (i.e. after the 20-byte header).

    Layout per entity (repeated for each entity i):
        [pad] [name 8B] [pad] [x 4B] [pad] [y 4B]
    """
    offsets = {}
    cursor = 0
    field_defs = [
        ('name', 0, NAME_LEN),
        ('x',    0, 4),
        ('y',    0, 4),
        ('name', 1, NAME_LEN),
        ('x',    1, 4),
        ('y',    1, 4),
    ]
    for idx, (field, entity_idx, size) in enumerate(field_defs):
        cursor += pad_sizes[idx]          # skip leading pad
        offsets[(entity_idx, field)] = cursor
        cursor += size
    return offsets


def random_pad_sizes() -> list[int]:
    return [randint(PAD_MIN, PAD_MAX) for _ in range(6)]


def build_fragmented_buffer(
    tick: int,
    epoch: int,
    entities: list,
    pad_sizes: list[int],
) -> bytes:
    """
    Serialise the register into a raw byte buffer with random noise padding
    between every entity field.  The header is packed cleanly so the magic
    bytes are still findable by a scanner; everything after offset 20 is
    deliberately fragmented.
    """
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, tick, epoch, MAX_ENTITIES)

    offsets = make_offset_map(pad_sizes)

    # Calculate total size of entity data region
    total_entity_bytes = 0
    for idx, (field, entity_idx, size) in enumerate([
        ('name', 0, NAME_LEN), ('x', 0, 4), ('y', 0, 4),
        ('name', 1, NAME_LEN), ('x', 1, 4), ('y', 1, 4),
    ]):
        total_entity_bytes += pad_sizes[idx] + size

    # Build entity region as a mutable bytearray filled with random noise
    entity_region = bytearray(randbytes(total_entity_bytes))

    # Stamp real field values at their correct (secret) offsets
    for i, entity in enumerate(entities[:MAX_ENTITIES]):
        name_off = offsets[(i, 'name')]
        x_off    = offsets[(i, 'x')]
        y_off    = offsets[(i, 'y')]

        name_bytes = entity.name.encode()[:NAME_LEN]
        name_bytes = name_bytes.ljust(NAME_LEN, b'\x00')
        entity_region[name_off:name_off + NAME_LEN] = name_bytes
        entity_region[x_off:x_off + 4] = struct.pack('<i', entity.x)
        entity_region[y_off:y_off + 4] = struct.pack('<i', entity.y)

    return header + bytes(entity_region)


# ── domain model (unchanged) ──────────────────────────────────────────────
class Entity:
    def __init__(self, name: str, x: int, y: int):
        self.name = name
        self.x = x
        self.y = y

    def __repr__(self):
        return f"Entity(name={self.name}, x={self.x}, y={self.y})"

    def setx(self, x: int): self.x = x
    def sety(self, y: int): self.y = y


class EntityLogger:
    def __init__(self):
        self.logger = []

    def log(self, timestamp, tick, epoch, snapshot):
        self.logger.append((timestamp, tick, epoch, snapshot))

    def access_log(self) -> List:
        return self.logger


# ── fragmented register ───────────────────────────────────────────────────
class FragmentedEntityRegister:
    """
    Double-buffered register whose shared memory representation uses random
    noise padding between every entity field.  Pad sizes are regenerated
    every epoch, so the struct layout is different each time.
    """

    # Fixed-size backing buffers large enough for max padding scenario.
    # MAX_ENTITIES * (3 fields) * (NAME_LEN or 4) + 6 * PAD_MAX + HEADER
    _MAX_BUF = HEADER_SIZE + MAX_ENTITIES * (NAME_LEN + 4 + 4) + 6 * PAD_MAX + 64

    def __init__(self):
        self.register   = {}
        self._buf_a     = create_string_buffer(self._MAX_BUF)
        self._buf_b     = create_string_buffer(self._MAX_BUF)
        self._active    = self._buf_a
        self._backup    = self._buf_b
        self._pad_sizes = random_pad_sizes()
        self._buf_size  = 0   # actual written size this epoch

    def add(self, entity: Entity):
        self.register[entity.name] = entity

    def access_register(self):
        return self.register

    def snapshot(self):
        return deepcopy(self.register)

    def _write_buffer(self, buf, tick: int, epoch: int):
        data = build_fragmented_buffer(
            tick, epoch,
            list(self.register.values()),
            self._pad_sizes,
        )
        # Zero out old contents then write new
        struct.pack_into(f'{len(buf)}s', buf, 0, b'\x00' * len(buf))
        struct.pack_into(f'{len(data)}s', buf, 0, data)
        return len(data)

    def sync_shared(self, tick: int, epoch: int):
        self._buf_size = self._write_buffer(self._active, tick, epoch)

    def swap_shared(self, tick: int, epoch: int):
        """Regenerate pad sizes for this epoch, write to backup, then flip."""
        self._pad_sizes = random_pad_sizes()
        self._buf_size  = self._write_buffer(self._backup, tick, epoch)
        self._active, self._backup = self._backup, self._active

    def shared_address(self):
        return addressof(self._active)

    def shared_addresses(self):
        return {
            'active':   addressof(self._active),
            'buf_a':    addressof(self._buf_a),
            'buf_b':    addressof(self._buf_b),
        }

    def shared_size(self):
        return self._buf_size

    def current_pad_sizes(self):
        return list(self._pad_sizes)

    def current_offsets(self):
        return make_offset_map(self._pad_sizes)


# ── globals ───────────────────────────────────────────────────────────────
entityRegister = FragmentedEntityRegister()
entityLogger   = EntityLogger()


def gameinit():
    e1 = Entity('CT1', randint(0, 9), randint(0, 9))
    e2 = Entity('T1',  randint(0, 9), randint(0, 9))
    entityRegister.add(e1)
    entityRegister.add(e2)
    entityRegister.sync_shared(0, 0)


def gameloop():
    try:
        second_counter  = 0
        current_second  = 0
        tick            = 0
        epoch           = 0
        i               = 0

        addrs = entityRegister.shared_addresses()
        print(f"PID:          {os.getpid()}")
        print(f"BUF_A_ADDR:   {addrs['buf_a']}")
        print(f"BUF_B_ADDR:   {addrs['buf_b']}")
        print(f"ACTIVE_ADDR:  {addrs['active']}  (starts as buf_a)")
        print(f"HEADER_SIZE:  {HEADER_SIZE}  (magic+version+tick+epoch+count)")
        print(f"PAD_RANGE:    [{PAD_MIN}, {PAD_MAX}] bytes per gap — changes every epoch")
        print(f"Initial pads: {entityRegister.current_pad_sizes()}")
        print(f"Initial offs: {entityRegister.current_offsets()}  (relative to end of header)")
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
                print(
                    f"[swap] tick={tick} epoch={epoch} "
                    f"active=buf_{label} addr={active_now} "
                    f"size={entityRegister.shared_size()}B "
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
