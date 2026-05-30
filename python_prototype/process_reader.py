import os
import sys
import struct
import time

MAGIC = 0xA11F
MAGIC_BYTES = struct.pack('<I', MAGIC)
SCAN_INTERVAL  = 0.5
SCAN_PASSES    = 20
EXPECTED_COUNT = 2

HEADER_FMT  = '<IIIII'
ENTITY_FMT  = '<8sii'    # naive: assumes packed, no padding
HEADER_SIZE = struct.calcsize(HEADER_FMT)
ENTITY_SIZE = struct.calcsize(ENTITY_FMT)


class EntityStruct:
    def __init__(self, name, x, y):
        self.name = name
        self.x    = x
        self.y    = y

    def __repr__(self):
        return f'Entity(name={self.name}, x={self.x}, y={self.y})'


def parse_maps(maps_text):
    regions = []
    for line in maps_text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        addr, perms = parts[0], parts[1]
        if perms != 'rw-p':
            continue
        start_s, end_s = addr.split('-')
        regions.append((int(start_s, 16), int(end_s, 16), perms))
    return regions


def decode_register(block):
    if len(block) < HEADER_SIZE:
        return None
    magic, version, tick, epoch, count = struct.unpack_from(HEADER_FMT, block, 0)
    if magic != MAGIC or version != 1 or count != EXPECTED_COUNT:
        return None
    required = HEADER_SIZE + count * ENTITY_SIZE
    if len(block) < required:
        return None
    offset   = HEADER_SIZE
    entities = []
    for _ in range(count):
        name_b, x, y = struct.unpack_from(ENTITY_FMT, block, offset)
        name = name_b.split(b'\x00', 1)[0].decode(errors='ignore')
        entities.append(EntityStruct(name, x, y))
        offset += ENTITY_SIZE
    return {'magic': magic, 'version': version, 'tick': tick,
            'epoch': epoch, 'count': count, 'entities': entities}


def scan_once(target_pid, regions):
    results   = []
    block_size = HEADER_SIZE + EXPECTED_COUNT * ENTITY_SIZE
    with open(f'/proc/{target_pid}/mem', 'rb', buffering=0) as mem:
        for start, end, perms in regions:
            try:
                mem.seek(start)
                chunk = mem.read(end - start)
            except Exception:
                continue
            pos = 0
            while True:
                idx = chunk.find(MAGIC_BYTES, pos)
                if idx == -1:
                    break
                block = chunk[idx:idx + block_size]
                reg   = decode_register(block)
                if reg is not None:
                    results.append((start + idx, perms, reg))
                pos = idx + 1
    return results


def main():
    target_pid = int(input('Enter target process pid: '))
    if not os.path.exists(f'/proc/{target_pid}'):
        print('Process not found.')
        sys.exit(0)

    prev_addresses = set()
    print(f'\nStarting {SCAN_PASSES} scan passes, {SCAN_INTERVAL}s apart...')
    print(f'Scanning rw-p regions only | expected count={EXPECTED_COUNT}')
    print('NOTE: reader is NAIVE — no knowledge of padding. Expect garbage.\n')

    for pass_num in range(1, SCAN_PASSES + 1):
        try:
            with open(f'/proc/{target_pid}/maps') as f:
                maps = f.read()
        except FileNotFoundError:
            print(f'[pass {pass_num:02d}] Process gone. Stopping.')
            break

        regions = parse_maps(maps)
        results = scan_once(target_pid, regions)

        if not results:
            print(f'[pass {pass_num:02d}] No struct found.')
        else:
            cur  = {addr for addr, _, _ in results}
            new  = cur - prev_addresses
            gone = prev_addresses - cur

            for addr, perms, reg in results:
                tag = '  <-- NEW' if addr in new else ''
                print(
                    f'[pass {pass_num:02d}] 0x{addr:x} ({perms}){tag}'
                    f'  tick={reg["tick"]} epoch={reg["epoch"]}'
                    f'  entities: {reg["entities"]}'
                )
            for old in gone:
                print(f'[pass {pass_num:02d}]           0x{old:x}  <-- gone')
            prev_addresses = cur

        time.sleep(SCAN_INTERVAL)

    print('\nScan complete.')


if __name__ == '__main__':
    main()
