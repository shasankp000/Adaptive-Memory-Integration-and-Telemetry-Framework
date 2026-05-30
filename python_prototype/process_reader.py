import os
import sys
import struct
import time

MAGIC = 0xA11F
MAGIC_BYTES = struct.pack('<I', MAGIC)
SCAN_INTERVAL = 0.5   # seconds between each scan pass
SCAN_PASSES   = 20    # total number of scan passes

# Only accept exactly MAX_ENTITIES (2). Raise this only if you increase MAX_ENTITIES.
EXPECTED_COUNT = 2

HEADER_FMT  = '<IIIII'
ENTITY_FMT  = '<8sii'
HEADER_SIZE = struct.calcsize(HEADER_FMT)
ENTITY_SIZE = struct.calcsize(ENTITY_FMT)


class EntityStruct:
    def __init__(self, name, x, y):
        self.name = name
        self.x = x
        self.y = y

    def __repr__(self):
        return f"Entity(name={self.name}, x={self.x}, y={self.y})"


def parse_maps(maps_text):
    """
    Parse /proc/<pid>/maps and return only writable heap/stack regions (rw-p).
    Skips r--p (read-only file mappings) and r-xp (executable code sections)
    since ctypes structs allocated on the Python heap will only appear in rw-p.
    """
    regions = []
    for line in maps_text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        addr, perms = parts[0], parts[1]
        # Only scan private writable regions — heap, stack, anonymous mmap
        if perms != 'rw-p':
            continue
        start_s, end_s = addr.split('-')
        start = int(start_s, 16)
        end   = int(end_s,   16)
        regions.append((start, end, perms))
    return regions


def decode_register(block):
    """
    Decode a raw bytes block into a register dict.
    Returns None if the block fails any sanity check:
    - wrong magic
    - wrong version
    - count != EXPECTED_COUNT (exact match, not a range)
    - buffer too small for the declared entity count
    """
    if len(block) < HEADER_SIZE:
        return None

    magic, version, tick, epoch, count = struct.unpack_from(HEADER_FMT, block, 0)

    if magic != MAGIC:
        return None
    if version != 1:
        return None
    # Exact count check — eliminates false positives from colliding magic bytes
    if count != EXPECTED_COUNT:
        return None

    required_size = HEADER_SIZE + count * ENTITY_SIZE
    if len(block) < required_size:
        return None

    offset = HEADER_SIZE
    entities = []
    for _ in range(count):
        name_b, x, y = struct.unpack_from(ENTITY_FMT, block, offset)
        name = name_b.split(b'\x00', 1)[0].decode(errors='ignore')
        entities.append(EntityStruct(name, x, y))
        offset += ENTITY_SIZE

    return {
        'magic':    magic,
        'version':  version,
        'tick':     tick,
        'epoch':    epoch,
        'count':    count,
        'entities': entities,
    }


def scan_once(target_pid, regions):
    """Scan /proc/<pid>/mem once and return ALL valid matching structs found."""
    results = []
    block_size = HEADER_SIZE + EXPECTED_COUNT * ENTITY_SIZE

    with open(f'/proc/{target_pid}/mem', 'rb', buffering=0) as mem:
        for start, end, perms in regions:
            try:
                mem.seek(start)
                chunk = mem.read(end - start)
            except Exception:
                continue

            search_start = 0
            while True:
                idx = chunk.find(MAGIC_BYTES, search_start)
                if idx == -1:
                    break

                block = chunk[idx:idx + block_size]
                reg = decode_register(block)
                if reg is not None:
                    results.append((start + idx, perms, reg))

                search_start = idx + 1

    return results


def main():
    target_pid = int(input('Enter target process pid: '))

    if not os.path.exists(f'/proc/{target_pid}'):
        print('Error! Process does not exist or entered PID is incorrect')
        sys.exit(0)

    prev_addresses = set()

    print(f"\nStarting {SCAN_PASSES} scan passes, {SCAN_INTERVAL}s apart...")
    print(f"Scanning only rw-p regions | expected count={EXPECTED_COUNT}\n")

    for pass_num in range(1, SCAN_PASSES + 1):
        try:
            with open(f'/proc/{target_pid}/maps', 'r') as f:
                target_maps = f.read()
        except FileNotFoundError:
            print(f"[pass {pass_num:02d}] Process {target_pid} no longer exists. Stopping.")
            break

        regions = parse_maps(target_maps)
        results = scan_once(target_pid, regions)

        if not results:
            print(f"[pass {pass_num:02d}] No valid struct found.")
        else:
            current_addresses = {addr for addr, _, _ in results}
            new_addrs  = current_addresses - prev_addresses
            gone_addrs = prev_addresses   - current_addresses

            for addr, perms, reg in results:
                tag = "  <-- NEW ADDR (swap detected!)" if addr in new_addrs else ""
                print(
                    f"[pass {pass_num:02d}] 0x{addr:x} ({perms}){tag}"
                    f"  tick={reg['tick']} epoch={reg['epoch']}"
                    f"  entities: {reg['entities']}"
                )

            for old in gone_addrs:
                print(f"[pass {pass_num:02d}]           0x{old:x}  <-- gone (buffer rotated out)")

            prev_addresses = current_addresses

        time.sleep(SCAN_INTERVAL)

    print("\nScan complete.")


if __name__ == '__main__':
    main()
