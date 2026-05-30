import os
import sys
import struct
import time

MAGIC = 0xA11F
MAGIC_BYTES = struct.pack('<I', MAGIC)
SCAN_INTERVAL = 0.5   # seconds between each scan pass
SCAN_PASSES   = 20    # total number of scan passes

class EntityStruct:
    def __init__(self, name, x, y):
        self.name = name
        self.x = x
        self.y = y

    def __repr__(self):
        return f"Entity(name={self.name}, x={self.x}, y={self.y})"


def parse_maps(maps_text):
    regions = []
    for line in maps_text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        addr, perms = parts[0], parts[1]
        if 'r' not in perms:
            continue
        start_s, end_s = addr.split('-')
        start = int(start_s, 16)
        end = int(end_s, 16)
        regions.append((start, end, perms))
    return regions


def decode_register(block):
    header_fmt = '<IIIII'
    entity_fmt = '<8sii'
    header_size = struct.calcsize(header_fmt)
    entity_size = struct.calcsize(entity_fmt)
    magic, version, tick, epoch, count = struct.unpack_from(header_fmt, block, 0)
    offset = header_size
    entities = []
    for _ in range(count):
        name_b, x, y = struct.unpack_from(entity_fmt, block, offset)
        name = name_b.split(b'\x00', 1)[0].decode(errors='ignore')
        entities.append(EntityStruct(name, x, y))
        offset += entity_size
    return {
        'magic': magic,
        'version': version,
        'tick': tick,
        'epoch': epoch,
        'count': count,
        'entities': entities,
    }


def scan_once(target_pid, regions, struct_size):
    """Scan /proc/<pid>/mem once and return ALL matching structs found."""
    results = []
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
                if idx == -1 or idx + struct_size > len(chunk):
                    break
                block = chunk[idx:idx + struct_size]
                reg = decode_register(block)
                results.append((start + idx, perms, reg))
                search_start = idx + 1
    return results


def main():
    target_pid = int(input('Enter target process pid: '))

    if not os.path.exists(f'/proc/{target_pid}'):
        print('Error! Process does not exist or entered PID is incorrect')
        sys.exit(0)

    struct_size = struct.calcsize('<IIIII') + 2 * struct.calcsize('<8sii')

    prev_addresses = set()

    print(f"\nStarting {SCAN_PASSES} scan passes, {SCAN_INTERVAL}s apart...\n")

    for pass_num in range(1, SCAN_PASSES + 1):
        # Re-read maps each pass since active address may change
        try:
            with open(f'/proc/{target_pid}/maps', 'r') as f:
                target_maps = f.read()
        except FileNotFoundError:
            print(f"[pass {pass_num}] Process {target_pid} no longer exists. Stopping.")
            break

        regions = parse_maps(target_maps)
        results = scan_once(target_pid, regions, struct_size)

        if not results:
            print(f"[pass {pass_num:02d}] No struct found.")
        else:
            current_addresses = {addr for addr, _, _ in results}
            new_addrs = current_addresses - prev_addresses
            gone_addrs = prev_addresses - current_addresses

            for addr, perms, reg in results:
                tag = " <-- NEW ADDR (swap detected!)" if addr in new_addrs else ""
                print(
                    f"[pass {pass_num:02d}] 0x{addr:x} ({perms}){tag}  "
                    f"tick={reg['tick']} epoch={reg['epoch']}  "
                    f"entities: {reg['entities']}"
                )

            if gone_addrs:
                for old in gone_addrs:
                    print(f"[pass {pass_num:02d}]           0x{old:x} no longer seen (buffer rotated out)")

            prev_addresses = current_addresses

        time.sleep(SCAN_INTERVAL)

    print("\nScan complete.")


if __name__ == '__main__':
    main()
