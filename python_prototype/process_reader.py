import os
import sys
import struct

MAGIC = 0xA11F
MAGIC_BYTES = struct.pack('<I', MAGIC)

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


def main():
    target_pid = int(input('Enter target process pid: '))

    if not os.path.exists(f'/proc/{target_pid}'):
        print('Error! Process does not exist or entered PID is incorrect')
        sys.exit(0)

    with open(f'/proc/{target_pid}/maps', 'r') as f:
        target_maps = f.read()

    regions = parse_maps(target_maps)
    struct_size = struct.calcsize('<IIIII') + 2 * struct.calcsize('<8sii')

    with open(f'/proc/{target_pid}/mem', 'rb', buffering=0) as mem:
        found = False
        for start, end, perms in regions:
            try:
                mem.seek(start)
                chunk = mem.read(end - start)
            except Exception:
                continue
            idx = chunk.find(MAGIC_BYTES)
            if idx != -1 and idx + struct_size <= len(chunk):
                block = chunk[idx:idx + struct_size]
                reg = decode_register(block)
                print(f"Found at 0x{start + idx:x} in region {perms}")
                print(f"magic=0x{reg['magic']:x} version={reg['version']} tick={reg['tick']} epoch={reg['epoch']} count={reg['count']}")
                for e in reg['entities']:
                    print(e)
                found = True
                break

        if not found:
            print('Struct not found')


if __name__ == '__main__':
    main()
