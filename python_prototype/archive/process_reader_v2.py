import os
import sys
import struct
import time
import math
from collections import defaultdict

# ── constants (must match prototype) ───────────────────────────────────────────────
MAGIC          = 0xA11F
MAGIC_BYTES    = struct.pack('<I', MAGIC)
SCAN_INTERVAL  = 0.5
SCAN_PASSES    = 20
EXPECTED_COUNT = 2
COORD_MIN      = 0
COORD_MAX      = 9

HEADER_FMT  = '<IIIII'
ENTITY_FMT  = '<8sii'
HEADER_SIZE = struct.calcsize(HEADER_FMT)
ENTITY_SIZE = struct.calcsize(ENTITY_FMT)

# Scoring weights
W_COORD_CLEAN   = 30   # both entities have coords in [0,9]
W_EPOCH_INC     = 25   # epoch incremented since last seen at this address
W_STABILITY     = 20   # survived N consecutive passes (5 pts per pass, cap 20)
W_COORD_PARTIAL = 10   # at least one entity has coords in range
W_EPOCH_FROZEN  = -40  # epoch never changed across 2+ passes — strong noise signal
W_WILD_COORDS   = -30  # all entities have at least one coord wildly out of range

FROZEN_PENALTY_PASSES = 2   # how many passes of no epoch change triggers FROZEN penalty
STABILITY_PER_PASS   = 5
STABILITY_CAP        = 20


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
    if magic != MAGIC or count != EXPECTED_COUNT:
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
    results    = []
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


def coords_in_range(entities):
    """Count how many entities have both coords cleanly in [COORD_MIN, COORD_MAX]."""
    clean = sum(
        1 for e in entities
        if COORD_MIN <= e.x <= COORD_MAX and COORD_MIN <= e.y <= COORD_MAX
    )
    return clean


def score_candidate(addr, reg, history):
    """
    Compute a heuristic confidence score for a candidate hit.

    history[addr] = {
        'passes':       int,          # consecutive passes this addr has been seen
        'last_epoch':   int or None,  # epoch value at previous pass
        'frozen_count': int,          # passes where epoch did not change
    }

    Returns (score: int, reasons: list[str])
    """
    score   = 0
    reasons = []
    entities = reg['entities']
    n = len(entities)

    # — coordinate range check —
    clean = coords_in_range(entities)
    if clean == n:
        score += W_COORD_CLEAN
        reasons.append(f'coords_clean(+{W_COORD_CLEAN})')
    elif clean > 0:
        score += W_COORD_PARTIAL
        reasons.append(f'coords_partial(+{W_COORD_PARTIAL})')
    else:
        score += W_WILD_COORDS
        reasons.append(f'wild_coords({W_WILD_COORDS})')

    if addr in history:
        h = history[addr]

        # — epoch increment check —
        if h['last_epoch'] is not None:
            if reg['epoch'] != h['last_epoch']:
                score += W_EPOCH_INC
                reasons.append(f'epoch_inc(+{W_EPOCH_INC})')
                h['frozen_count'] = 0
            else:
                h['frozen_count'] += 1
                if h['frozen_count'] >= FROZEN_PENALTY_PASSES:
                    score += W_EPOCH_FROZEN
                    reasons.append(f'epoch_frozen({W_EPOCH_FROZEN})')

        # — address stability bonus —
        stability_bonus = min(h['passes'] * STABILITY_PER_PASS, STABILITY_CAP)
        score += stability_bonus
        if stability_bonus > 0:
            reasons.append(f'stability(+{stability_bonus}, {h["passes"]} passes)')
    else:
        reasons.append('first_seen')

    return score, reasons


def update_history(history, addr, reg):
    if addr not in history:
        history[addr] = {'passes': 1, 'last_epoch': reg['epoch'], 'frozen_count': 0}
    else:
        history[addr]['passes']     += 1
        history[addr]['last_epoch']  = reg['epoch']


def main():
    target_pid = int(input('Enter target process pid: '))
    if not os.path.exists(f'/proc/{target_pid}'):
        print('Process not found.')
        sys.exit(0)

    print(f'\nStarting {SCAN_PASSES} scan passes, {SCAN_INTERVAL}s apart...')
    print(f'Scanning rw-p regions only | expected count={EXPECTED_COUNT}')
    print('NOTE: reader is HEURISTIC — applies epoch, coord, and stability scoring.\n')
    print(f'  Score guide: >={W_COORD_CLEAN + W_EPOCH_INC} = high confidence | '
          f'{W_COORD_CLEAN}..{W_COORD_CLEAN+W_EPOCH_INC-1} = medium | '
          f'<{W_COORD_CLEAN} = low / noise\n')

    prev_addresses = set()
    history        = {}   # addr -> {passes, last_epoch, frozen_count}
    high_conf_log  = []   # (pass_num, addr, score, reg) for summary

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

            pass_scores = []
            for addr, perms, reg in results:
                score, reasons = score_candidate(addr, reg, history)
                update_history(history, addr, reg)
                tag   = '  <-- NEW' if addr in new else ''
                conf  = ('HIGH  ' if score >= W_COORD_CLEAN + W_EPOCH_INC
                         else 'MED   ' if score >= W_COORD_CLEAN
                         else 'LOW   ')
                print(
                    f'[pass {pass_num:02d}] 0x{addr:x} ({perms}){tag}'
                    f'  ver={reg["version"]} tick={reg["tick"]} epoch={reg["epoch"]}'
                    f'  score={score:+d} [{conf}]  reasons={reasons}'
                    f'\n          entities: {reg["entities"]}'
                )
                pass_scores.append((score, addr, reg))
                if score >= W_COORD_CLEAN + W_EPOCH_INC:
                    high_conf_log.append((pass_num, addr, score, reg))

            for old in gone:
                print(f'[pass {pass_num:02d}]           0x{old:x}  <-- gone')
                if old in history:
                    history[old]['passes'] = 0  # reset stability if gone

            prev_addresses = cur

            # Per-pass best candidate
            if pass_scores:
                best_score, best_addr, best_reg = max(pass_scores, key=lambda t: t[0])
                print(
                    f'[pass {pass_num:02d}] >> BEST CANDIDATE: 0x{best_addr:x}'
                    f'  score={best_score:+d}  epoch={best_reg["epoch"]}'
                    f'  entities={best_reg["entities"]}'
                )

        print()
        time.sleep(SCAN_INTERVAL)

    # ── final summary ──
    print('\n' + '=' * 70)
    print('SCAN COMPLETE — HIGH CONFIDENCE CANDIDATES ACROSS ALL PASSES')
    print('=' * 70)
    if not high_conf_log:
        print('  None. No candidate exceeded the high-confidence threshold.')
    else:
        seen = {}
        for pass_num, addr, score, reg in high_conf_log:
            key = addr
            if key not in seen:
                seen[key] = {'count': 0, 'max_score': score, 'last_reg': reg}
            seen[key]['count']     += 1
            seen[key]['max_score']  = max(seen[key]['max_score'], score)
            seen[key]['last_reg']   = reg
        for addr, info in sorted(seen.items(), key=lambda kv: -kv[1]['max_score']):
            print(
                f'  0x{addr:x}  appeared_in={info["count"]} passes'
                f'  max_score={info["max_score"]:+d}'
                f'  last_entities={info["last_reg"]["entities"]}'
            )
    print('=' * 70)


if __name__ == '__main__':
    main()
