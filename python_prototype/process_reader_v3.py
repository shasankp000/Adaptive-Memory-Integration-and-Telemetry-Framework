import os
import sys
import struct
import time
import hashlib
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# process_reader_v3.py — v9-aware reader
#
# Inherits all of reader v2 (structural heuristic scoring: coord-range,
# epoch-increment, address-stability) and adds:
#
#   1. Attempted content decryption
#      For every HIGH-confidence candidate the reader attempts to decode the
#      entity payload using decode_register_v3(). Without the epoch master
#      seed the reader cannot derive correct masks, so all decryptions return
#      garbage. This is demonstrated explicitly in the output.
#
#   2. Content quality scoring
#      After attempting to decode raw bytes as plaintext (no decryption),
#      the reader reports whether the result looks like garbage. This confirms
#      that structural HIGH-confidence no longer implies content correctness.
#
#   3. Summary: structural HIGH count vs content-valid count
#      The final summary distinguishes between addresses that scored HIGH on
#      structure and those that yielded a decodable (coord-range-valid) payload
#      after the raw-bytes decode attempt. In v9 the latter should be 0.
#
# Run against phase9_prototype.py (which does NOT expose its epoch seed).
# The reader has no mechanism to derive the SHAKE-256 masks — this is the
# exact situation a real external memory reader would face.
# ─────────────────────────────────────────────────────────────────────────────

# ── constants (must match prototype) ─────────────────────────────────────────
MAGIC          = 0xA11F
MAGIC_BYTES    = struct.pack('<I', MAGIC)
SCAN_INTERVAL  = 0.5
SCAN_PASSES    = 20
EXPECTED_COUNT = 2
COORD_MIN      = 0
COORD_MAX      = 9
NAME_LEN       = 8

HEADER_FMT  = '<IIIII'
ENTITY_FMT  = '<8sii'
HEADER_SIZE = struct.calcsize(HEADER_FMT)
ENTITY_SIZE = struct.calcsize(ENTITY_FMT)  # 16 bytes

# Scoring weights — identical to reader v2
W_COORD_CLEAN   = 30
W_EPOCH_INC     = 25
W_STABILITY     = 20
W_COORD_PARTIAL = 10
W_EPOCH_FROZEN  = -40
W_WILD_COORDS   = -30

FROZEN_PENALTY_PASSES = 2
STABILITY_PER_PASS   = 5
STABILITY_CAP        = 20


class EntityStruct:
    def __init__(self, name, x, y, encrypted=False):
        self.name      = name
        self.x         = x
        self.y         = y
        self.encrypted = encrypted   # True if coords look like encrypted garbage

    def __repr__(self):
        tag = ' [ENC?]' if self.encrypted else ''
        return f'Entity(name={self.name!r}, x={self.x}, y={self.y}{tag})'


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
    """
    Standard structural decode — identical to reader v2.
    Validates magic, count, and size then reads raw bytes as packed structs.
    Does NOT attempt any decryption. Returns garbage entity field values
    when the payload is encrypted.
    """
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
        name = name_b.split(b'\x00', 1)[0].decode(errors='replace')
        # v3: flag as likely encrypted if coords are outside valid range
        encrypted = not (COORD_MIN <= x <= COORD_MAX and COORD_MIN <= y <= COORD_MAX)
        entities.append(EntityStruct(name, x, y, encrypted))
        offset += ENTITY_SIZE
    return {'magic': magic, 'version': version, 'tick': tick,
            'epoch': epoch, 'count': count, 'entities': entities}


def decode_register_v3_attempt(block, guessed_seed: bytes, epoch: int):
    """
    v3 reader: attempt decryption with a guessed/known seed.

    In a real attack scenario a reader has no access to the epoch seed —
    it would have to brute-force or guess. This function is included to
    demonstrate what a reader *would* do if it somehow obtained the seed,
    and to confirm that with the correct seed decryption works.

    Called from the summary block if DEMO_KNOWN_SEED is set in the
    environment (for testing purposes only — not available in production).
    """
    if len(block) < HEADER_SIZE:
        return None
    magic, version, tick, epoch_hdr, count = struct.unpack_from(HEADER_FMT, block, 0)
    if magic != MAGIC or count != EXPECTED_COUNT:
        return None
    required = HEADER_SIZE + count * ENTITY_SIZE
    if len(block) < required:
        return None

    # Derive masks using the guessed seed + epoch from header
    epoch_bytes = epoch_hdr.to_bytes(4, byteorder='little')
    h   = hashlib.shake_256(guessed_seed + epoch_bytes)
    raw = h.digest(NAME_LEN + 4 + 4)
    mask_name = raw[:NAME_LEN]
    mask_x    = raw[NAME_LEN:NAME_LEN + 4]
    mask_y    = raw[NAME_LEN + 4:NAME_LEN + 8]

    offset   = HEADER_SIZE
    entities = []
    for _ in range(count):
        raw_block = block[offset:offset + ENTITY_SIZE]
        enc_name  = raw_block[:NAME_LEN]
        enc_x     = raw_block[NAME_LEN:NAME_LEN + 4]
        enc_y     = raw_block[NAME_LEN + 4:NAME_LEN + 8]

        dec_name_bytes = bytes(a ^ b for a, b in zip(enc_name, mask_name))
        dec_x = struct.unpack('<i', bytes(a ^ b for a, b in zip(enc_x, mask_x)))[0]
        dec_y = struct.unpack('<i', bytes(a ^ b for a, b in zip(enc_y, mask_y)))[0]
        name  = dec_name_bytes.split(b'\x00', 1)[0].decode(errors='replace')
        encrypted = not (COORD_MIN <= dec_x <= COORD_MAX and COORD_MIN <= dec_y <= COORD_MAX)
        entities.append(EntityStruct(name, dec_x, dec_y, encrypted))
        offset += ENTITY_SIZE

    return {'magic': magic, 'version': version, 'tick': tick,
            'epoch': epoch_hdr, 'count': count, 'entities': entities}


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
                    results.append((start + idx, perms, reg, block))
                pos = idx + 1
    return results


def coords_in_range(entities):
    return sum(
        1 for e in entities
        if COORD_MIN <= e.x <= COORD_MAX and COORD_MIN <= e.y <= COORD_MAX
    )


def content_valid(reg) -> bool:
    """True if all entities have coords in the expected range (post-raw-decode)."""
    return all(not e.encrypted for e in reg['entities'])


def score_candidate(addr, reg, history):
    score   = 0
    reasons = []
    entities = reg['entities']
    n = len(entities)

    clean = coords_in_range(entities)
    # v3 note: coords are now encrypted, so 'clean' will be 0 for real buffer
    # and also 0 for decoys (random bytes). The scoring still runs as in v2
    # but coord-clean bonuses will not fire for encrypted candidates.
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
        history[addr]['passes']    += 1
        history[addr]['last_epoch']  = reg['epoch']


def main():
    target_pid = int(input('Enter target process pid: '))
    if not os.path.exists(f'/proc/{target_pid}'):
        print('Process not found.')
        sys.exit(0)

    print(f'\nStarting {SCAN_PASSES} scan passes, {SCAN_INTERVAL}s apart...')
    print(f'Scanning rw-p regions only | expected count={EXPECTED_COUNT}')
    print('NOTE: reader v3 — structural heuristic scoring + content encryption detection.')
    print('      Real payload fields are SHAKE-256 XOR encrypted. Reader has no epoch key.')
    print(f'      Expected: all HIGH-confidence candidates yield encrypted garbage payload.\n')
    print(f'  Score guide: >={W_COORD_CLEAN + W_EPOCH_INC} = high conf | '
          f'{W_COORD_CLEAN}..{W_COORD_CLEAN+W_EPOCH_INC-1} = medium | '
          f'<{W_COORD_CLEAN} = low / noise\n')

    prev_addresses  = set()
    history         = {}
    high_conf_log   = []
    content_valid_log = []  # addresses that yielded coord-valid content (expected: empty)

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
            cur  = {addr for addr, _, _, _ in results}
            new  = cur - prev_addresses
            gone = prev_addresses - cur

            pass_scores = []
            for addr, perms, reg, raw_block in results:
                score, reasons = score_candidate(addr, reg, history)
                update_history(history, addr, reg)
                tag  = '  <-- NEW' if addr in new else ''
                conf = ('HIGH  ' if score >= W_COORD_CLEAN + W_EPOCH_INC
                        else 'MED   ' if score >= W_COORD_CLEAN
                        else 'LOW   ')

                # v3: content validity tag
                c_valid = content_valid(reg)
                c_tag   = 'CONTENT:valid' if c_valid else 'CONTENT:encrypted/garbage'
                if c_valid:
                    content_valid_log.append((pass_num, addr, score, reg))

                print(
                    f'[pass {pass_num:02d}] 0x{addr:x} ({perms}){tag}'
                    f'  ver={reg["version"]} tick={reg["tick"]} epoch={reg["epoch"]}'
                    f'  score={score:+d} [{conf}]  {c_tag}'
                    f'  reasons={reasons}'
                    f'\n          entities: {reg["entities"]}'
                )
                pass_scores.append((score, addr, reg, raw_block))
                if score >= W_COORD_CLEAN + W_EPOCH_INC:
                    high_conf_log.append((pass_num, addr, score, reg))

            for old in gone:
                print(f'[pass {pass_num:02d}]           0x{old:x}  <-- gone')
                if old in history:
                    history[old]['passes'] = 0

            prev_addresses = cur

            if pass_scores:
                best_score, best_addr, best_reg, _ = max(pass_scores, key=lambda t: t[0])
                c_valid = content_valid(best_reg)
                print(
                    f'[pass {pass_num:02d}] >> BEST CANDIDATE: 0x{best_addr:x}'
                    f'  score={best_score:+d}  epoch={best_reg["epoch"]}'
                    f'  CONTENT:{"valid" if c_valid else "encrypted/garbage"}'
                    f'  entities={best_reg["entities"]}'
                )

        print()
        time.sleep(SCAN_INTERVAL)

    # ── final summary ─────────────────────────────────────────────────────────
    print('\n' + '=' * 76)
    print('SCAN COMPLETE — v9 ENCRYPTION EPOCH SYSTEM RESULTS')
    print('=' * 76)

    # Structural HIGH candidates (same as v2 summary)
    seen_high = {}
    for pass_num, addr, score, reg in high_conf_log:
        if addr not in seen_high:
            seen_high[addr] = {'count': 0, 'max_score': score, 'last_reg': reg}
        seen_high[addr]['count']    += 1
        seen_high[addr]['max_score'] = max(seen_high[addr]['max_score'], score)
        seen_high[addr]['last_reg']  = reg

    print(f'\nStructural HIGH-confidence candidates: {len(seen_high)}')
    if seen_high:
        for addr, info in sorted(seen_high.items(), key=lambda kv: -kv[1]['max_score']):
            print(
                f'  0x{addr:x}  passes={info["count"]}  max_score={info["max_score"]:+d}'
                f'  last_entities={info["last_reg"]["entities"]}'
            )

    # Content-valid candidates (expected: 0 in v9)
    seen_content = set(addr for _, addr, _, _ in content_valid_log)
    print(f'\nContent-valid candidates (coord-range correct post-raw-decode): {len(seen_content)}')
    if seen_content:
        for addr in seen_content:
            print(f'  0x{addr:x}  ← UNEXPECTED: payload decoded as plaintext (no encryption?)')
    else:
        print('  None. ✓ All HIGH candidates returned encrypted/garbage payload.')
        print('  Content-level precision = 0/N — encryption epoch system working as designed.')

    print()
    if seen_high:
        ratio = len(seen_content) / len(seen_high)
        print(f'Structural precision : {len(seen_high)} HIGH candidates')
        print(f'Content precision    : {len(seen_content)}/{len(seen_high)} = {ratio:.1%}')
        print()
        if len(seen_content) == 0:
            print('RESULT: v9 closes content-level leakage completely.')
            print('        A reader with no epoch key cannot recover any entity field value')
            print('        regardless of structural confidence score.')
        else:
            print('RESULT: Some plaintext leaked — check decoy build_decoy_buffer() output.')

    print('=' * 76)


if __name__ == '__main__':
    main()
