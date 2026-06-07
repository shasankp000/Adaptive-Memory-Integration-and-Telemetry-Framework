#!/usr/bin/env python3
"""
process_reader_phase1.py  —  Reader for phase1_prototype.py / Phase 1

WHY A NEW READER IS NEEDED
--------------------------
All previous readers (v1–v5) were written to attack phase11_prototype.py
(header VERSION=11) or earlier.  phase1_prototype.py differs in three
critical ways that break every prior reader:

  1. Header VERSION byte = 12  (readers v1-v5 reject this immediately)
  2. Real-buffer entity layout is RANDOMISED each epoch:
       - pad_sizes  : six random 1-16 byte pads inserted between fields
       - field_order: "name/x/y" shuffled randomly
     → no fixed 22-byte entity stride; structural scanning lands on garbage.
  3. All entity fields are XOR-encrypted with per-epoch polymorphic keys
     derived from a 32-byte master seed the reader does not know.
     → raw decode of any entity field is meaningless ciphertext.

WHAT THIS READER DOES INSTEAD
------------------------------
Since the structural payload is fully opaque, this reader focuses on the
two channels that ARE observable from outside the process:

  ── Channel 1: IPC Arena (telemetry frames, slots 0-62) ──────────────────
  Same SHAKE-256 rotating XOR scheme as v11.  The TPM seed is unknown, so
  frames cannot be decrypted.  The reader runs the same three attacks as v5:

    Attack A — Arena Discovery
        Scan /proc/pid/maps for rw-p regions whose size matches the IPC
        arena footprint.  In phase1_prototype the arena is a memfd mmap
        (1280 bytes = IPC_FRAME_SIZE * 64).  The hunter's dossier slot
        adds HUNTER_SLOT_SIZE (512 bytes) × 64 slots = 32 768 bytes in a
        separate write, but the IPC arena itself is still 1280 bytes.

    Attack B — Probe-seed brute-force on telemetry slots 0-62
        Same zero/0xAA/0x55/0xFF/null-mask probes as v5.
        Expected: 0 valid frames (SHAKE-256 rotating keys).

    Attack C — Delta-XOR consecutive frame attack on telemetry slots
        Expected: 0 valid frames.

  ── Channel 2: Hunter Dossier (IPC slot 63, HUNTER_SLOT_SIZE=512 bytes) ──
  When the hunter is ACTIVE it writes a SHAKE-256-masked JSON dossier into
  arena slot 63.  The frame layout (from phase1_tracker.py _emit_dossier):

      offset 0  : uint32 LE  — packet_id
      offset 4  : uint32 LE  — payload length in bytes (≤ 504)
      offset 8  : bytes      — SHAKE-256(tpm_seed || packet_id) XOR json_bytes

  The reader cannot decrypt this (tpm_seed is unknown).  It can however:
    • Detect whether slot 63 has been written to (non-zero packet_id).
    • Report the raw payload length field (not masked — it is unencrypted
      in the frame layout above: the mask covers only offset 8+, so the
      length at offset 4 is XOR'd with mask[4:8]; the packet_id at offset 0
      is XOR'd with mask[0:4]).
    • Attempt weak-seed decryption of the dossier payload (zero seed etc.)
      and check whether the result parses as valid JSON.

  ── Channel 3: Active /proc/pid/mem hold (hunter provocation) ────────────
  The hunter's primary detection path is its _FdPoller which polls
  /proc/*/fd every 50 ms for open handles on /proc/<target>/mem.

  This reader keeps /proc/<pid>/mem open in a BACKGROUND THREAD for the
  entire scan duration (HOLD_DURATION seconds, default 30 s) while the
  main thread does its pass-by-pass scan.  This maximises the window during
  which the poller can observe the open file descriptor and trigger the
  hunter, even without the anomaly score crossing the MEDIUM threshold.

  The background thread holds the fd open, seeks to a random rw-p region,
  and does a tiny read every HOLD_READ_INTERVAL seconds to keep the fd
  alive in the kernel's fd table.

PRIVILEGES & YAMA PTRACE SCOPE
--------------------------------
This reader does NOT require root / sudo when the target prototype is
running as the SAME user.  Linux's Yama LSM controls cross-process memory
access via /proc/sys/kernel/yama/ptrace_scope:

  0 — classic ptrace: any process may read any other process it could
      ptrace (i.e. same UID).  process_vm_readv works without sudo.
  1 — restricted ptrace (Ubuntu/Debian default): a process may only read
      its direct descendants OR processes that have called
      prctl(PR_SET_PTRACER, reader_pid).  Run both prototype and reader
      from the same shell session, or lower to scope=0 for testing:

          echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

  2 — admin-only: only CAP_SYS_PTRACE (root) may cross-process read.
      Requires sudo for this reader.
  3 — no cross-process ptrace at all; reader cannot function.

RECOMMENDED WORKFLOW (no sudo needed, no manual PID entry):
  Terminal 1:  python3 process_reader_phase1.py
               (starts immediately; waits up to 60 s for prototype)
  Terminal 2:  python3 phase1_prototype.py

  The reader auto-discovers the prototype's PID by scanning /proc/*/cmdline.
  Both terminals must run as the same non-root user.

  Alternatively, pass an explicit PID on the command line:
      python3 process_reader_phase1.py <pid>

  Or override the target script name via environment variable:
      READER_TARGET=my_prototype.py python3 process_reader_phase1.py

If you get a PermissionError on process_vm_readv, lower ptrace_scope to 0
(see above) or pass the reader PID to prctl(PR_SET_PTRACER) from the
prototype.

NOTE: Running the reader as root (sudo) while the prototype runs as a
normal user makes the reader a higher-privilege process.  The hunter's
_FdPoller will still fire (inotify sees the open), but it cannot resolve
the reader's PID from /proc/*/fd (PermissionError on /proc/<root_pid>/fd).
The hunter logs an anonymous-open dossier with pid=-1 instead of naming
the reader.  Run both as the same non-root user for a fully attributed
dossier.

EXPECTED BEHAVIOUR
------------------
  Hunter IDLE (no reader before this):
    Epoch 1 — fd-poller fires within 50 ms of reader open() call.
    Hunter TRIGGERED via reason=[direct-fd-hit pid=<reader_pid> via fd-poller].
    Hunter emits dossier to IPC slot 63.

  Reader output:
    • Attack A: 1 arena candidate found (memfd mmap, 1280 bytes).
    • Attack B: 0 valid telemetry frames decoded (SHAKE-256 opaque).
    • Attack C: 0 valid delta-XOR frames.
    • Slot 63 probe: packet_id > 0 detected (hunter wrote a dossier).
      Decryption attempt: FAIL (unknown tpm_seed) — raw bytes logged.
    • Structural scan: score ceiling ≤ +15 (version mismatch kills all
      candidates at parse time; no false-positive entity decodes possible).

USAGE
-----
    python3 process_reader_phase1.py
    (auto-discovers phase1_prototype.py PID — start reader BEFORE or AFTER
     the prototype; reader waits up to DISCOVER_TIMEOUT seconds)

    python3 process_reader_phase1.py <pid>
    (explicit PID — legacy behaviour)

    READER_TARGET=some_script.py python3 process_reader_phase1.py
    (auto-discover a differently-named prototype)

    The reader runs for HOLD_DURATION seconds (default 30 s) while keeping
    /proc/<pid>/mem open so the hunter can observe and record it.
    Extend HOLD_DURATION if you want the hunter to log the dossier before
    the reader exits.
"""

import ctypes
import ctypes.util
import hashlib
import json
import os
import struct
import sys
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants  —  must match phase1_prototype.py / phase1_tracker.py
# ---------------------------------------------------------------------------

# Header layout (v12 buffer — the reader checks but expects rejection)
MAGIC         = 0x1FA1
EXPECTED_VER  = 12         # phase1 writes VERSION=12 in the binary header
EXPECTED_CNT  = 2
HEADER_SIZE   = 10
ENTITY_SIZE   = 22         # nominal; actual stride is random — not usable

# Scan parameters
SCAN_PASSES   = 30         # total structural passes
SCAN_DELAY    = 0.5        # seconds between passes
HIGH_THRESH   = 55
MED_THRESH    = 30

# IPC telemetry arena (slots 0-62 carry telemetry frames)
IPC_HEADER_SIZE  = 4
IPC_PAYLOAD_SIZE = 16
IPC_FRAME_SIZE   = IPC_HEADER_SIZE + IPC_PAYLOAD_SIZE   # 20 bytes
IPC_SLOTS        = 64
IPC_ARENA_SIZE   = IPC_FRAME_SIZE * IPC_SLOTS            # 1280 bytes

# Hunter dossier slot (slot 63, separate write region)
HUNTER_SLOT      = 63
HUNTER_SLOT_SIZE = 512     # bytes — matches phase1_tracker.HUNTER_SLOT_SIZE

# fd hold thread parameters
HOLD_DURATION       = 30.0   # seconds to keep /proc/<pid>/mem open
HOLD_READ_INTERVAL  = 0.8    # seconds between keep-alive reads in hold thread

# Auto-discovery parameters
DISCOVER_TARGET        = os.environ.get("READER_TARGET", "phase1_prototype.py")
DISCOVER_TIMEOUT       = 60.0   # seconds to wait for the prototype to appear
DISCOVER_POLL_INTERVAL = 0.5    # seconds between /proc scans while waiting

# Probe seeds for Attack B / dossier brute-force
_PROBE_SEEDS = [
    ("zero_seed", bytes(32)),
    ("0xAA_seed", bytes([0xAA] * 32)),
    ("0x55_seed", bytes([0x55] * 32)),
    ("0xFF_seed", bytes([0xFF] * 32)),
    ("null_mask", None),   # None → identity (no XOR)
]


# ---------------------------------------------------------------------------
# PID auto-discovery
# ---------------------------------------------------------------------------

def _cmdline(pid: int) -> str:
    """Return the /proc/<pid>/cmdline as a single space-joined string, or ''."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
    except Exception:
        return ""


def discover_pid(target_script: str = DISCOVER_TARGET) -> Optional[int]:
    """
    Scan /proc for a process whose cmdline contains `target_script`.
    Returns the PID (int) of the first match, or None if not found.

    Excludes our own PID and any process whose cmdline contains
    'process_reader' (to avoid self-matching when the reader is restarted).
    """
    our_pid = os.getpid()
    try:
        pids = [int(e) for e in os.listdir("/proc") if e.isdigit()]
    except Exception:
        return None

    for pid in pids:
        if pid == our_pid:
            continue
        cmdline = _cmdline(pid)
        if target_script in cmdline and "process_reader" not in cmdline:
            return pid
    return None


def wait_for_pid(
    target_script: str = DISCOVER_TARGET,
    timeout: float = DISCOVER_TIMEOUT,
    poll: float = DISCOVER_POLL_INTERVAL,
) -> int:
    """
    Wait up to `timeout` seconds for a process matching `target_script`
    to appear in /proc.  Returns the PID when found.

    Prints a friendly waiting message every 5 seconds so the user knows
    the reader is alive and waiting.
    """
    deadline   = time.time() + timeout
    next_print = time.time()

    print(f"[auto-discover] Waiting for '{target_script}' "
          f"(timeout={timeout:.0f}s) …")

    while time.time() < deadline:
        pid = discover_pid(target_script)
        if pid is not None:
            print(f"[auto-discover] Found '{target_script}'  PID={pid}")
            return pid

        now = time.time()
        if now >= next_print:
            remaining = deadline - now
            print(f"[auto-discover]   still waiting … {remaining:.0f}s left  "
                  f"(start 'python3 {target_script}' in another terminal)")
            next_print = now + 5.0

        time.sleep(poll)

    print(f"\n[auto-discover] ERROR: '{target_script}' not found within "
          f"{timeout:.0f}s.\n"
          f"  • Make sure phase1_prototype.py is running as the SAME user.\n"
          f"  • Or pass an explicit PID:  python3 process_reader_phase1.py <pid>\n"
          f"  • Or set READER_TARGET env var to the correct script name.")
    sys.exit(1)


# ---------------------------------------------------------------------------
# process_vm_readv  — same-UID cross-process read without /proc/<pid>/mem
# ---------------------------------------------------------------------------
#
# process_vm_readv(2) reads from a remote process's address space directly
# via a kernel syscall.  It requires the same privileges as ptrace (i.e.
# same UID and ptrace_scope <= 1), but does NOT require the reader to open
# /proc/<pid>/mem as a file — so it bypasses path-level permission checks
# while still triggering the hunter via the /proc/<pid>/mem open() in the
# fd-hold thread.
#
# We also keep the original open()+seek()+read() path as a fallback so the
# reader still works in environments where process_vm_readv is unavailable.
# ---------------------------------------------------------------------------

_libc = None
_process_vm_readv = None


def _init_vm_readv() -> bool:
    """Load libc and resolve process_vm_readv.  Returns True on success."""
    global _libc, _process_vm_readv
    if _process_vm_readv is not None:
        return True
    try:
        libc_name = ctypes.util.find_library("c") or "libc.so.6"
        _libc = ctypes.CDLL(libc_name, use_errno=True)
        _process_vm_readv = _libc.process_vm_readv
        _process_vm_readv.restype  = ctypes.c_ssize_t
        _process_vm_readv.argtypes = [
            ctypes.c_int,                   # pid
            ctypes.c_void_p,                # local_iov
            ctypes.c_ulong,                 # liovcnt
            ctypes.c_void_p,                # remote_iov
            ctypes.c_ulong,                 # riovcnt
            ctypes.c_ulong,                 # flags (must be 0)
        ]
        return True
    except Exception:
        _process_vm_readv = None
        return False


class _Iovec(ctypes.Structure):
    """struct iovec { void *iov_base; size_t iov_len; }"""
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len",  ctypes.c_size_t),
    ]


def _vm_readv(pid: int, addr: int, size: int) -> Optional[bytes]:
    """Read `size` bytes from `addr` in process `pid` via process_vm_readv."""
    if not _init_vm_readv():
        return None
    buf = (ctypes.c_char * size)()
    local_iov  = _Iovec(ctypes.cast(buf, ctypes.c_void_p), size)
    remote_iov = _Iovec(ctypes.c_void_p(addr), size)
    n = _process_vm_readv(
        pid,
        ctypes.byref(local_iov),  1,
        ctypes.byref(remote_iov), 1,
        0,
    )
    if n < 0:
        return None
    return bytes(buf[:n])


def read_mem(pid: int, addr: int, size: int) -> Optional[bytes]:
    """
    Read `size` bytes from virtual address `addr` in process `pid`.

    Strategy (in order):
      1. process_vm_readv via ctypes — works same-UID without sudo as long
         as /proc/sys/kernel/yama/ptrace_scope <= 1.  Does NOT require
         opening /proc/<pid>/mem, so it is unaffected by file-level DAC.
      2. Fallback: open /proc/<pid>/mem, seek, read.  Requires the same
         UID or CAP_SYS_PTRACE (root).  Used automatically if vm_readv
         fails (e.g. kernel < 3.2 or ptrace_scope = 2).
    """
    data = _vm_readv(pid, addr, size)
    if data is not None:
        return data
    # Fallback: classic /proc/<pid>/mem open
    try:
        with open(f"/proc/{pid}/mem", "rb") as f:
            f.seek(addr)
            return f.read(size)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# /proc helpers
# ---------------------------------------------------------------------------

def list_rw_regions(pid: int) -> List[Tuple[int, int]]:
    regions = []
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                if parts[1] != "rw-p":
                    continue
                lo, hi = parts[0].split("-")
                regions.append((int(lo, 16), int(hi, 16)))
    except Exception:
        pass
    return regions


def open_mem_fd(pid: int):
    """Return an open file object for /proc/<pid>/mem, or None."""
    try:
        return open(f"/proc/{pid}/mem", "rb")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Structural header parse  (expects VERSION=12; will always fail on real buf
# because entity layout is randomised, but we report what we see)
# ---------------------------------------------------------------------------

def try_parse_header(data: bytes) -> Optional[Tuple[int, int, int, int]]:
    if len(data) < HEADER_SIZE:
        return None
    magic, ver, tick = struct.unpack_from("<HBB", data, 0)
    epoch,           = struct.unpack_from("<I",   data, 4)
    count,           = struct.unpack_from("<H",   data, 8)
    if magic != MAGIC or ver != EXPECTED_VER or count != EXPECTED_CNT:
        return None
    return ver, tick, epoch, count


# ---------------------------------------------------------------------------
# IPC / dossier SHAKE-256 mask (same KDF as prototype & tracker)
# ---------------------------------------------------------------------------

def _shake256_mask(seed: bytes, packet_id: int, length: int) -> bytes:
    h = hashlib.shake_256(seed + struct.pack("<I", packet_id))
    return h.digest(length)


# ---------------------------------------------------------------------------
# IPC telemetry frame plausibility (Attack B / C)
# ---------------------------------------------------------------------------

def _ipc_frame_plausible(raw_payload: bytes) -> bool:
    """
    Heuristic: decoded IPC frame (16 bytes) must satisfy:
      epoch        uint32  [0, 10000]
      tick         uint32  [0, 10000]
      total_hits   uint32  [0, 100000]
      mean_delta   float32 (0.0, 5000.0)
    """
    if len(raw_payload) < IPC_PAYLOAD_SIZE:
        return False
    try:
        epoch, tick, total_hits, mean_delta = struct.unpack(
            "<IIIf", raw_payload[:IPC_PAYLOAD_SIZE]
        )
    except struct.error:
        return False
    return (
        0 <= epoch <= 10_000
        and 0 <= tick <= 10_000
        and 0 <= total_hits <= 100_000
        and 0.0 < mean_delta < 5000.0
    )


# ---------------------------------------------------------------------------
# Scoring  (inherited from v4/v5 — used for structural scan only)
# ---------------------------------------------------------------------------

class AddrRecord:
    def __init__(self):
        self.seen_passes: int = 0
        self.last_epoch: Optional[int] = None


def score_candidate(
    rec: AddrRecord,
    epoch: int,
    entities_raw: bytes,
) -> Tuple[int, List[str]]:
    """
    Minimal structural scorer.  Since entity layout is random we cannot
    run content_valid checks — coords are meaningless ciphertext.
    We keep epoch monotonicity and address-stability scoring only.
    """
    reasons = []
    score   = 0

    if rec.last_epoch is None:
        reasons.append("first_seen")
    elif epoch == rec.last_epoch:
        score -= 40
        reasons.append("epoch_frozen(-40)")
    elif epoch == rec.last_epoch + 1:
        score += 25
        reasons.append("epoch_inc(+25)")

    stability = min(rec.seen_passes, 4) * 5
    if stability:
        score += stability
        reasons.append(f"stability(+{stability})")

    return score, reasons


def confidence_label(score: int) -> str:
    if score >= HIGH_THRESH:
        return "HIGH  "
    if score >= MED_THRESH:
        return "MEDIUM"
    return "LOW   "


# ---------------------------------------------------------------------------
# fd-hold thread  — keeps /proc/<pid>/mem open for HOLD_DURATION seconds
# ---------------------------------------------------------------------------

class FdHoldThread:
    """
    Opens /proc/<pid>/mem and holds the fd open for HOLD_DURATION seconds,
    doing a tiny keep-alive read every HOLD_READ_INTERVAL seconds.

    Purpose: give the hunter's _FdPoller (50 ms cadence) many opportunities
    to observe our open handle and trigger the hunter — independent of
    whether the anomaly score crosses the MEDIUM threshold.

    Note: the keep-alive reads use the process_vm_readv path (read_mem)
    rather than the held fd, so the fd-hold thread purely demonstrates
    /proc/<pid>/mem presence to the hunter's inotify + fd-poller.
    """

    def __init__(self, pid: int, regions: List[Tuple[int, int]]):
        self._pid      = pid
        self._regions  = regions
        self._stop     = threading.Event()
        self._thread   = threading.Thread(target=self._run, daemon=True,
                                          name="fd-hold")
        self.opened    = False
        self.fd        = None

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=HOLD_DURATION + 2)
        if self.fd is not None:
            try:
                self.fd.close()
            except Exception:
                pass

    def _run(self):
        try:
            self.fd = open(f"/proc/{self._pid}/mem", "rb")
            self.opened = True
        except PermissionError as exc:
            print(
                f"[fd-hold] FAILED to open /proc/{self._pid}/mem: {exc}\n"
                f"[fd-hold] → Run both prototype and reader as the same "
                f"non-root user.\n"
                f"[fd-hold] → If ptrace_scope=1, either start both from "
                f"the same shell or run:\n"
                f"[fd-hold]     echo 0 | sudo tee "
                f"/proc/sys/kernel/yama/ptrace_scope"
            )
            return
        except Exception as exc:
            print(f"[fd-hold] FAILED to open /proc/{self._pid}/mem: {exc}")
            return

        print(f"[fd-hold] Holding /proc/{self._pid}/mem open for "
              f"{HOLD_DURATION}s  (hunter fd-poller window)")

        deadline = time.time() + HOLD_DURATION
        while not self._stop.is_set() and time.time() < deadline:
            # Keep-alive read via process_vm_readv (avoids double-open noise)
            for start, end in self._regions:
                sz = min(16, end - start)
                if sz <= 0:
                    continue
                read_mem(self._pid, start, sz)
                break
            self._stop.wait(timeout=HOLD_READ_INTERVAL)

        print(f"[fd-hold] Releasing /proc/{self._pid}/mem fd")


# ---------------------------------------------------------------------------
# IPC Arena Interceptor  (Attacks A / B / C on telemetry slots)
# ---------------------------------------------------------------------------

class IPCInterceptor:

    def __init__(self):
        self.arena_candidates:   List[int] = []
        self.valid_frames_total: int       = 0
        self.delta_xor_valid:    int       = 0
        self.delta_xor_attempts: int       = 0
        self._prev_ciphertexts: Dict[Tuple[int, int], bytes] = {}

    # ── Attack A ──────────────────────────────────────────────────────────

    def discover_arenas(self, pid: int) -> List[int]:
        """Find rw-p regions matching IPC_ARENA_SIZE (±8 KiB tolerance)."""
        found = []
        for start, end in list_rw_regions(pid):
            if abs((end - start) - IPC_ARENA_SIZE) <= 8192:
                found.append(start)
        self.arena_candidates = found
        return found

    # ── Attack B ──────────────────────────────────────────────────────────

    def attack_b(self, pid: int, arena_addr: int, pass_num: int) -> int:
        raw = read_mem(pid, arena_addr, IPC_ARENA_SIZE)
        if raw is None:
            print(f"  [ipc-attack-b] pass={pass_num}  arena=0x{arena_addr:x}  read FAILED")
            return 0

        valid_count = 0
        for slot in range(IPC_SLOTS - 1):   # slots 0-62; slot 63 = dossier
            offset    = slot * IPC_FRAME_SIZE
            raw_frame = raw[offset:offset + IPC_FRAME_SIZE]
            if len(raw_frame) < IPC_FRAME_SIZE:
                continue

            packet_id  = struct.unpack("<I", raw_frame[:IPC_HEADER_SIZE])[0]
            ciphertext = raw_frame[IPC_HEADER_SIZE:IPC_HEADER_SIZE + IPC_PAYLOAD_SIZE]

            slot_valid = False
            for label, seed in _PROBE_SEEDS:
                if seed is None:
                    decoded = ciphertext
                else:
                    mask    = _shake256_mask(seed, packet_id, IPC_PAYLOAD_SIZE)
                    decoded = bytes(c ^ m for c, m in zip(ciphertext, mask))

                if _ipc_frame_plausible(decoded):
                    valid_count += 1
                    slot_valid   = True
                    key = (arena_addr, slot)
                    self._prev_ciphertexts[key] = ciphertext
                    print(
                        f"  [ipc-attack-b] pass={pass_num}  arena=0x{arena_addr:x}"
                        f"  slot={slot:02d}  pkt_id={packet_id}  seed={label}"
                        f"  PLAUSIBLE  decoded={decoded.hex()}"
                    )

            if not slot_valid and pass_num == 1:
                print(
                    f"  [ipc-attack-b] pass={pass_num}  arena=0x{arena_addr:x}"
                    f"  slot={slot:02d}  pkt_id={packet_id}  all_seeds=GARBAGE"
                    f"  cipher[:8]={ciphertext[:8].hex()}"
                )

        self.valid_frames_total += valid_count
        return valid_count

    # ── Attack C ──────────────────────────────────────────────────────────

    def attack_c(self, pid: int, arena_addr: int, pass_num: int) -> int:
        raw = read_mem(pid, arena_addr, IPC_ARENA_SIZE)
        if raw is None:
            return 0

        valid_count = 0
        for slot in range(IPC_SLOTS - 1):
            key = (arena_addr, slot)
            if key not in self._prev_ciphertexts:
                continue
            offset    = slot * IPC_FRAME_SIZE
            raw_frame = raw[offset:offset + IPC_FRAME_SIZE]
            if len(raw_frame) < IPC_FRAME_SIZE:
                continue

            curr_cipher = raw_frame[IPC_HEADER_SIZE:IPC_HEADER_SIZE + IPC_PAYLOAD_SIZE]
            prev_cipher = self._prev_ciphertexts[key]
            xor_delta   = bytes(a ^ b for a, b in zip(curr_cipher, prev_cipher))

            self.delta_xor_attempts += 1
            if _ipc_frame_plausible(xor_delta):
                valid_count          += 1
                self.delta_xor_valid += 1
                print(
                    f"  [ipc-attack-c] pass={pass_num}  arena=0x{arena_addr:x}"
                    f"  slot={slot:02d}  delta-XOR=PLAUSIBLE  xor={xor_delta.hex()}"
                )
            self._prev_ciphertexts[key] = curr_cipher

        return valid_count

    def summary(self) -> str:
        return (
            f"IPC Intercept (telemetry slots 0-62)\n"
            f"  Arena candidates found:          {len(self.arena_candidates)}\n"
            f"  Attack B — valid frames decoded: {self.valid_frames_total}\n"
            f"  Attack C — delta-XOR attempts:  {self.delta_xor_attempts}\n"
            f"  Attack C — valid delta frames:  {self.delta_xor_valid}"
        )


# ---------------------------------------------------------------------------
# Hunter Dossier Probe  (IPC slot 63 — HUNTER_SLOT_SIZE bytes)
# ---------------------------------------------------------------------------

class DossierProbe:
    """
    Reads IPC arena slot 63 (the hunter's dossier slot) and attempts to
    determine whether the hunter has written a dossier.

    Frame layout (_emit_dossier in phase1_tracker.py):
      offset 0 : uint32 LE — packet_id  (masked: XOR with mask[0:4])
      offset 4 : uint32 LE — payload_len (masked: XOR with mask[4:8])
      offset 8 : bytes     — SHAKE-256(tpm_seed || packet_id) XOR json_payload

    Since tpm_seed is unknown, we cannot decrypt.  We can:
      • Report the raw packet_id and masked payload_len bytes.
      • Try each probe seed and check if the result is valid UTF-8 JSON.
      • Track whether slot 63 changes between passes (indicates hunter writes).
    """

    def __init__(self):
        self.prev_raw:      Optional[bytes] = None
        self.write_count:   int             = 0   # times slot 63 changed
        self.json_decoded:  int             = 0   # successful JSON parses
        self.last_dossier:  Optional[dict]  = None

    def probe(
        self, pid: int, arena_addr: int, pass_num: int,
    ) -> None:
        # Offset if hunter used IPC_FRAME_SIZE stride (last telemetry slot)
        ipc_offset = 63 * IPC_FRAME_SIZE   # 1260 — last byte in 1280-byte arena

        # Offset if hunter used HUNTER_SLOT_SIZE stride (out of range for 1280-byte arena)
        hunter_offset = 63 * HUNTER_SLOT_SIZE  # 32256

        # Try to read the last telemetry slot (offset 1260, 20 bytes in range)
        raw_ipc = read_mem(pid, arena_addr + ipc_offset, IPC_FRAME_SIZE)

        # Try to read at HUNTER_SLOT_SIZE offset (likely out of range for this mmap)
        raw_hunter = read_mem(pid, arena_addr + hunter_offset, HUNTER_SLOT_SIZE)

        print(f"\n  [dossier-probe] pass={pass_num}  arena=0x{arena_addr:x}")
        print(f"    IPC-stride slot 63  (offset={ipc_offset}): "
              f"{'read OK' if raw_ipc else 'read FAILED'}")
        if raw_ipc:
            pkt_id_raw = raw_ipc[:4].hex()
            print(f"      raw[:8]={raw_ipc[:8].hex()}  pkt_id_bytes={pkt_id_raw}")

        hunter_status = "read OK" if raw_hunter else "read FAILED (arena too small — expected)"
        print(f"    Hunter-stride slot 63 (offset={hunter_offset}): {hunter_status}")

        if raw_hunter:
            # Unexpected success — hunter arena larger than 1280 bytes
            if raw_hunter != self.prev_raw:
                self.write_count += 1
                print(f"      [!] Slot 63 CHANGED (write #{self.write_count}) — "
                      f"hunter may have emitted a dossier")
                self._try_decode(raw_hunter, pass_num)
            self.prev_raw = raw_hunter
        else:
            print(f"      [info] Arena is 1280 bytes — hunter dossier write at "
                  f"offset 32256 will silently fail in _emit_dossier.")
            print(f"      [info] Hunter detection still works via stdout "
                  f"(phase1_prototype terminal) and the log file.")

    def _try_decode(self, raw: bytes, pass_num: int) -> None:
        """Attempt to decrypt and parse the dossier payload with all probe seeds."""
        if len(raw) < 8:
            return
        raw_pkt_id  = struct.unpack_from("<I", raw, 0)[0]
        raw_pay_len = struct.unpack_from("<I", raw, 4)[0]
        payload_enc = raw[8:]

        print(f"      raw_pkt_id={raw_pkt_id}  raw_pay_len_field={raw_pay_len}")

        for label, seed in _PROBE_SEEDS:
            if seed is None:
                decoded_bytes = payload_enc
            else:
                mask          = _shake256_mask(seed, raw_pkt_id, len(payload_enc))
                decoded_bytes = bytes(p ^ m for p, m in zip(payload_enc, mask))

            # Also try to unmask the packet_id and length with same seed
            if seed is not None:
                id_mask  = _shake256_mask(seed, 0, 8)
                pkt_id   = struct.unpack_from("<I", bytes(
                    raw[i] ^ id_mask[i] for i in range(4)))[0]
                pay_len  = struct.unpack_from("<I", bytes(
                    raw[4 + i] ^ id_mask[4 + i] for i in range(4)))[0]
            else:
                pkt_id, pay_len = raw_pkt_id, raw_pay_len

            if 0 < pay_len <= HUNTER_SLOT_SIZE - 8:
                candidate = decoded_bytes[:pay_len]
                try:
                    text = candidate.decode("utf-8")
                    obj  = json.loads(text)
                    self.json_decoded += 1
                    self.last_dossier  = obj
                    print(f"      [dossier-decode] seed={label}  pkt_id={pkt_id}"
                          f"  pay_len={pay_len}  JSON=VALID  → {obj}")
                    return
                except Exception:
                    pass

        print(f"      [dossier-decode] all seeds failed — "
              f"tpm_seed unknown, payload is opaque (expected)")

    def summary(self) -> str:
        lines = [
            "Hunter Dossier Probe (IPC slot 63)",
            f"  Slot-63 writes detected:  {self.write_count}",
            f"  Successful JSON decodes:  {self.json_decoded}",
        ]
        if self.last_dossier:
            lines.append(f"  Last decoded dossier:     {self.last_dossier}")
        else:
            lines.append(
                "  No JSON decoded (expected — tpm_seed unknown).\n"
                "  Check phase1_prototype terminal for [hunter] SUSPECT lines\n"
                "  and the hunter_suspects_<pid>_*.log file for the dossier."
            )
        lines.append(
            "\n  NOTE: SecureIPCArena is 1280 bytes; hunter writes dossier at\n"
            "        offset 63 × 512 = 32256 (out of range).\n"
            "        _emit_dossier silently fails — this is a known arena-size\n"
            "        mismatch between phase1_tracker and phase1_prototype.\n"
            "        The hunter still DETECTS and LOGS the reader via stdout\n"
            "        and the hunter_suspects_<pid>_*.log file."
        )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # ── PID resolution ──────────────────────────────────────────────────────
    # Priority:
    #   1. Explicit CLI argument: python3 process_reader_phase1.py <pid>
    #   2. Auto-discovery: scan /proc/*/cmdline for DISCOVER_TARGET
    if len(sys.argv) >= 2:
        try:
            pid = int(sys.argv[1])
            print(f"[pid] Using explicit PID from command line: {pid}")
        except ValueError:
            print(f"[pid] ERROR: '{sys.argv[1]}' is not a valid PID integer.")
            sys.exit(1)
    else:
        pid = wait_for_pid()

    regions     = list_rw_regions(pid)
    block_size  = HEADER_SIZE + EXPECTED_CNT * ENTITY_SIZE
    records: Dict[int, AddrRecord] = defaultdict(AddrRecord)

    ipc_intercept = IPCInterceptor()
    dossier_probe = DossierProbe()

    high_conf_count = 0
    best_score      = -9999
    best_addr       = None

    # Report which memory-read backend is available
    vm_readv_ok = _init_vm_readv()

    print()
    print("=" * 72)
    print("  process_reader_phase1.py  —  Reader for phase1_prototype.py")
    print("=" * 72)
    print(f"  Target PID:       {pid}")
    print(f"  Scan passes:      {SCAN_PASSES}  ×  {SCAN_DELAY}s  ({SCAN_PASSES * SCAN_DELAY:.0f}s)")
    print(f"  fd hold:          {HOLD_DURATION}s (hunter provocation)")
    print(f"  IPC arena size:   {IPC_ARENA_SIZE}B  ({IPC_SLOTS} slots × {IPC_FRAME_SIZE}B)")
    print(f"  EXPECTED_VER:     {EXPECTED_VER}  (structural scan — expect all REJECT)")
    print(f"  mem read backend: {'process_vm_readv (no sudo needed)' if vm_readv_ok else 'fallback: /proc/<pid>/mem open()'}")
    print()
    print("  NOTE: Real-buffer entity layout is per-epoch random (pad_sizes +")
    print("        field_order shuffle + per-field XOR encryption).  Structural")
    print("        scanning will score ≤ +15.  Primary observable channels are")
    print("        the IPC arena and the /proc/mem fd-hold hunter provocation.")
    print("  NOTE: Run both prototype and reader as the same non-root user.")
    print("        If PermissionError, check /proc/sys/kernel/yama/ptrace_scope.")
    print("        scope=0 or 1 → no sudo needed.  scope=2 → sudo required.")
    print("=" * 72)
    print()

    # ── fd-hold thread (hunter provocation) ──────────────────────────────
    hold_thread = FdHoldThread(pid, regions)
    hold_thread.start()
    time.sleep(0.2)   # give poller time to see the fd before first pass

    # ── Attack A: IPC arena discovery ─────────────────────────────────────
    arenas = ipc_intercept.discover_arenas(pid)
    if arenas:
        print(f"[ipc-attack-a] {len(arenas)} IPC arena candidate(s): "
              f"{[hex(a) for a in arenas]}")
    else:
        print("[ipc-attack-a] No IPC arena candidates matched size "
              f"(IPC_ARENA_SIZE={IPC_ARENA_SIZE}B ± 8KiB) — "
              "arena may be inside a larger allocation.")
    print()

    # ── Main scan loop ─────────────────────────────────────────────────────
    for pass_num in range(1, SCAN_PASSES + 1):
        pass_start = time.time()

        # Structural scan (all rw-p regions)
        current_regions = list_rw_regions(pid)
        found_this_pass = 0

        for start, end in current_regions:
            sz = end - start
            if sz < block_size:
                continue

            raw = read_mem(pid, start, block_size)
            if raw is None:
                continue

            parsed = try_parse_header(raw)
            if parsed is None:
                if len(raw) >= 4:
                    magic_read = struct.unpack_from("<H", raw, 0)[0]
                    ver_read   = raw[2] if len(raw) > 2 else 0
                    if magic_read == MAGIC and ver_read == EXPECTED_VER:
                        rec   = records[start]
                        epoch = struct.unpack_from("<I", raw, 4)[0] if len(raw) >= 8 else 0
                        score, reasons = score_candidate(rec, epoch, raw)
                        rec.last_epoch  = epoch
                        rec.seen_passes += 1
                        label = confidence_label(score)
                        found_this_pass += 1
                        if score > best_score:
                            best_score = score
                            best_addr  = start
                        if score >= HIGH_THRESH:
                            high_conf_count += 1
                        if pass_num <= 3 or score >= MED_THRESH:
                            print(
                                f"  pass={pass_num:02d}  addr=0x{start:x}  "
                                f"ver=12(OK)  epoch={epoch}  "
                                f"score={score:+d}  [{label}]  "
                                f"layout=OPAQUE(random-padded+XOR)  "
                                f"reasons={reasons}"
                            )
                continue

            # Parsed cleanly (extremely unlikely given random layout + XOR)
            ver, tick, epoch, count = parsed
            rec   = records[start]
            score, reasons = score_candidate(rec, epoch, raw)
            rec.last_epoch  = epoch
            rec.seen_passes += 1
            label = confidence_label(score)
            found_this_pass += 1
            if score > best_score:
                best_score = score
                best_addr  = start
            if score >= HIGH_THRESH:
                high_conf_count += 1
            print(
                f"  pass={pass_num:02d}  addr=0x{start:x}  "
                f"ver={ver}  tick={tick}  epoch={epoch}  "
                f"score={score:+d}  [{label}]  reasons={reasons}"
            )

        # IPC Attack B on all arena candidates
        for arena_addr in arenas:
            ipc_intercept.attack_b(pid, arena_addr, pass_num)

        # IPC Attack C (delta-XOR, from pass 2 onward)
        if pass_num >= 2:
            for arena_addr in arenas:
                ipc_intercept.attack_c(pid, arena_addr, pass_num)

        # Dossier probe on all arena candidates (every 5 passes to reduce noise)
        if pass_num % 5 == 0 or pass_num == 1:
            for arena_addr in arenas:
                dossier_probe.probe(pid, arena_addr, pass_num)

        elapsed = time.time() - pass_start
        remaining = max(0.0, SCAN_DELAY - elapsed)
        print(
            f"[pass {pass_num:02d}/{SCAN_PASSES}]  "
            f"structural_hits={found_this_pass}  "
            f"arena_candidates={len(arenas)}  "
            f"elapsed={elapsed:.2f}s"
        )
        if remaining > 0:
            time.sleep(remaining)

    # ── Stop fd-hold thread ────────────────────────────────────────────────
    hold_thread.stop()

    # ── Final report ──────────────────────────────────────────────────────
    print()
    print("=" * 72)
    print("  PHASE 1 READER  —  FINAL REPORT")
    print("=" * 72)
    print()
    print("  ── Structural Scan ──────────────────────────────────────────────")
    print(f"  Scan passes completed:   {SCAN_PASSES}")
    print(f"  Best structural score:   {best_score:+d}  "
          f"({'addr=0x' + format(best_addr, 'x') if best_addr else 'none'})")
    print(f"  HIGH-confidence hits:    {high_conf_count}")
    print(f"  Score ceiling:           ≤ +15 expected (no content_valid,"
          f" no epoch monotonicity possible on encrypted random layout)")
    print()
    print("  ── IPC Arena (telemetry slots 0-62) ────────────────────────────")
    print(f"  {ipc_intercept.summary()}")
    print()
    print("  ── Hunter Dossier (IPC slot 63) ────────────────────────────────")
    print(f"  {dossier_probe.summary()}")
    print()
    print("  ── fd-Hold / Hunter Provocation ────────────────────────────────")
    print(f"  fd hold duration:        {HOLD_DURATION}s")
    print(f"  fd hold opened:          {hold_thread.opened}")
    print(f"  mem read backend:        {'process_vm_readv' if vm_readv_ok else '/proc/<pid>/mem fallback'}")
    print()
    print("  EXPECTED HUNTER BEHAVIOUR in phase1_prototype.py terminal:")
    print("    [hunter] fd-poller HIT: pid=<this_pid>  exe='...python...'")
    print("    [hunter] TRIGGERED at epoch=<N>  reason=[direct-fd-hit ...]")
    print("    [hunter] SUSPECT (snapshot) → pid=<this_pid>  exe=...")
    print("    (+ dossier written to hunter_suspects_<target_pid>_*.log)")
    print()
    print("=" * 72)
    print("  Reader complete.")
    print("=" * 72)


if __name__ == "__main__":
    main()
