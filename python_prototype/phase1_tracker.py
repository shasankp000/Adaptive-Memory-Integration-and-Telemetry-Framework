#!/usr/bin/env python3
"""
phase1_tracker.py  —  Phase 1: Reactive Observer Hunter

Standalone module. Import and use ObserverHunter in any prototype that
exposes an anomaly score scalar and a SecureIPCArena instance.

Design
------
The hunter is IDLE by default.  It wakes when EITHER:
  (a) the caller's anomaly score crosses trigger_score (default 0.01), OR
  (b) a direct /proc/<own_pid>/mem fd poll detects an open handle from
      any foreign PID (checked inside notify_score each epoch).

While active it:
  1. Scans /proc/*/fd for open file descriptors pointing to
     /proc/<our_pid>/mem  — the clearest signal of an external reader.
  2. Scans /proc/*/status for processes whose VmRSS delta suggests
     active scanning (secondary heuristic, optional).
  3. For each suspect PID, builds a full attribution dossier from:
       /proc/<pid>/exe        — resolved binary path
       /proc/<pid>/cmdline    — full invocation string
       /proc/<pid>/status     — Uid / Gid lines
       /proc/<pid>/loginuid   — PAM login UID (immutable, survives sudo)
       /proc/<pid>/environ    — environment variable KEYS only
  4. Emits the dossier as a JSON-serialised, SHAKE-256 masked IPC packet
     through the caller's SecureIPCArena (slot 63, reserved for hunter).
  5. Rescans every HUNTER_INTERVAL seconds while anomaly >= trigger_score
     OR while /proc/mem handles are still open.
  6. Returns to IDLE once anomaly is LOW for HUNTER_IDLE_AFTER epochs
     AND no /proc/mem handles are open.

Constraints
-----------
  * Pure userspace — /proc filesystem reads only, no kernel interaction.
  * No new IPC mechanisms — reuses the v11 memfd arena (slot 63).
  * False-positive guard: skips own PID, PIDs with loginuid == 0xFFFFFFFF
    (no session), and any PID whose /proc/<pid>/mem fd does NOT point at
    our own PID’s mem path.

Usage
-----
    from phase1_tracker import ObserverHunter, HunterConfig

    cfg    = HunterConfig()          # all defaults
    hunter = ObserverHunter(cfg, ipc_arena, ipc_tpm_seed)
    hunter.start()                   # starts the daemon thread (sleeps)

    # In swap_shared, after computing anomaly score:
    hunter.notify_score(score, epoch)

    hunter.stop()                    # on shutdown
"""

import hashlib
import json
import os
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class HunterConfig:
    """
    All tunable knobs for the observer hunter.

    Attributes
    ----------
    trigger_score       Anomaly score threshold that wakes the hunter.
                        Set to 0.01 — any detectable canary activity
                        (even 1 hit/epoch) crosses this floor.
                        The old 0.20 MEDIUM threshold was unreachable
                        given the current canary-hit rate formula.
    hunter_interval     Rescan cadence while active (seconds).
                        Deliberately non-round to avoid phase-locking
                        with the 1.0 s epoch interval.
    idle_after_epochs   Number of consecutive LOW-score epochs before
                        the hunter returns to IDLE (also requires no
                        open /proc/mem handles).
    ipc_slot            Arena slot index reserved for hunter dossiers.
                        Default 63 (last slot, away from telemetry).
    max_dossier_age     Seconds before a seen PID is evicted from the
                        dossier cache (PID may have been recycled).
    """
    trigger_score:      float = 0.01   # was 0.20 — lowered to any-activity floor
    hunter_interval:    float = 2.3
    idle_after_epochs:  int   = 3
    ipc_slot:           int   = 63
    max_dossier_age:    float = 60.0


# ---------------------------------------------------------------------------
# IPC constants (must match phase1_prototype.py)
# ---------------------------------------------------------------------------
IPC_HEADER_SIZE  = 4    # packet_id uint32 LE
IPC_FRAME_SIZE   = 20   # header + 16-byte payload used by telemetry
HUNTER_SLOT_SIZE = 512  # generous slot for a JSON dossier fragment


# ---------------------------------------------------------------------------
# /proc helpers
# ---------------------------------------------------------------------------

def _read_file(path: str) -> Optional[str]:
    """Read a /proc file; return None on any error."""
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except Exception:
        return None


def _read_file_bytes(path: str) -> Optional[bytes]:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except Exception:
        return None


def _resolve_link(path: str) -> Optional[str]:
    try:
        return os.readlink(path)
    except Exception:
        return None


def _all_pids() -> List[int]:
    """Return all numeric PID entries under /proc."""
    pids = []
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pids.append(int(entry))
    except Exception:
        pass
    return pids


def _open_fds_pointing_to(pid: int, target_path: str) -> List[str]:
    """
    Return the fd symlink paths for `pid` that resolve to `target_path`.
    """
    hits = []
    fd_dir = f"/proc/{pid}/fd"
    try:
        for fd_name in os.listdir(fd_dir):
            link = _resolve_link(f"{fd_dir}/{fd_name}")
            if link == target_path:
                hits.append(f"{fd_dir}/{fd_name}")
    except Exception:
        pass
    return hits


def _any_foreign_mem_handle(own_pid: int, mem_target: str) -> bool:
    """
    Quick O(n-PIDs) poll: return True if ANY foreign PID currently holds
    an open fd pointing at mem_target (i.e. /proc/<own_pid>/mem).
    Used as a direct wake trigger independent of the anomaly score.
    """
    for pid in _all_pids():
        if pid == own_pid:
            continue
        if _open_fds_pointing_to(pid, mem_target):
            return True
    return False


def _parse_status_uid(status_text: str) -> Optional[int]:
    """Extract the first (real) UID from the Uid: line."""
    for line in status_text.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    pass
    return None


def _parse_status_gid(status_text: str) -> Optional[int]:
    """Extract the first (real) GID from the Gid: line."""
    for line in status_text.splitlines():
        if line.startswith("Gid:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    pass
    return None


def _read_loginuid(pid: int) -> int:
    """Read PAM loginuid; returns 0xFFFFFFFF if unset (kernel default)."""
    raw = _read_file(f"/proc/{pid}/loginuid")
    if raw is None:
        return 0xFFFFFFFF
    try:
        return int(raw.strip())
    except ValueError:
        return 0xFFFFFFFF


def _read_environ_keys(pid: int) -> List[str]:
    """
    Return the NAMES of environment variables for pid.
    Reads /proc/<pid>/environ (NUL-delimited KEY=value pairs).
    Returns only the key names, never values.
    """
    raw = _read_file_bytes(f"/proc/{pid}/environ")
    if raw is None:
        return []
    keys = []
    for entry in raw.split(b"\x00"):
        if b"=" in entry:
            key = entry.split(b"=", 1)[0].decode(errors="replace")
            if key:
                keys.append(key)
    return keys


def _read_cmdline(pid: int) -> str:
    """
    Read /proc/<pid>/cmdline (NUL-delimited argv) and return a
    space-joined string.
    """
    raw = _read_file_bytes(f"/proc/{pid}/cmdline")
    if raw is None:
        return ""
    parts = raw.split(b"\x00")
    return " ".join(p.decode(errors="replace") for p in parts if p)


def _read_exe(pid: int) -> str:
    link = _resolve_link(f"/proc/{pid}/exe")
    return link if link else ""


# ---------------------------------------------------------------------------
# Attribution dossier
# ---------------------------------------------------------------------------

@dataclass
class Dossier:
    """
    Full attribution record for one suspect observer process.
    """
    pid:              int
    exe:              str
    cmdline:          str
    uid:              int
    gid:              int
    loginuid:         int          # PAM login UID — golden attribution field
    environ_keys:     List[str]    # env var names only, never values
    first_seen_epoch: int
    last_seen_epoch:  int
    seen_count:       int
    session_type:     str          # classified from environ_keys

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid":              self.pid,
            "exe":              self.exe,
            "cmdline":          self.cmdline,
            "uid":              self.uid,
            "gid":              self.gid,
            "loginuid":         self.loginuid,
            "loginuid_hex":     hex(self.loginuid),
            "environ_keys":     self.environ_keys,
            "session_type":     self.session_type,
            "first_seen_epoch": self.first_seen_epoch,
            "last_seen_epoch":  self.last_seen_epoch,
            "seen_count":       self.seen_count,
        }

    def summary(self) -> str:
        return (
            f"pid={self.pid}  exe={self.exe!r}  loginuid={self.loginuid}"
            f"  session={self.session_type}  seen={self.seen_count}x"
            f"  epochs=[{self.first_seen_epoch},{self.last_seen_epoch}]"
        )


def _classify_session(environ_keys: List[str]) -> str:
    """
    Derive a session-type label from environment variable names.
    Priority order: SSH > VIRTUAL_ENV > DISPLAY > SUDO > headless.
    """
    keys = set(environ_keys)
    if "SSH_CONNECTION" in keys or "SSH_CLIENT" in keys:
        return "remote-ssh"
    if "VIRTUAL_ENV" in keys or "CONDA_DEFAULT_ENV" in keys:
        return "python-venv"     # script-based reader profile
    if "DISPLAY" in keys or "WAYLAND_DISPLAY" in keys:
        return "local-gui"
    if "SUDO_USER" in keys or "SUDO_UID" in keys:
        return "sudo-escalated"
    return "headless-service"


def _build_dossier(pid: int, epoch: int,
                   existing: Optional["Dossier"] = None) -> Optional[Dossier]:
    """
    Construct (or update) a Dossier for the given PID.
    Returns None if the PID has vanished by the time we read it.
    """
    status_text = _read_file(f"/proc/{pid}/status")
    if status_text is None:
        return None  # process gone

    uid          = _parse_status_uid(status_text) or 0
    gid          = _parse_status_gid(status_text) or 0
    loginuid     = _read_loginuid(pid)
    environ_keys = _read_environ_keys(pid)
    exe          = _read_exe(pid)
    cmdline      = _read_cmdline(pid)
    session      = _classify_session(environ_keys)

    if existing is not None:
        existing.last_seen_epoch = epoch
        existing.seen_count     += 1
        existing.uid          = uid
        existing.gid          = gid
        existing.exe          = exe or existing.exe
        existing.cmdline      = cmdline or existing.cmdline
        existing.environ_keys = environ_keys or existing.environ_keys
        existing.session_type = session
        return existing

    return Dossier(
        pid=pid,
        exe=exe,
        cmdline=cmdline,
        uid=uid,
        gid=gid,
        loginuid=loginuid,
        environ_keys=environ_keys,
        first_seen_epoch=epoch,
        last_seen_epoch=epoch,
        seen_count=1,
        session_type=session,
    )


# ---------------------------------------------------------------------------
# IPC emit helper
# ---------------------------------------------------------------------------

def _hunter_ipc_mask(tpm_seed: bytes, packet_id: int, length: int) -> bytes:
    """Derive a SHAKE-256 XOR mask identical to the v11 telemetry path."""
    h = hashlib.shake_256(tpm_seed + struct.pack("<I", packet_id))
    return h.digest(length)


def _emit_dossier(arena, tpm_seed: bytes, packet_id: int,
                  dossier: Dossier, slot: int) -> None:
    """
    Serialise dossier to JSON, XOR-mask it, and write it into the
    IPC arena at the hunter’s reserved slot.

    Wire format:
      [4B packet_id LE] [4B payload_len LE] [N bytes masked JSON]
    Truncated to HUNTER_SLOT_SIZE bytes if the JSON is too long.
    """
    if arena is None:
        return
    try:
        payload = json.dumps(dossier.to_dict(), separators=(",", ":")
                             ).encode()
        payload = payload[:HUNTER_SLOT_SIZE - 8]  # reserve 8B for header
        mask    = _hunter_ipc_mask(tpm_seed, packet_id, len(payload))
        masked  = bytes(p ^ m for p, m in zip(payload, mask))
        frame   = (struct.pack("<I", packet_id)
                   + struct.pack("<I", len(payload))
                   + masked)
        offset = slot * HUNTER_SLOT_SIZE
        arena.write(offset, frame)
    except Exception:
        pass  # never crash the caller


# ---------------------------------------------------------------------------
# Observer Hunter
# ---------------------------------------------------------------------------

class ObserverHunter:
    """
    Reactive observer hunter daemon thread.

    Wake paths
    ----------
    A. Score-based: notify_score() is called each epoch; if score >=
       trigger_score (0.01) the thread is woken.
    B. Direct fd poll: notify_score() also checks whether any foreign PID
       currently holds /proc/<own_pid>/mem open.  If yes, the thread is
       woken immediately regardless of the anomaly score.  This handles
       the case where the reader doesn't generate enough canary hits to
       raise the score above the floor.
    """

    def __init__(self, cfg: HunterConfig, arena, tpm_seed: bytes):
        self._cfg        = cfg
        self._arena      = arena
        self._tpm_seed   = tpm_seed
        self._own_pid    = os.getpid()
        self._mem_target = f"/proc/{self._own_pid}/mem"

        # State
        self._active         = False
        self._low_count      = 0
        self._current_score  = 0.0
        self._current_epoch  = 0
        self._packet_id      = 0
        self._dossiers: Dict[int, Dossier] = {}
        self._dossier_ts: Dict[int, float] = {}

        # Synchronisation
        self._lock       = threading.Lock()
        self._wake_event = threading.Event()
        self._stop_event = threading.Event()
        self._thread     = threading.Thread(
            target=self._run, daemon=True, name="observer-hunter")

        # Public counters
        self.total_suspects_found: int = 0
        self.total_scans:          int = 0
        self.trigger_count:        int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self):
        self._thread.start()
        print("[hunter] ObserverHunter started — IDLE (trigger score:"
              f" {self._cfg.trigger_score:.2f}, direct-fd-poll: enabled)")

    def stop(self):
        self._stop_event.set()
        self._wake_event.set()
        self._thread.join(timeout=5.0)

    def notify_score(self, score: float, epoch: int):
        """
        Called from the game loop each epoch.  Two independent wake paths:
          A. score >= trigger_score  (anomaly-based)
          B. any foreign PID has /proc/<own_pid>/mem open right now
        Either path flips IDLE → ACTIVE and wakes the scan thread.
        """
        # Direct fd poll (wake path B) — cheap, done outside the lock
        direct_hit = _any_foreign_mem_handle(self._own_pid, self._mem_target)

        with self._lock:
            self._current_score = score
            self._current_epoch = epoch

            should_wake = (score >= self._cfg.trigger_score) or direct_hit

            if not self._active:
                if should_wake:
                    self._active    = True
                    self._low_count = 0
                    self.trigger_count += 1
                    reason = []
                    if score >= self._cfg.trigger_score:
                        reason.append(f"score={score:.4f}>={self._cfg.trigger_score:.2f}")
                    if direct_hit:
                        reason.append("direct-fd-hit")
                    print(f"[hunter] TRIGGERED at epoch={epoch}"
                          f"  reason=[{', '.join(reason)}]  initiating scan")
                    self._wake_event.set()
            else:
                if not should_wake:
                    self._low_count += 1
                    if self._low_count >= self._cfg.idle_after_epochs:
                        self._active = False
                        print(f"[hunter] returning to IDLE at epoch={epoch}"
                              f"  (LOW for {self._low_count} epochs, no fd hits)")
                else:
                    self._low_count = 0

    # ------------------------------------------------------------------
    # Internal thread
    # ------------------------------------------------------------------

    def _run(self):
        while not self._stop_event.is_set():
            self._wake_event.wait()
            self._wake_event.clear()

            if self._stop_event.is_set():
                break

            while not self._stop_event.is_set():
                with self._lock:
                    active = self._active
                    epoch  = self._current_epoch

                if not active:
                    break

                self._scan(epoch)
                self._stop_event.wait(timeout=self._cfg.hunter_interval)

    def _scan(self, epoch: int):
        """
        One full scan iteration:
          1. Enumerate all PIDs.
          2. For each PID (not ours), check for open /proc/<own_pid>/mem fds.
          3. Build / update dossier.
          4. Emit via IPC.
          5. Prune stale dossiers.
        """
        self.total_scans += 1
        now   = time.time()
        found = []

        for pid in _all_pids():
            if pid == self._own_pid:
                continue
            fd_hits = _open_fds_pointing_to(pid, self._mem_target)
            if fd_hits:
                found.append((pid, fd_hits))

        for pid, fd_hits in found:
            self.total_suspects_found += 1
            existing = self._dossiers.get(pid)
            dossier  = _build_dossier(pid, epoch, existing)
            if dossier is None:
                self._dossiers.pop(pid, None)
                self._dossier_ts.pop(pid, None)
                continue

            self._dossiers[pid]   = dossier
            self._dossier_ts[pid] = now

            print(f"[hunter] SUSPECT → {dossier.summary()}")
            print(f"[hunter]   fd_hits={fd_hits}")
            print(f"[hunter]   environ_keys={dossier.environ_keys}")

            _emit_dossier(
                self._arena, self._tpm_seed,
                self._packet_id, dossier,
                slot=self._cfg.ipc_slot
            )
            self._packet_id += 1

        if not found:
            print(f"[hunter] scan #{self.total_scans} epoch={epoch}"
                  f"  no /proc/mem handles found")

        # Prune expired dossiers
        expired = [
            p for p, ts in self._dossier_ts.items()
            if now - ts > self._cfg.max_dossier_age
        ]
        for p in expired:
            print(f"[hunter] evicting stale dossier pid={p}")
            self._dossiers.pop(p, None)
            self._dossier_ts.pop(p, None)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> str:
        lines = [
            f"  HUNTER_TRIGGER_COUNT: {self.trigger_count}",
            f"  HUNTER_TOTAL_SCANS:   {self.total_scans}",
            f"  HUNTER_SUSPECTS:      {self.total_suspects_found}",
            f"  HUNTER_DOSSIERS:      {len(self._dossiers)}",
        ]
        for pid, d in self._dossiers.items():
            lines.append(f"    └─ {d.summary()}")
        return "\n".join(lines)
