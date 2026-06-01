#!/usr/bin/env python3
"""
phase1_tracker.py  —  Phase 1: Reactive Observer Hunter

Standalone module.  Import and use ObserverHunter in any prototype that
exposes an anomaly score scalar and a SecureIPCArena instance.

Design
------
The hunter is IDLE by default.  It wakes when EITHER:
  (a) the caller's anomaly score crosses trigger_score (default 0.01), OR
  (b) a direct /proc/<own_pid>/mem fd poll inside notify_score() detects
      an open handle from any foreign PID.

Key detail
----------
process_reader_v5.py runs for ~10 s (20 passes × 0.5 s) then exits.
To catch it reliably the hunter uses TWO detection paths:

  Path 1 — Cached snapshot (reliable)
      notify_score() is called once per epoch from the game loop.
      It runs _find_foreign_mem_handles() which enumerates /proc/*/fd
      right at epoch time.  Any PIDs found are stored in
      self._pending_fd_hits (a list of (pid, [fd_paths]) tuples).
      The scan thread drains this list at the start of every _scan()
      call and builds dossiers from it, even if the reader has since
      exited.

  Path 2 — Live scan (catches persistent readers)
      _scan() also does its own live /proc/*/fd enumeration.
      hunter_interval is now 0.3 s so this fires well within the
      reader's lifetime even without Path 1.

Logging
-------
All [hunter] output is written to BOTH stdout AND a dedicated log file:

    hunter_suspects_<pid>_<YYYYMMDD_HHMMSS>.log

The file is created in HunterConfig.log_dir (defaults to the directory
that contains this script).  Every line is timestamped and flushed
immediately so `tail -f` works live.  The resolved path is available
as ObserverHunter.log_path after construction.

Constraints
-----------
  * Pure userspace — /proc filesystem reads only, no kernel interaction.
  * No new IPC mechanisms — reuses the v11 memfd arena (slot 63).
  * False-positive guard: skips own PID and PIDs with
    loginuid == 0xFFFFFFFF (kernel default, no session).

Usage
-----
    from phase1_tracker import ObserverHunter, HunterConfig

    cfg    = HunterConfig()
    hunter = ObserverHunter(cfg, ipc_arena, ipc_tpm_seed)
    hunter.start()
    print(f"[hunter] logging suspects to: {hunter.log_path}")

    # Each epoch, after computing anomaly score:
    hunter.notify_score(score, epoch)

    hunter.stop()   # on shutdown
"""

import hashlib
import json
import os
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class HunterConfig:
    """
    Tunable knobs for the observer hunter.

    trigger_score     : 0.01 — any detectable canary activity wakes hunter.
    hunter_interval   : 0.3 s — fast enough to catch a ~10 s reader script.
    idle_after_epochs : 3 consecutive LOW + no fd hits before going IDLE.
    ipc_slot          : 63 (last arena slot, away from telemetry traffic).
    max_dossier_age   : 60 s before a cached dossier is evicted.
    log_dir           : directory for the suspect log file (default: next to
                        this script).  Set to None to disable file logging.
    """
    trigger_score:      float = 0.01
    hunter_interval:    float = 0.3    # was 2.3 s — too slow for short-lived readers
    idle_after_epochs:  int   = 3
    ipc_slot:           int   = 63
    max_dossier_age:    float = 60.0
    log_dir:            Optional[str] = None   # None → auto (script directory)


# ---------------------------------------------------------------------------
# IPC constants (must match phase12_prototype.py)
# ---------------------------------------------------------------------------
IPC_HEADER_SIZE  = 4
IPC_FRAME_SIZE   = 20
HUNTER_SLOT_SIZE = 512


# ---------------------------------------------------------------------------
# /proc helpers
# ---------------------------------------------------------------------------

def _read_file(path: str) -> Optional[str]:
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
    pids = []
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pids.append(int(entry))
    except Exception:
        pass
    return pids


def _open_fds_pointing_to(pid: int, target_path: str) -> List[str]:
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


def _find_foreign_mem_handles(
    own_pid: int, mem_target: str
) -> List[Tuple[int, List[str]]]:
    """
    Enumerate ALL PIDs and return a list of (pid, [fd_paths]) for every
    foreign PID that currently has mem_target open.
    Returns an empty list if none found.
    """
    results = []
    for pid in _all_pids():
        if pid == own_pid:
            continue
        fd_hits = _open_fds_pointing_to(pid, mem_target)
        if fd_hits:
            results.append((pid, fd_hits))
    return results


def _parse_status_uid(status_text: str) -> Optional[int]:
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
    raw = _read_file(f"/proc/{pid}/loginuid")
    if raw is None:
        return 0xFFFFFFFF
    try:
        return int(raw.strip())
    except ValueError:
        return 0xFFFFFFFF


def _read_environ_keys(pid: int) -> List[str]:
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
    pid:              int
    exe:              str
    cmdline:          str
    uid:              int
    gid:              int
    loginuid:         int
    environ_keys:     List[str]
    first_seen_epoch: int
    last_seen_epoch:  int
    seen_count:       int
    session_type:     str

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
    keys = set(environ_keys)
    if "SSH_CONNECTION" in keys or "SSH_CLIENT" in keys:
        return "remote-ssh"
    if "VIRTUAL_ENV" in keys or "CONDA_DEFAULT_ENV" in keys:
        return "python-venv"
    if "DISPLAY" in keys or "WAYLAND_DISPLAY" in keys:
        return "local-gui"
    if "SUDO_USER" in keys or "SUDO_UID" in keys:
        return "sudo-escalated"
    return "headless-service"


def _build_dossier(
    pid: int, epoch: int,
    existing: Optional["Dossier"] = None,
    snapshot_exe: str = "",
    snapshot_cmdline: str = "",
) -> Optional["Dossier"]:
    """
    Build or update a Dossier.  If /proc/<pid> is already gone, we fall
    back to any snapshot values passed in (captured earlier by notify_score).
    """
    status_text  = _read_file(f"/proc/{pid}/status")
    proc_alive   = status_text is not None

    if proc_alive:
        uid          = _parse_status_uid(status_text) or 0
        gid          = _parse_status_gid(status_text) or 0
        loginuid     = _read_loginuid(pid)
        environ_keys = _read_environ_keys(pid)
        exe          = _read_exe(pid) or snapshot_exe
        cmdline      = _read_cmdline(pid) or snapshot_cmdline
    else:
        # Process gone — use whatever the caller snapshotted
        if not snapshot_exe and not snapshot_cmdline and existing is None:
            return None   # nothing at all to report
        uid          = existing.uid          if existing else 0
        gid          = existing.gid          if existing else 0
        loginuid     = existing.loginuid     if existing else 0xFFFFFFFF
        environ_keys = existing.environ_keys if existing else []
        exe          = snapshot_exe  or (existing.exe      if existing else "")
        cmdline      = snapshot_cmdline or (existing.cmdline if existing else "")

    session = _classify_session(environ_keys)

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
    h = hashlib.shake_256(tpm_seed + struct.pack("<I", packet_id))
    return h.digest(length)


def _emit_dossier(
    arena, tpm_seed: bytes, packet_id: int,
    dossier: "Dossier", slot: int,
) -> None:
    if arena is None:
        return
    try:
        payload = json.dumps(
            dossier.to_dict(), separators=(",", ":")
        ).encode()
        payload = payload[:HUNTER_SLOT_SIZE - 8]
        mask    = _hunter_ipc_mask(tpm_seed, packet_id, len(payload))
        masked  = bytes(p ^ m for p, m in zip(payload, mask))
        frame   = (
            struct.pack("<I", packet_id)
            + struct.pack("<I", len(payload))
            + masked
        )
        arena.write(slot * HUNTER_SLOT_SIZE, frame)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Snapshot captured by notify_score for a single foreign PID
# ---------------------------------------------------------------------------

@dataclass
class _FdSnapshot:
    pid:     int
    fd_hits: List[str]
    exe:     str
    cmdline: str
    epoch:   int


# ---------------------------------------------------------------------------
# Hunter Logger  —  tee [hunter] lines to stdout + log file
# ---------------------------------------------------------------------------

class _HunterLogger:
    """
    Thread-safe logger that writes every [hunter] message to:
      1. stdout  (always)
      2. a timestamped .log file  (if log_path is not None)

    Each file line is prefixed with a wall-clock timestamp so the log is
    useful even when the prototype's own stdout is being tailed separately.
    """

    def __init__(self, log_path: Optional[str]):
        self.log_path = log_path
        self._fh: Optional[Any] = None
        self._lock = threading.Lock()

        if log_path is not None:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(log_path)),
                            exist_ok=True)
                self._fh = open(log_path, "w", buffering=1,  # line-buffered
                                encoding="utf-8", errors="replace")
                self._fh.write(
                    f"# AMITF hunter suspect log\n"
                    f"# started {datetime.now().isoformat(timespec='seconds')}\n"
                    f"# pid={os.getpid()}\n"
                    f"# ---\n"
                )
                self._fh.flush()
            except Exception as exc:
                print(f"[hunter] WARNING: could not open log file {log_path!r}: {exc}")
                self._fh = None

    def log(self, msg: str) -> None:
        """Print to stdout and, if open, append timestamped line to file."""
        print(msg)
        if self._fh is not None:
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]  # HH:MM:SS.mmm
            with self._lock:
                try:
                    self._fh.write(f"[{ts}] {msg}\n")
                    self._fh.flush()
                except Exception:
                    pass

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.write(
                    f"# closed {datetime.now().isoformat(timespec='seconds')}\n"
                )
                self._fh.flush()
                self._fh.close()
            except Exception:
                pass
            self._fh = None


def _make_log_path(cfg: HunterConfig) -> Optional[str]:
    """Derive the log file path from config, or None if logging is disabled."""
    if cfg.log_dir is None:
        # Default: same directory as this script
        base_dir = os.path.dirname(os.path.abspath(__file__))
    elif cfg.log_dir == "":
        return None   # empty string explicitly disables file logging
    else:
        base_dir = cfg.log_dir

    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    pid = os.getpid()
    return os.path.join(base_dir, f"hunter_suspects_{pid}_{ts}.log")


# ---------------------------------------------------------------------------
# Observer Hunter
# ---------------------------------------------------------------------------

class ObserverHunter:
    """
    Reactive observer hunter daemon thread.

    Wake paths
    ----------
    A. Score-based  : score >= trigger_score in notify_score().
    B. Direct fd hit: notify_score() finds /proc/<own>/mem open right now;
                      captures a snapshot and queues it for the scan thread.

    Detection path for short-lived readers
    ---------------------------------------
    notify_score() runs in the game-loop thread (every 1 s).  It calls
    _find_foreign_mem_handles() immediately and stores any hits as
    _FdSnapshot objects in self._pending_fd_hits.  _scan() drains this
    queue first — building dossiers from the snapshot data — before
    doing its own live /proc scan.  This ensures detection even when the
    reader exits before hunter_interval (0.3 s) fires.

    Logging
    -------
    All output goes through self._logger which tees to stdout AND a
    dedicated log file.  Access the resolved path via self.log_path.
    """

    def __init__(self, cfg: HunterConfig, arena, tpm_seed: bytes):
        self._cfg        = cfg
        self._arena      = arena
        self._tpm_seed   = tpm_seed
        self._own_pid    = os.getpid()
        self._mem_target = f"/proc/{self._own_pid}/mem"

        self._active         = False
        self._low_count      = 0
        self._current_score  = 0.0
        self._current_epoch  = 0
        self._packet_id      = 0
        self._dossiers:    Dict[int, Dossier]    = {}
        self._dossier_ts:  Dict[int, float]      = {}
        self._pending_fd_hits: List[_FdSnapshot] = []

        self._lock       = threading.Lock()
        self._wake_event = threading.Event()
        self._stop_event = threading.Event()
        self._thread     = threading.Thread(
            target=self._run, daemon=True, name="observer-hunter")

        self.total_suspects_found: int = 0
        self.total_scans:          int = 0
        self.trigger_count:        int = 0

        # Logger (stdout + file)
        log_path      = _make_log_path(cfg)
        self._logger  = _HunterLogger(log_path)
        self.log_path = self._logger.log_path   # None if file logging disabled

    # ------------------------------------------------------------------
    # Convenience wrapper
    # ------------------------------------------------------------------

    def _hlog(self, msg: str) -> None:
        """Write a hunter message to stdout and the suspect log file."""
        self._logger.log(msg)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self):
        self._thread.start()
        self._hlog(
            "[hunter] ObserverHunter started — IDLE"
            f" (trigger_score={self._cfg.trigger_score:.2f}"
            f", hunter_interval={self._cfg.hunter_interval}s"
            f", direct-fd-snapshot: enabled"
            f", log={self.log_path or 'disabled'})"
        )

    def stop(self):
        self._stop_event.set()
        self._wake_event.set()
        self._thread.join(timeout=5.0)
        self._logger.close()

    def notify_score(self, score: float, epoch: int):
        """
        Called from the game loop each epoch.

        1. Run direct fd poll RIGHT NOW (in the caller's thread).
           Snapshot any PIDs found — even if they vanish before _scan() runs.
        2. Wake the hunter thread if score or direct hit crosses the threshold.
        """
        # Direct fd poll — done BEFORE acquiring the lock (may be slow-ish)
        live_hits = _find_foreign_mem_handles(self._own_pid, self._mem_target)
        snapshots = []
        for pid, fd_hits in live_hits:
            snap = _FdSnapshot(
                pid=pid,
                fd_hits=fd_hits,
                exe=_read_exe(pid),
                cmdline=_read_cmdline(pid),
                epoch=epoch,
            )
            snapshots.append(snap)

        direct_hit = bool(live_hits)

        with self._lock:
            self._current_score = score
            self._current_epoch = epoch

            if snapshots:
                self._pending_fd_hits.extend(snapshots)

            should_wake = (score >= self._cfg.trigger_score) or direct_hit

            if not self._active:
                if should_wake:
                    self._active    = True
                    self._low_count = 0
                    self.trigger_count += 1
                    reasons = []
                    if score >= self._cfg.trigger_score:
                        reasons.append(
                            f"score={score:.4f}>={self._cfg.trigger_score:.2f}")
                    if direct_hit:
                        pids = [p for p, _ in live_hits]
                        reasons.append(f"direct-fd-hit pids={pids}")
                    self._hlog(
                        f"[hunter] TRIGGERED at epoch={epoch}"
                        f"  reason=[{', '.join(reasons)}]  initiating scan"
                    )
                    self._wake_event.set()
            else:
                if not should_wake:
                    self._low_count += 1
                    if self._low_count >= self._cfg.idle_after_epochs:
                        self._active = False
                        self._hlog(
                            f"[hunter] returning to IDLE at epoch={epoch}"
                            f"  (LOW for {self._low_count} epochs, no fd hits)"
                        )
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
        Two-phase detection:
          Phase A — drain pending snapshots from notify_score().
                     These were captured in the game-loop thread and may
                     represent PIDs that have already exited.
          Phase B — live /proc/*/fd scan for still-running readers.
        """
        self.total_scans += 1
        now = time.time()

        # ---- Phase A: snapshots queued by notify_score ----
        with self._lock:
            pending = list(self._pending_fd_hits)
            self._pending_fd_hits.clear()

        reported_pids = set()
        for snap in pending:
            pid = snap.pid
            reported_pids.add(pid)
            self.total_suspects_found += 1

            existing = self._dossiers.get(pid)
            dossier  = _build_dossier(
                pid, snap.epoch, existing,
                snapshot_exe=snap.exe,
                snapshot_cmdline=snap.cmdline,
            )
            if dossier is None:
                continue

            self._dossiers[pid]   = dossier
            self._dossier_ts[pid] = now

            self._hlog(f"[hunter] SUSPECT (snapshot) → {dossier.summary()}")
            self._hlog(f"[hunter]   fd_hits={snap.fd_hits}")
            if dossier.environ_keys:
                self._hlog(f"[hunter]   environ_keys={dossier.environ_keys}")

            _emit_dossier(
                self._arena, self._tpm_seed,
                self._packet_id, dossier,
                slot=self._cfg.ipc_slot,
            )
            self._packet_id += 1

        # ---- Phase B: live scan for persistent readers ----
        live_found = []
        for pid in _all_pids():
            if pid == self._own_pid or pid in reported_pids:
                continue
            fd_hits = _open_fds_pointing_to(pid, self._mem_target)
            if fd_hits:
                live_found.append((pid, fd_hits))

        for pid, fd_hits in live_found:
            self.total_suspects_found += 1
            existing = self._dossiers.get(pid)
            dossier  = _build_dossier(pid, epoch, existing)
            if dossier is None:
                continue

            self._dossiers[pid]   = dossier
            self._dossier_ts[pid] = now

            self._hlog(f"[hunter] SUSPECT (live) → {dossier.summary()}")
            self._hlog(f"[hunter]   fd_hits={fd_hits}")
            if dossier.environ_keys:
                self._hlog(f"[hunter]   environ_keys={dossier.environ_keys}")

            _emit_dossier(
                self._arena, self._tpm_seed,
                self._packet_id, dossier,
                slot=self._cfg.ipc_slot,
            )
            self._packet_id += 1

        total_found = len(pending) + len(live_found)
        if total_found == 0:
            self._hlog(
                f"[hunter] scan #{self.total_scans} epoch={epoch}"
                f"  no /proc/mem handles found (snapshot=0, live=0)"
            )

        # Prune expired dossiers
        expired = [
            p for p, ts in self._dossier_ts.items()
            if now - ts > self._cfg.max_dossier_age
        ]
        for p in expired:
            self._hlog(f"[hunter] evicting stale dossier pid={p}")
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
            f"  HUNTER_LOG_FILE:      {self.log_path or 'disabled'}",
        ]
        for pid, d in self._dossiers.items():
            lines.append(f"    └─ {d.summary()}")
        return "\n".join(lines)
