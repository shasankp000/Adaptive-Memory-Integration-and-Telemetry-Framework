#!/usr/bin/env python3
"""
phase1_tracker.py  —  Phase 1: Reactive Observer Hunter

Standalone module.  Import and use ObserverHunter in any prototype that
exposes an anomaly score scalar and a SecureIPCArena instance.

Detection tiers (highest priority first)
-----------------------------------------
Tier 1 — inotify IN_OPEN on /proc/<own_pid>/mem  (_InotifyMemWatcher)
    Watches the inode of our /proc/<pid>/mem pseudofile.  Fires the
    instant ANY process calls open() on it, regardless of that process's
    UID.  On the IN_OPEN callback we immediately scan /proc/*/fd for the
    opener — the reader's fd is guaranteed live at this point because the
    open() syscall has not yet returned.  This fixes the root-reader /
    non-root-prototype permission gap that defeated _FdPoller.

    /proc quirk: pread64() on /proc/*/mem re-triggers IN_OPEN internally
    on every call.  A debounce gate (_OPEN_DEBOUNCE_S = 0.10 s) coalesces
    rapid-fire events from one reader session into one callback per burst.
    The gate resets on IN_CLOSE so a genuine re-open after close is never
    suppressed.

    When the outward /proc/*/fd scan finds nothing (reader is root, we are
    not), the open is logged as SUSPECT(anonymous-open) with a 1 s rate
    limit rather than flooding stdout.

    Falls back automatically to Tier 2 if inotify on /proc pseudofiles
    is unavailable (some containers, older kernels).

Tier 2 — periodic /proc/*/fd poll  (_FdPoller)  [FALLBACK]
    Polls _find_foreign_mem_handles() every fd_poll_interval (0.05 s).
    Can miss sub-millisecond open windows AND cannot list fds of
    higher-privilege readers — kept only as a fallback for environments
    where inotify is restricted.

Tier 3 — epoch fd poll in notify_score()
    Belt-and-suspenders scan in the game-loop thread once per epoch.
    Catches any reader that holds /proc/<pid>/mem open for a full second.

Key design note
---------------
inotify on /proc pseudofiles works on Linux >= 3.x when the watch is
placed on the file itself (not the directory).  The kernel delivers
IN_OPEN because it hooks the file's ->open() VFS operation.  The event
arrives in the watcher thread while the opener is still inside the
open() syscall, so the outward /proc scan always finds the fd — UNLESS
the reader is higher-privilege (root), in which case the fd directory is
unreadable.  In that case we treat the inotify event itself as the
detection signal and emit an anonymous-open dossier.

Logging
-------
All [hunter] output goes to BOTH stdout AND a timestamped log file:

    hunter_suspects_<pid>_<YYYYMMDD_HHMMSS>.log

The file is created in HunterConfig.log_dir (default: script directory).
Set log_dir="" to disable file logging.  Resolved path: hunter.log_path.

Constraints
-----------
  * Pure userspace — /proc filesystem reads only, no kernel modules.
  * No new IPC — reuses the v11 memfd arena (slot 63).
  * False-positive guard: skips own PID.

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

import ctypes
import ctypes.util
import hashlib
import json
import os
import select
import struct
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class HunterConfig:
    """
    Tunable knobs for the observer hunter.

    trigger_score     : 0.01 — any detectable canary activity wakes hunter.
    hunter_interval   : 0.3 s — scan thread cadence while ACTIVE.
    fd_poll_interval  : 0.05 s — _FdPoller fallback cadence (only used when
                        inotify is unavailable).
    idle_after_epochs : 3 consecutive LOW + no fd hits before going IDLE.
    ipc_slot          : 63 (last arena slot, away from telemetry traffic).
    max_dossier_age   : 60 s before a cached dossier is evicted.
    log_dir           : directory for the suspect log file (default: next to
                        this script).  Set to "" to disable file logging.
    """
    trigger_score:      float = 0.01
    hunter_interval:    float = 0.3
    fd_poll_interval:   float = 0.05   # fallback poller cadence
    idle_after_epochs:  int   = 3
    ipc_slot:           int   = 63
    max_dossier_age:    float = 60.0
    log_dir:            Optional[str] = None   # None → auto (script directory)


# ---------------------------------------------------------------------------
# IPC constants (must match phase1_prototype.py)
# ---------------------------------------------------------------------------
IPC_HEADER_SIZE  = 4
IPC_FRAME_SIZE   = 20
HUNTER_SLOT_SIZE = 512


# ---------------------------------------------------------------------------
# inotify constants / ctypes bindings
# ---------------------------------------------------------------------------
_IN_OPEN          = 0x00000020   # file was opened
_IN_CLOSE_NOWRITE = 0x00000010   # unwritable file closed (read-only open)
_IN_CLOSE_WRITE   = 0x00000008   # writable file closed
_IN_NONBLOCK      = 0x00000800   # O_NONBLOCK for inotify_init1

# Debounce: coalesce rapid IN_OPEN events (pread64 flood) into one callback.
# The gate resets on IN_CLOSE so genuine re-opens are never suppressed.
_OPEN_DEBOUNCE_S   = 0.10   # seconds — events within this window are merged

# Rate-limit for the "anonymous open" log line (root reader, scan misses).
_ANON_LOG_COOLDOWN_S = 1.0  # seconds between repeated anonymous-open logs

# inotify event struct: wd(i32) mask(u32) cookie(u32) len(u32)  [+ name[len]]
_INOTIFY_EVENT_STRUCT = struct.Struct("iIII")
_INOTIFY_EVENT_SIZE   = _INOTIFY_EVENT_STRUCT.size   # 16 bytes


def _inotify_init1(flags: int = 0) -> int:
    libc_name = ctypes.util.find_library("c") or "libc.so.6"
    libc = ctypes.CDLL(libc_name, use_errno=True)
    return int(libc.inotify_init1(ctypes.c_int(flags)))


def _inotify_add_watch(inotify_fd: int, path: str, mask: int) -> int:
    libc_name = ctypes.util.find_library("c") or "libc.so.6"
    libc = ctypes.CDLL(libc_name, use_errno=True)
    return int(libc.inotify_add_watch(
        ctypes.c_int(inotify_fd),
        path.encode(),
        ctypes.c_uint32(mask),
    ))


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
) -> Tuple[List[Tuple[int, List[str]]], bool]:
    """
    Enumerate ALL PIDs and return:
      (hits, any_permission_denied)

    hits                : [(pid, [fd_paths]), ...]  — foreign PIDs with mem open
    any_permission_denied: True if at least one /proc/<pid>/fd was unreadable
                          (indicates a higher-privilege process exists that we
                           cannot inspect — treat inotify event as anonymous-open)

    The permission_denied flag lets the caller distinguish "nobody has it open"
    from "someone has it open but we can't see them".
    """
    results: List[Tuple[int, List[str]]] = []
    any_eperm = False
    for pid in _all_pids():
        if pid == own_pid:
            continue
        fd_dir = f"/proc/{pid}/fd"
        try:
            entries = os.listdir(fd_dir)
        except PermissionError:
            any_eperm = True
            continue
        except Exception:
            continue
        hits = []
        for fd_name in entries:
            link = _resolve_link(f"{fd_dir}/{fd_name}")
            if link == mem_target:
                hits.append(f"{fd_dir}/{fd_name}")
        if hits:
            results.append((pid, hits))
    return results, any_eperm


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
            "loginuid_hex":     hex(self.loginuid) if self.loginuid >= 0 else "unknown",
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
    status_text = _read_file(f"/proc/{pid}/status")
    proc_alive  = status_text is not None

    if proc_alive:
        uid          = _parse_status_uid(status_text) or 0
        gid          = _parse_status_gid(status_text) or 0
        loginuid     = _read_loginuid(pid)
        environ_keys = _read_environ_keys(pid)
        exe          = _read_exe(pid) or snapshot_exe
        cmdline      = _read_cmdline(pid) or snapshot_cmdline
    else:
        if not snapshot_exe and not snapshot_cmdline and existing is None:
            return None
        uid          = existing.uid          if existing else 0
        gid          = existing.gid          if existing else 0
        loginuid     = existing.loginuid     if existing else 0xFFFFFFFF
        environ_keys = existing.environ_keys if existing else []
        exe          = snapshot_exe  or (existing.exe     if existing else "")
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
        pid=pid, exe=exe, cmdline=cmdline,
        uid=uid, gid=gid, loginuid=loginuid,
        environ_keys=environ_keys,
        first_seen_epoch=epoch, last_seen_epoch=epoch,
        seen_count=1, session_type=session,
    )


def _build_anonymous_dossier(epoch: int, existing: Optional["Dossier"] = None) -> "Dossier":
    """
    Construct a minimal Dossier for a confirmed-but-opaque opener.

    Used when inotify fires IN_OPEN but the outward /proc/*/fd scan is
    blocked by PermissionError (reader is root, we are not).  pid=-1
    signals "anonymous" to downstream consumers.
    """
    if existing is not None:
        existing.last_seen_epoch = epoch
        existing.seen_count     += 1
        return existing
    return Dossier(
        pid=-1,
        exe="(anonymous-opener — higher-privilege process, fd unreadable)",
        cmdline="",
        uid=-1,
        gid=-1,
        loginuid=0xFFFFFFFF,
        environ_keys=[],
        first_seen_epoch=epoch,
        last_seen_epoch=epoch,
        seen_count=1,
        session_type="unknown-elevated",
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
# Snapshot captured at detection time
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
    def __init__(self, log_path: Optional[str]):
        self.log_path = log_path
        self._fh: Optional[Any] = None
        self._lock = threading.Lock()

        if log_path is not None:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(log_path)),
                            exist_ok=True)
                self._fh = open(log_path, "w", buffering=1,
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
        print(msg)
        if self._fh is not None:
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
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
    if cfg.log_dir is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    elif cfg.log_dir == "":
        return None
    else:
        base_dir = cfg.log_dir
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    pid = os.getpid()
    return os.path.join(base_dir, f"hunter_suspects_{pid}_{ts}.log")


# ---------------------------------------------------------------------------
# Tier 1 — inotify watcher  (PRIMARY detection path)
# ---------------------------------------------------------------------------

class _InotifyMemWatcher:
    """
    Daemon thread: watches /proc/<own_pid>/mem for IN_OPEN via inotify(7).

    pread64 flood fix
    -----------------
    /proc/*/mem re-triggers IN_OPEN on every pread64() call, not just the
    initial open().  _last_open_ts + _OPEN_DEBOUNCE_S coalesces a burst of
    events from one reader session into a single on_open() callback.
    _last_open_ts is reset to 0.0 on every IN_CLOSE event so a genuine
    re-open after close is never suppressed.

    Anonymous-open handling
    -----------------------
    When the outward scan returns ([], any_eperm=True) the opener is a
    higher-privilege process whose /proc/<pid>/fd is unreadable.  The
    watcher sets self.last_open_was_anonymous = True so ObserverHunter can
    emit an anonymous-open dossier instead of logging a misleading "no fd"
    message.
    """

    def __init__(
        self,
        mem_path:   str,
        on_open,            # callable(epoch: int, anonymous: bool)
        stop_event: threading.Event,
        get_epoch,          # callable() -> int
    ):
        self._mem_path  = mem_path
        self._on_open   = on_open
        self._stop      = stop_event
        self._get_epoch = get_epoch

        self._inotify_fd  = -1
        self._watch_wd    = -1
        self._last_open_ts: float = 0.0   # debounce gate
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="inotify-mem-watcher")

        self.available:    bool = False
        self.open_events:  int  = 0   # total raw IN_OPEN events received
        self.open_fired:   int  = 0   # callbacks actually dispatched (post-debounce)
        self.close_events: int  = 0

        self._setup()

    def _setup(self) -> None:
        try:
            fd = _inotify_init1(_IN_NONBLOCK)
            if fd < 0:
                return
            mask = _IN_OPEN | _IN_CLOSE_NOWRITE | _IN_CLOSE_WRITE
            wd = _inotify_add_watch(fd, self._mem_path, mask)
            if wd < 0:
                os.close(fd)
                return
            self._inotify_fd = fd
            self._watch_wd   = wd
            self.available   = True
        except Exception:
            pass

    def start(self) -> None:
        if self.available:
            self._thread.start()

    def stop(self) -> None:
        if self.available:
            self._thread.join(timeout=3.0)
        if self._inotify_fd >= 0:
            try:
                os.close(self._inotify_fd)
            except Exception:
                pass
            self._inotify_fd = -1

    def _run(self) -> None:
        buf = bytearray(4096)
        while not self._stop.is_set():
            try:
                r, _, _ = select.select([self._inotify_fd], [], [], 1.0)
            except Exception:
                break
            if not r:
                continue
            try:
                n = os.read(self._inotify_fd, len(buf))
            except OSError:
                break

            offset = 0
            while offset + _INOTIFY_EVENT_SIZE <= len(n):
                wd, mask, cookie, name_len = _INOTIFY_EVENT_STRUCT.unpack_from(n, offset)
                offset += _INOTIFY_EVENT_SIZE + name_len

                if mask & _IN_OPEN:
                    self.open_events += 1
                    now = time.monotonic()
                    # Debounce: skip if within the gate window
                    if now - self._last_open_ts < _OPEN_DEBOUNCE_S:
                        continue
                    self._last_open_ts = now
                    self.open_fired   += 1
                    epoch = self._get_epoch()
                    # Outward scan — check for permission-denied
                    hits, any_eperm = _find_foreign_mem_handles(
                        os.getpid(), self._mem_path
                    )
                    anonymous = (not hits) and any_eperm
                    self._on_open(epoch, anonymous, hits)

                if mask & (_IN_CLOSE_NOWRITE | _IN_CLOSE_WRITE):
                    self.close_events += 1
                    # Reset debounce gate — next open after close is genuine
                    self._last_open_ts = 0.0


# ---------------------------------------------------------------------------
# Tier 2 — periodic fd poller  (FALLBACK — used only when inotify unavailable)
# ---------------------------------------------------------------------------

class _FdPoller:
    """
    Daemon thread that polls /proc/*/fd every fd_poll_interval seconds.

    FALLBACK ONLY — used automatically when _InotifyMemWatcher is
    unavailable (containers, kernels that block inotify on /proc).

    Limitation: cannot see fds belonging to higher-privilege processes
    (e.g. root reader, non-root prototype).  Use inotify watcher instead.
    """

    def __init__(
        self,
        own_pid:    int,
        mem_target: str,
        interval:   float,
        on_hit,             # callable(pid, fd_hits, exe, cmdline)
        stop_event: threading.Event,
    ):
        self._own_pid    = own_pid
        self._mem_target = mem_target
        self._interval   = interval
        self._on_hit     = on_hit
        self._stop       = stop_event
        self._thread     = threading.Thread(
            target=self._run, daemon=True, name="fd-poller-fallback")
        self.poll_count: int = 0
        self.hit_count:  int = 0

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(timeout=self._interval)
            if self._stop.is_set():
                break
            self.poll_count += 1
            hits, _ = _find_foreign_mem_handles(self._own_pid, self._mem_target)
            for pid, fd_hits in hits:
                self.hit_count += 1
                exe     = _read_exe(pid)
                cmdline = _read_cmdline(pid)
                self._on_hit(pid, fd_hits, exe, cmdline)


# ---------------------------------------------------------------------------
# Observer Hunter
# ---------------------------------------------------------------------------

class ObserverHunter:
    """
    Reactive observer hunter daemon thread.

    Wake paths
    ----------
    A. inotify IN_OPEN (named)    : reader found in /proc — enqueue snapshot.
    B. inotify IN_OPEN (anonymous): reader is root/elevated — emit anon dossier.
    C. Score-based                : score >= trigger_score in notify_score().
    D. Epoch fd poll              : notify_score() finds handle open right now.
    E. _FdPoller hit              : fallback when inotify unavailable.
    """

    # Sentinel key for the anonymous-opener dossier in self._dossiers
    _ANON_KEY = -1

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
        self._seen_snap_keys: Set[Tuple[int, int]] = set()

        self._lock       = threading.Lock()
        self._wake_event = threading.Event()
        self._stop_event = threading.Event()
        self._thread     = threading.Thread(
            target=self._run, daemon=True, name="observer-hunter")

        self.total_suspects_found:  int = 0
        self.total_scans:           int = 0
        self.trigger_count:         int = 0
        self.watcher_hit_count:     int = 0
        self.watcher_anon_count:    int = 0   # anonymous-open events logged
        self.poller_hit_count:      int = 0

        # Rate-limit for anonymous-open log line
        self._last_anon_log_ts: float = 0.0

        # Logger
        log_path      = _make_log_path(cfg)
        self._logger  = _HunterLogger(log_path)
        self.log_path = self._logger.log_path

        # Tier 1 — inotify watcher
        self._watcher = _InotifyMemWatcher(
            mem_path   = self._mem_target,
            on_open    = self._on_inotify_open,
            stop_event = self._stop_event,
            get_epoch  = lambda: self._current_epoch,
        )

        # Tier 2 — fallback poller (only started when watcher unavailable)
        self._poller = _FdPoller(
            own_pid    = self._own_pid,
            mem_target = self._mem_target,
            interval   = cfg.fd_poll_interval,
            on_hit     = self._on_poller_hit,
            stop_event = self._stop_event,
        )

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _hlog(self, msg: str) -> None:
        self._logger.log(msg)

    # ------------------------------------------------------------------
    # inotify callback  — called from _InotifyMemWatcher._run()
    # ------------------------------------------------------------------

    def _on_inotify_open(
        self,
        epoch: int,
        anonymous: bool,
        hits: List[Tuple[int, List[str]]],
    ) -> None:
        """
        Three outcomes:

        (a) hits non-empty  → named reader found; enqueue snapshot normally.
        (b) anonymous=True  → reader exists but is higher-privilege; emit
                              anonymous-open dossier with 1 s rate-limit log.
        (c) hits empty, anonymous=False → self-open or kernel artefact;
                              silent (no log, no wake).
        """
        if hits:
            # (a) Named hit
            for pid, fd_hits in hits:
                exe     = _read_exe(pid)
                cmdline = _read_cmdline(pid)
                enqueued = self._enqueue_snapshot(
                    pid, fd_hits, exe, cmdline, epoch, source="inotify"
                )
                if enqueued:
                    self.watcher_hit_count += 1
                    self._hlog(
                        f"[hunter] inotify HIT: pid={pid}  exe={exe!r}"
                        f"  fd_hits={fd_hits}  epoch={epoch}"
                    )
            return

        if anonymous:
            # (b) Anonymous open — higher-privilege opener
            self.watcher_anon_count += 1
            now = time.monotonic()
            if now - self._last_anon_log_ts >= _ANON_LOG_COOLDOWN_S:
                self._last_anon_log_ts = now
                self._hlog(
                    f"[hunter] inotify ANONYMOUS-OPEN at epoch={epoch}"
                    f"  (opener is higher-privilege; /proc/*/fd unreadable)"
                    f"  total_anon={self.watcher_anon_count}"
                )
                # Build / update anonymous dossier
                existing = self._dossiers.get(self._ANON_KEY)
                dossier  = _build_anonymous_dossier(epoch, existing)
                self._dossiers[self._ANON_KEY]   = dossier
                self._dossier_ts[self._ANON_KEY] = time.time()
                self.total_suspects_found += 1

                self._hlog(f"[hunter] SUSPECT (anonymous-open) → {dossier.summary()}")
                _emit_dossier(
                    self._arena, self._tpm_seed,
                    self._packet_id, dossier,
                    slot=self._cfg.ipc_slot,
                )
                self._packet_id += 1

                # Wake the hunter for its active-scan pass
                with self._lock:
                    if not self._active:
                        self._active    = True
                        self._low_count = 0
                        self.trigger_count += 1
                        self._wake_event.set()
            return

        # (c) Self-open / kernel artefact — silent

    # ------------------------------------------------------------------
    # Fallback poller callback
    # ------------------------------------------------------------------

    def _on_poller_hit(
        self,
        pid: int, fd_hits: List[str],
        exe: str, cmdline: str,
    ) -> None:
        epoch    = self._current_epoch
        enqueued = self._enqueue_snapshot(
            pid, fd_hits, exe, cmdline, epoch, source="fd-poller-fallback"
        )
        if enqueued:
            self.poller_hit_count += 1
            self._hlog(
                f"[hunter] fd-poller HIT: pid={pid}  exe={exe!r}"
                f"  fd_hits={fd_hits}  epoch~={epoch}"
            )

    # ------------------------------------------------------------------
    # Snapshot queue
    # ------------------------------------------------------------------

    def _enqueue_snapshot(
        self,
        pid: int, fd_hits: List[str],
        exe: str, cmdline: str,
        epoch: int,
        source: str = "notify",
    ) -> bool:
        key = (pid, epoch)
        with self._lock:
            if key in self._seen_snap_keys:
                return False
            self._seen_snap_keys.add(key)
            snap = _FdSnapshot(
                pid=pid, fd_hits=fd_hits,
                exe=exe, cmdline=cmdline, epoch=epoch,
            )
            self._pending_fd_hits.append(snap)

            if not self._active:
                self._active    = True
                self._low_count = 0
                self.trigger_count += 1
                self._hlog(
                    f"[hunter] TRIGGERED at epoch={epoch}"
                    f"  reason=[direct-fd-hit pid={pid} via {source}]"
                    f"  initiating scan"
                )
                self._wake_event.set()

        return True

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._thread.start()
        self._watcher.start()

        if self._watcher.available:
            self._hlog(
                "[hunter] ObserverHunter started — IDLE"
                f" (trigger_score={self._cfg.trigger_score:.2f}"
                f", hunter_interval={self._cfg.hunter_interval}s"
                f", detection=inotify-IN_OPEN [Tier 1]"
                f", debounce={_OPEN_DEBOUNCE_S}s"
                f", anon_cooldown={_ANON_LOG_COOLDOWN_S}s"
                f", log={self.log_path or 'disabled'})"
            )
        else:
            self._hlog(
                "[hunter] WARNING: inotify on /proc/mem unavailable"
                " — falling back to _FdPoller (Tier 2)."
                " Cross-UID readers (e.g. sudo) may be missed."
            )
            self._poller.start()
            self._hlog(
                "[hunter] ObserverHunter started — IDLE"
                f" (trigger_score={self._cfg.trigger_score:.2f}"
                f", hunter_interval={self._cfg.hunter_interval}s"
                f", detection=fd-poller-fallback [{self._cfg.fd_poll_interval}s]"
                f", log={self.log_path or 'disabled'})"
            )

    def stop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()
        self._thread.join(timeout=5.0)
        self._watcher.stop()
        if not self._watcher.available:
            self._poller.stop()
        self._logger.close()

    def notify_score(self, score: float, epoch: int) -> None:
        """
        Called from the game loop each epoch.

        1. Update current epoch.
        2. Tier 3 belt-and-suspenders fd poll.
        3. Wake/idle hunter based on score or direct hit.
        """
        with self._lock:
            self._current_epoch = epoch

        # Tier 3: epoch-boundary fd poll
        live_hits, _ = _find_foreign_mem_handles(self._own_pid, self._mem_target)
        for pid, fd_hits in live_hits:
            exe     = _read_exe(pid)
            cmdline = _read_cmdline(pid)
            self._enqueue_snapshot(
                pid, fd_hits, exe, cmdline, epoch, source="notify_score"
            )

        direct_hit = bool(live_hits)

        with self._lock:
            self._current_score = score
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

    def _run(self) -> None:
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

    def _scan(self, epoch: int) -> None:
        self.total_scans += 1
        now = time.time()

        # Phase A: drain snapshot queue
        with self._lock:
            pending = list(self._pending_fd_hits)
            self._pending_fd_hits.clear()
            self._seen_snap_keys = {
                k for k in self._seen_snap_keys if k[1] >= epoch - 5
            }

        reported_pids: Set[int] = set()
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

        # Phase B: live scan for persistent readers
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
        if self._watcher.available:
            detection_line = (
                f"  HUNTER_DETECTION:      inotify-IN_OPEN (Tier 1)"
                f"  raw_events={self._watcher.open_events}"
                f"  fired={self._watcher.open_fired}"
                f"  close_events={self._watcher.close_events}"
                f"  named_hits={self.watcher_hit_count}"
                f"  anon_hits={self.watcher_anon_count}"
            )
        else:
            detection_line = (
                f"  HUNTER_DETECTION:      fd-poller-fallback (Tier 2)"
                f"  polls={self._poller.poll_count}"
                f"  interval={self._cfg.fd_poll_interval}s"
                f"  poller_hits={self.poller_hit_count}"
            )
        lines = [
            f"  HUNTER_TRIGGER_COUNT:  {self.trigger_count}",
            f"  HUNTER_TOTAL_SCANS:    {self.total_scans}",
            f"  HUNTER_SUSPECTS:       {self.total_suspects_found}",
            f"  HUNTER_DOSSIERS:       {len(self._dossiers)}",
            detection_line,
            f"  HUNTER_LOG_FILE:       {self.log_path or 'disabled'}",
        ]
        for pid, d in self._dossiers.items():
            lines.append(f"    └─ {d.summary()}")
        return "\n".join(lines)
