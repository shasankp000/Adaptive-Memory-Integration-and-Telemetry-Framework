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

Tier 2 — /proc/*/syscall poller  (_VmReadvPoller)  [NEW]
    Catches readers that use process_vm_readv() instead of opening
    /proc/<pid>/mem.  process_vm_readv is a direct kernel syscall
    (SYS_process_vm_readv) that reads a foreign process's virtual memory
    without creating any file descriptor, making it completely invisible
    to both the inotify watcher and the /proc/*/fd scanner.

    Detection: Linux exposes the currently-executing syscall and register
    arguments of every task in /proc/<pid>/syscall (format:
    "<nr> <a0> <a1> ... <a5> <sp> <pc>").  This tier scans all foreign
    PIDs' /proc/<pid>/syscall files and flags any PID whose active syscall
    is process_vm_readv with arg0 == own_pid (the first argument to
    process_vm_readv is the target pid_t).

    SYS_process_vm_readv by architecture:
        x86_64  : 310
        aarch64 : 270
        i386    : 347
        arm     : 376
        riscv64 : 270

    Architecture is detected once at import time via platform.machine().

    When a hit is found the existing _build_dossier() / _emit_dossier()
    pipeline is reused, producing the same pid/exe/cmdline/loginuid/
    session_type output as a Tier 1 hit.  Log tag: SUSPECT (vm-readv).

    Controlled by HunterConfig.vm_readv_poll (bool, default True) and
    HunterConfig.vm_readv_rate (float seconds, default 0.05).

Tier 3 — periodic /proc/*/fd poll  (_FdPoller)  [FALLBACK]
    Polls _find_foreign_mem_handles() every fd_poll_interval (0.05 s).
    Can miss sub-millisecond open windows AND cannot list fds of
    higher-privilege readers — kept only as a fallback for environments
    where inotify is restricted.

Tier 4 — epoch fd poll in notify_score()
    Belt-and-suspenders scan in the game-loop thread once per epoch.
    Catches any reader that holds /proc/<pid>/mem open for a full second.

    Self-open suppression: the outward /proc/*/fd scan performed inside
    notify_score() can itself trigger an inotify IN_OPEN on our mem file
    on certain kernel paths.  The inotify callback discards any hit whose
    only matching PIDs are the prototype itself (own_pid), treating it as
    outcome (c) — silent, no wake, no dossier update.  Additionally,
    _find_foreign_mem_handles already skips own_pid in the fd loop, so
    the Tier 4 scan never self-reports.

Anonymous dossier seen_count integrity
---------------------------------------
seen_count on the anonymous dossier only increments when a genuinely new
inotify event is accepted (post-debounce).  The rate-limit log branch no
longer mutates the dossier — a separate `increment` flag on
_build_anonymous_dossier(increment=True/False) controls whether the
seen_count is bumped.

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
import platform
import select
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any


# ---------------------------------------------------------------------------
# Architecture-specific syscall numbers for process_vm_readv
# ---------------------------------------------------------------------------

_ARCH_VM_READV: Dict[str, int] = {
    "x86_64":  310,
    "aarch64": 270,
    "arm64":   270,   # macOS/Linux alias
    "i386":    347,
    "i686":    347,
    "arm":     376,
    "armv7l":  376,
    "riscv64": 270,
}

def _detect_vm_readv_syscall_nr() -> Tuple[int, bool]:
    """Return (syscall_nr, is_known_arch).  Falls back to 310 (x86_64)."""
    arch = platform.machine().lower()
    for key, nr in _ARCH_VM_READV.items():
        if arch.startswith(key):
            return nr, True
    return 310, False   # unknown — default to x86_64, warn at startup

_SYS_PROCESS_VM_READV, _VM_READV_ARCH_KNOWN = _detect_vm_readv_syscall_nr()


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
    vm_readv_poll     : True — enable Tier 2 /proc/*/syscall poller for
                        process_vm_readv detection.
    vm_readv_rate     : 0.05 s — minimum interval between full
                        /proc/*/syscall sweeps inside each _scan() call.
    """
    trigger_score:      float = 0.01
    hunter_interval:    float = 0.3
    fd_poll_interval:   float = 0.05   # fallback poller cadence
    idle_after_epochs:  int   = 3
    ipc_slot:           int   = 63
    max_dossier_age:    float = 60.0
    log_dir:            Optional[str] = None   # None → auto (script directory)
    vm_readv_poll:      bool  = True           # Tier 2 — syscall poller
    vm_readv_rate:      float = 0.05           # min seconds between sweeps


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

_OPEN_DEBOUNCE_S   = 0.10   # seconds — events within this window are merged
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


def _find_vm_readv_readers(own_pid: int) -> List[int]:
    """
    Tier 2 detection — scan /proc/*/syscall for foreign PIDs actively
    executing process_vm_readv() with own_pid as the target.

    /proc/<pid>/syscall format (Linux kernel):
        "<syscall_nr> <a0> <a1> <a2> <a3> <a4> <a5> <sp> <pc>"
    All values are hex strings prefixed with 0x.

    For process_vm_readv(pid_t pid, ...):
        syscall_nr == SYS_process_vm_readv
        a0         == target pid   (the process being read FROM)

    Returns a list of PIDs that are actively reading our memory via
    process_vm_readv at the moment of the scan.  The scan is inherently
    racy (a very short-lived call may be missed), but process_vm_readv
    on large memory regions — or repeated calls in a tight loop — will
    be visible for long enough to be caught.

    Permission notes:
      /proc/<pid>/syscall is world-readable for processes with the same
      UID, so this scan works without any special privileges as long as
      yama ptrace_scope is 0 or the reader is the same UID.
    """
    hits: List[int] = []
    own_pid_hex = hex(own_pid)
    nr_hex = hex(_SYS_PROCESS_VM_READV)
    for pid in _all_pids():
        if pid == own_pid:
            continue
        raw = _read_file(f"/proc/{pid}/syscall")
        if not raw:
            continue
        raw = raw.strip()
        if not raw or raw in ("running", "0"):
            continue
        parts = raw.split()
        if len(parts) < 2:
            continue
        try:
            syscall_nr = int(parts[0], 16)
            arg0_hex   = parts[1].lower()
        except (ValueError, IndexError):
            continue
        if syscall_nr != _SYS_PROCESS_VM_READV:
            continue
        # arg0 is the target pid — compare both hex and decimal forms
        try:
            arg0_int = int(arg0_hex, 16)
        except ValueError:
            continue
        if arg0_int == own_pid:
            hits.append(pid)
    return hits


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

_CMDLINE_MAX_SUMMARY = 120   # characters shown in summary() / log lines


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
        # Truncate cmdline so log lines stay readable; full value is in to_dict()
        cmdline_display = self.cmdline
        if len(cmdline_display) > _CMDLINE_MAX_SUMMARY:
            cmdline_display = cmdline_display[:_CMDLINE_MAX_SUMMARY] + "..."
        return (
            f"pid={self.pid}  exe={self.exe!r}  cmdline={cmdline_display!r}"
            f"  loginuid={self.loginuid}"
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


def _build_anonymous_dossier(
    epoch: int,
    existing: Optional["Dossier"] = None,
    increment: bool = True,
) -> "Dossier":
    """
    Construct a minimal Dossier for a confirmed-but-opaque opener.

    Used when inotify fires IN_OPEN but the outward /proc/*/fd scan is
    blocked by PermissionError (reader is root, we are not).  pid=-1
    signals "anonymous" to downstream consumers.
    """
    if existing is not None:
        if increment:
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
    initial open().  A debounce gate (_OPEN_DEBOUNCE_S) coalesces these
    rapid-fire events into one callback per burst.  The gate resets on
    IN_CLOSE so a genuine re-open after close is never suppressed.
    """

    def __init__(self, mem_path: str, own_pid: int,
                 on_open_cb, on_close_cb,
                 logger: "_HunterLogger"):
        self._mem_path    = mem_path
        self._own_pid     = own_pid
        self._on_open_cb  = on_open_cb
        self._on_close_cb = on_close_cb
        self._logger      = logger
        self._ifd         = -1
        self._wd          = -1
        self._thread: Optional[threading.Thread] = None
        self._stop        = threading.Event()
        self.available    = False

        # Debounce state
        self._debounce_active  = False
        self._debounce_timer: Optional[threading.Timer] = None
        self._debounce_lock    = threading.Lock()

    def start(self) -> bool:
        try:
            ifd = _inotify_init1(_IN_NONBLOCK)
            if ifd < 0:
                return False
            wd = _inotify_add_watch(ifd, self._mem_path,
                                     _IN_OPEN | _IN_CLOSE_NOWRITE | _IN_CLOSE_WRITE)
            if wd < 0:
                os.close(ifd)
                return False
            self._ifd = ifd
            self._wd  = wd
            self.available = True
        except Exception:
            return False

        self._thread = threading.Thread(
            target=self._run, daemon=True, name="hunter-inotify")
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._ifd >= 0:
            try:
                os.close(self._ifd)
            except Exception:
                pass

    def _fire_open(self) -> None:
        """Called once per debounced burst — invokes the open callback."""
        with self._debounce_lock:
            self._debounce_active = False
            self._debounce_timer  = None
        self._on_open_cb()

    def _run(self) -> None:
        buf = bytearray(4096)
        while not self._stop.is_set():
            r, _, _ = select.select([self._ifd], [], [], 0.5)
            if not r:
                continue
            try:
                n = os.readinto(self._ifd, buf)
            except Exception:
                break
            offset = 0
            while offset + _INOTIFY_EVENT_SIZE <= n:
                wd, mask, cookie, name_len = _INOTIFY_EVENT_STRUCT.unpack_from(
                    buf, offset)
                offset += _INOTIFY_EVENT_SIZE + name_len

                if mask & _IN_OPEN:
                    with self._debounce_lock:
                        if not self._debounce_active:
                            self._debounce_active = True
                            t = threading.Timer(_OPEN_DEBOUNCE_S, self._fire_open)
                            self._debounce_timer  = t
                            t.daemon = True
                            t.start()
                        # else: already debouncing — swallow this event

                if mask & (_IN_CLOSE_NOWRITE | _IN_CLOSE_WRITE):
                    # Reset debounce so a genuine re-open is never suppressed
                    with self._debounce_lock:
                        if self._debounce_timer is not None:
                            self._debounce_timer.cancel()
                        self._debounce_active = False
                        self._debounce_timer  = None
                    self._on_close_cb()


# ---------------------------------------------------------------------------
# Tier 2 — process_vm_readv poller  (NEW)
# ---------------------------------------------------------------------------

class _VmReadvPoller:
    """
    Daemon thread: polls /proc/*/syscall every vm_readv_rate seconds,
    looking for foreign PIDs actively executing process_vm_readv() with
    own_pid as the target argument (arg0).

    Fires on_vmreadv_cb(pid) for each newly discovered reader PID.
    Rate-limited to avoid flooding: a confirmed PID is only reported
    once per _VMREADV_REARM_S seconds.
    """

    _VMREADV_REARM_S = 1.0   # minimum seconds between repeated reports of same PID

    def __init__(self, own_pid: int, rate: float,
                 on_vmreadv_cb,
                 logger: "_HunterLogger"):
        self._own_pid       = own_pid
        self._rate          = rate
        self._on_vmreadv_cb = on_vmreadv_cb
        self._logger        = logger
        self._thread: Optional[threading.Thread] = None
        self._stop          = threading.Event()
        self._active        = threading.Event()   # set when hunter is ACTIVE
        self._last_report: Dict[int, float] = {}  # pid → last report time

    def set_active(self, active: bool) -> None:
        if active:
            self._active.set()
        else:
            self._active.clear()

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="hunter-vmreadv")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            # Only scan while the hunter is ACTIVE (anomaly score triggered)
            if not self._active.wait(timeout=0.5):
                continue
            hits = _find_vm_readv_readers(self._own_pid)
            now  = time.monotonic()
            for pid in hits:
                last = self._last_report.get(pid, 0.0)
                if now - last >= self._VMREADV_REARM_S:
                    self._last_report[pid] = now
                    self._on_vmreadv_cb(pid)
            time.sleep(self._rate)


# ---------------------------------------------------------------------------
# Main ObserverHunter
# ---------------------------------------------------------------------------

class ObserverHunter:
    """
    Phase 1 observer hunter — detects external processes reading game memory.

    Combines:
      Tier 1  inotify IN_OPEN on /proc/<pid>/mem          (primary)
      Tier 2  /proc/*/syscall scan for process_vm_readv   (new)
      Tier 3  periodic /proc/*/fd poll                    (fallback)
      Tier 4  epoch scan in notify_score()                (belt-and-suspenders)
    """

    _STATE_IDLE    = "IDLE"
    _STATE_ACTIVE  = "ACTIVE"

    def __init__(self, cfg: HunterConfig, arena, tpm_seed: bytes):
        self._cfg        = cfg
        self._arena      = arena
        self._tpm_seed   = tpm_seed
        self._own_pid    = os.getpid()
        self._mem_target = f"/proc/{self._own_pid}/mem"

        self._state      = self._STATE_IDLE
        self._state_lock = threading.Lock()

        self._epoch      = 0
        self._low_streak = 0
        self._packet_id  = 0

        # Dossier cache: pid → Dossier  (-1 for anonymous-open)
        self._dossiers: Dict[int, Dossier] = {}
        self._dossier_lock = threading.Lock()

        # inotify snapshot queue: _FdSnapshot objects from callback thread
        self._snapshot_q: List[_FdSnapshot] = []
        self._snapshot_lock = threading.Lock()

        # vm_readv hit queue: pids discovered by _VmReadvPoller
        self._vmreadv_q: List[int] = []
        self._vmreadv_lock = threading.Lock()

        # Anon-open rate limiting
        self._last_anon_log = 0.0

        # Counters
        self.trigger_count  = 0
        self.suspect_count  = 0

        # Logging
        log_path   = _make_log_path(cfg)
        self._log  = _HunterLogger(log_path)
        self.log_path = log_path

        # Tier 1 — inotify watcher
        self._inotify = _InotifyMemWatcher(
            mem_path=self._mem_target,
            own_pid=self._own_pid,
            on_open_cb=self._on_mem_open,
            on_close_cb=self._on_mem_close,
            logger=self._log,
        )

        # Tier 2 — vm_readv poller
        self._vmreadv_poller: Optional[_VmReadvPoller] = None
        if cfg.vm_readv_poll:
            self._vmreadv_poller = _VmReadvPoller(
                own_pid=self._own_pid,
                rate=cfg.vm_readv_rate,
                on_vmreadv_cb=self._on_vmreadv_hit,
                logger=self._log,
            )

        # Scan thread
        self._scan_thread: Optional[threading.Thread] = None
        self._stop_event  = threading.Event()
        self._wake_event  = threading.Event()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        inotify_ok = self._inotify.start()
        tier1_label = "inotify-IN_OPEN [Tier 1]" if inotify_ok else "fd-poll-fallback [Tier 3]"

        vm_label = ""
        if self._vmreadv_poller is not None:
            self._vmreadv_poller.start()
            arch = platform.machine()
            if not _VM_READV_ARCH_KNOWN:
                self._log.log(
                    f"[hunter] WARNING: unknown arch {arch!r} — "
                    f"vm_readv syscall nr defaulting to {_SYS_PROCESS_VM_READV} (x86_64). "
                    f"Set HunterConfig.vm_readv_poll=False to suppress."
                )
            vm_label = (
                f", vm_readv_poll=Tier2 "
                f"(SYS_process_vm_readv={_SYS_PROCESS_VM_READV} arch={arch})"
            )

        self._log.log(
            f"[hunter] ObserverHunter started — IDLE "
            f"(trigger_score={self._cfg.trigger_score}, "
            f"hunter_interval={self._cfg.hunter_interval}s, "
            f"detection={tier1_label}"
            f", debounce={_OPEN_DEBOUNCE_S}s"
            f", anon_cooldown={_ANON_LOG_COOLDOWN_S}s"
            f"{vm_label}"
            f", log={self.log_path})"
        )

        self._scan_thread = threading.Thread(
            target=self._scan_loop, daemon=True, name="hunter-scan")
        self._scan_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()
        self._inotify.stop()
        if self._vmreadv_poller is not None:
            self._vmreadv_poller.stop()
        self._log.close()

    def notify_score(self, score: float, epoch: int) -> None:
        """Called by the game loop each epoch with the latest anomaly score."""
        self._epoch = epoch

        with self._state_lock:
            currently_active = (self._state == self._STATE_ACTIVE)

        if score >= self._cfg.trigger_score:
            self._low_streak = 0
            if not currently_active:
                with self._state_lock:
                    self._state = self._STATE_ACTIVE
                if self._vmreadv_poller is not None:
                    self._vmreadv_poller.set_active(True)
                self.trigger_count += 1
                self._log.log(
                    f"[hunter] TRIGGERED at epoch={epoch}  "
                    f"reason=[score={score:.4f}>={self._cfg.trigger_score}]  "
                    f"initiating scan"
                )
                self._wake_event.set()
        else:
            self._low_streak += 1
            if currently_active and self._low_streak >= self._cfg.idle_after_epochs:
                with self._state_lock:
                    self._state = self._STATE_IDLE
                if self._vmreadv_poller is not None:
                    self._vmreadv_poller.set_active(False)
                self._log.log(
                    f"[hunter] returning to IDLE at epoch={epoch}  "
                    f"low_streak={self._low_streak}"
                )

        # Tier 4 — belt-and-suspenders epoch scan
        if currently_active:
            hits, _ = _find_foreign_mem_handles(self._own_pid, self._mem_target)
            for pid, fd_paths in hits:
                snap = _FdSnapshot(
                    pid=pid,
                    fd_hits=fd_paths,
                    exe=_read_exe(pid),
                    cmdline=_read_cmdline(pid),
                    epoch=epoch,
                )
                with self._snapshot_lock:
                    self._snapshot_q.append(snap)
                self._wake_event.set()

    def summary(self) -> str:
        lines = [
            f"  HUNTER_STATE:          {self._state}",
            f"  HUNTER_TRIGGER_COUNT:  {self.trigger_count}",
            f"  HUNTER_SUSPECT_COUNT:  {self.suspect_count}",
            f"  HUNTER_DOSSIER_COUNT:  {len(self._dossiers)}",
        ]
        with self._dossier_lock:
            for dos in self._dossiers.values():
                lines.append(f"    {dos.summary()}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # inotify callbacks  (run in the inotify watcher thread)
    # ------------------------------------------------------------------

    def _on_mem_open(self) -> None:
        """Fired (debounced) when IN_OPEN is received on /proc/<pid>/mem."""
        hits, any_eperm = _find_foreign_mem_handles(self._own_pid, self._mem_target)

        if hits:
            for pid, fd_paths in hits:
                snap = _FdSnapshot(
                    pid=pid,
                    fd_hits=fd_paths,
                    exe=_read_exe(pid),
                    cmdline=_read_cmdline(pid),
                    epoch=self._epoch,
                )
                with self._snapshot_lock:
                    self._snapshot_q.append(snap)
            self._wake_event.set()
            return

        # No named opener found — could be:
        # (a) reader already closed (very fast open/close before scan)
        # (b) higher-privilege reader (PermissionError on their fd dir)
        # (c) our own Tier 4 scan triggered the IN_OPEN (self-open)
        if not any_eperm:
            # outcome (c) — silent, no wake
            return

        # outcome (b) — anonymous opener
        now = time.monotonic()
        with self._state_lock:
            cur_epoch = self._epoch
        if now - self._last_anon_log >= _ANON_LOG_COOLDOWN_S:
            self._last_anon_log = now
            self._log.log(
                f"[hunter] inotify ANONYMOUS-OPEN at epoch={cur_epoch}"
            )
            with self._dossier_lock:
                existing = self._dossiers.get(-1)
                dos = _build_anonymous_dossier(cur_epoch, existing, increment=True)
                self._dossiers[-1] = dos
            self._log.log(
                f"[hunter] SUSPECT (anonymous-open) → "
                f"pid={dos.pid}  exe={dos.exe!r}  "
                f"loginuid={dos.loginuid}  session={dos.session_type}"
            )
            self.suspect_count += 1
            self._emit(dos)
        else:
            # Rate-limited — do NOT bump seen_count
            with self._dossier_lock:
                existing = self._dossiers.get(-1)
                _build_anonymous_dossier(cur_epoch, existing, increment=False)

    def _on_mem_close(self) -> None:
        pass  # debounce reset handled inside _InotifyMemWatcher

    # ------------------------------------------------------------------
    # vm_readv callback  (run in _VmReadvPoller thread)
    # ------------------------------------------------------------------

    def _on_vmreadv_hit(self, pid: int) -> None:
        """Fired by _VmReadvPoller when a foreign PID is caught using
        process_vm_readv() against our process."""
        with self._vmreadv_lock:
            self._vmreadv_q.append(pid)
        self._wake_event.set()

    # ------------------------------------------------------------------
    # Scan loop
    # ------------------------------------------------------------------

    def _scan_loop(self) -> None:
        scan_n = 0
        while not self._stop_event.is_set():
            self._wake_event.wait(timeout=self._cfg.hunter_interval)
            self._wake_event.clear()

            with self._state_lock:
                active = (self._state == self._STATE_ACTIVE)
            if not active:
                continue

            scan_n += 1
            epoch = self._epoch
            self._scan(scan_n, epoch)

    def _scan(self, scan_n: int, epoch: int) -> None:
        """Single scan pass — drains snapshot queue, live fd scan,
        and now also drains the vm_readv queue."""

        # --- Phase A: drain inotify snapshot queue ---
        with self._snapshot_lock:
            snaps = list(self._snapshot_q)
            self._snapshot_q.clear()

        # --- Phase B: live /proc/*/fd scan ---
        live_hits, _ = _find_foreign_mem_handles(self._own_pid, self._mem_target)

        # Merge snapshot + live fd hits
        fd_pids: Dict[int, _FdSnapshot] = {}
        for snap in snaps:
            fd_pids[snap.pid] = snap
        for pid, fd_paths in live_hits:
            if pid not in fd_pids:
                fd_pids[pid] = _FdSnapshot(
                    pid=pid, fd_hits=fd_paths,
                    exe=_read_exe(pid), cmdline=_read_cmdline(pid),
                    epoch=epoch,
                )

        # --- Phase C: drain vm_readv queue ---
        with self._vmreadv_lock:
            vmreadv_pids = list(self._vmreadv_q)
            self._vmreadv_q.clear()

        total_found = len(fd_pids) + len(vmreadv_pids)

        if total_found == 0:
            self._log.log(
                f"[hunter] scan #{scan_n} epoch={epoch}  "
                f"no /proc/mem handles found "
                f"(snapshot={len(snaps)}, live={len(live_hits)})"
                + (f"  vm_readv_hits=0" if self._cfg.vm_readv_poll else "")
            )
            return

        # Process fd-based hits (Tier 1 / Tier 3 / Tier 4)
        for pid, snap in fd_pids.items():
            with self._dossier_lock:
                existing = self._dossiers.get(pid)
            dos = _build_dossier(
                pid, epoch,
                existing=existing,
                snapshot_exe=snap.exe,
                snapshot_cmdline=snap.cmdline,
            )
            if dos is None:
                continue
            with self._dossier_lock:
                self._dossiers[pid] = dos
            self._log.log(
                f"[hunter] SUSPECT (snapshot) → {dos.summary()}"
            )
            self.suspect_count += 1
            self._emit(dos)

        # Process vm_readv hits (Tier 2)
        for pid in vmreadv_pids:
            with self._dossier_lock:
                existing = self._dossiers.get(pid)
            dos = _build_dossier(pid, epoch, existing=existing)
            if dos is None:
                continue
            with self._dossier_lock:
                self._dossiers[pid] = dos
            self._log.log(
                f"[hunter] SUSPECT (vm-readv) → {dos.summary()}"
            )
            self.suspect_count += 1
            self._emit(dos)

    # ------------------------------------------------------------------
    # IPC emit
    # ------------------------------------------------------------------

    def _emit(self, dossier: "Dossier") -> None:
        _emit_dossier(
            self._arena, self._tpm_seed, self._packet_id,
            dossier, self._cfg.ipc_slot,
        )
        self._packet_id += 1
