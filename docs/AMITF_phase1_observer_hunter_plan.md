# AMITF Phase 1 — Observer Hunter: Reactive Design Plan

Phase 1 shifts from **passive awareness** (knowing *that* we are being observed) to **active attribution**
(knowing *who* and *what* is observing us). The target has detected observation cadence since v6; it now
needs to identify the observer's process, binary, and owning user — entirely from userspace, without
touching the kernel.

---

## Objective

Build a reactive observer hunter that:

1. **Sleeps** until the existing anomaly scoring system crosses a suspicion threshold
2. **Scans `/proc`** for processes with open handles to our memory or overlapping address-space access
3. **Attributes** each suspect to a PID, binary path, invocation, UID, and login user
4. **Emits** the attribution dossier through the existing v11 secure IPC channel
5. **Returns to sleep** once suspicion drops back to baseline

No kernel modules, no eBPF, no elevated privileges required — pure userspace `/proc` filesystem reads.

---

## Trigger Condition

The hunter thread wakes only when:

- Anomaly score reaches `[MEDIUM]` or higher, **AND**
- At least N telemetry hits recorded in the last M epochs

This prevents the hunter from activating on noise spikes and ensures it only profiles genuine
observation activity. The threshold mirrors the existing `POISON_ACTIVATIONS` logic from v7.

---

## Hunter Thread State Machine

```
IDLE
  │
  │  anomaly_score >= MEDIUM threshold
  ▼
TRIGGERED — log "Observer suspected, initiating scan"
  │
  │  scan /proc/*/fd for open handles to /proc/[our_pid]/mem
  │  scan /proc/*/maps / syscall for process_vm_readv candidates
  ▼
ATTRIBUTING — for each suspect PID:
  │  read exe, cmdline, status (uid/gid), loginuid, environ
  │  build attribution dossier
  ▼
REPORTING — emit dossier to IPC arena (v11 SHAKE-256 masked channel)
  │
  │  rescan every HUNTER_INTERVAL seconds while anomaly >= MEDIUM
  │  until anomaly drops to LOW for K consecutive epochs
  ▼
IDLE
```

---

## Key Design Decisions

### HUNTER_INTERVAL

The hunter rescans at **2.3 second intervals** while active — a deliberately non-round, prime-ish
value that won't phase-lock with the 1.0 s game loop epoch. This prevents the hunter's own
scanning cadence from being fingerprinted as a paired signal alongside the write/scrub cycle.

### False Positive Guard

Not every process with `/proc/[pid]/mem` open is a reader. Filters applied:

- Open fd symlink must point specifically to `/proc/[our_pid]/mem`
- OR the suspect's `rw-p` regions must overlap our process address space
- `loginuid != 0` preferred — excludes system daemons running as root with no login session
- PID must differ from our own PID and from known Python runtime child PIDs

### Dossier Structure

Each attributed suspect produces the following record:

```python
{
  "pid":             int,   # transient process ID
  "exe":             str,   # resolved /proc/pid/exe symlink — full binary path
  "cmdline":         str,   # full invocation string from /proc/pid/cmdline
  "uid":             int,   # effective user ID from /proc/pid/status
  "gid":             int,   # effective group ID
  "loginuid":        int,   # PAM login UID — immutable across sudo/su, golden attribution field
  "environ_keys":    list,  # environment variable KEYS only (not values) — enough to classify session
  "first_seen_epoch": int,  # game loop epoch when first detected
  "last_seen_epoch":  int,  # most recent epoch the PID appeared in a scan
  "seen_count":       int,  # number of hunter scans this PID appeared in
}
```

### `environ_keys` — Keys Only, Not Values

Only the *names* of environment variables are recorded, not their values. This is sufficient to
classify the session type without capturing potentially sensitive data:

| Key present | Interpretation |
|---|---|
| `SSH_CONNECTION` | Remote attacker — not local |
| `DISPLAY` (no SSH) | Local GUI session |
| `VIRTUAL_ENV` | Python venv — matches script-based reader profile (v2–v5 readers) |
| `SUDO_USER` | Privilege-escalated run — real `loginuid` still leaks through |
| None of the above | Headless/service context — likely an automated tool |

---

## Attribution Sources (all `/proc`, pure userspace)

| Source | Field extracted | Purpose |
|---|---|---|
| `/proc/[pid]/fd/*` | Symlinks to `/proc/[our_pid]/mem` | Primary reader detection |
| `/proc/[pid]/exe` | Resolved binary path | Tool identification |
| `/proc/[pid]/cmdline` | Full invocation | Script name, flags, arguments |
| `/proc/[pid]/status` | `Uid`, `Gid` lines | Effective user/group |
| `/proc/[pid]/loginuid` | Login UID (PAM-set, immutable) | Permanent user attribution |
| `/proc/[pid]/environ` | Environment variable keys | Session type classification |
| `/proc/[pid]/syscall` | Current syscall (momentary) | `process_vm_readv` detection |
| `/proc/[pid]/wchan` | Kernel wait channel | Reader in `read`/`pread` confirms polling |

### Why `loginuid` is the Golden Field

`loginuid` is written by PAM at login time and is **immutable** for the entire session lifetime.
It survives `sudo`, `su`, `newgrp`, and container namespace shifts within the same session.
A reader running as root via `sudo python reader.py` still exposes the original login UID.
This is the field that ties the reader process back to a specific human account.

---

## Integration with Existing Stack

```
phase1_prototype.py
│
├── Game loop thread          ← v1–v11 full stack (unchanged)
├── Telemetry thread          ← canary watcher (unchanged)
└── Observer Hunter thread    ← NEW (phase1_tracker.py)
    │
    ├── Reads:  anomaly_score scalar (from swap_shared, already computed)
    ├── Writes: attribution dossier packets → IPC arena (v11 memfd channel)
    │           same SHAKE-256 rotating XOR mask as telemetry stream
    └── Sleeps: most of the time — only active when anomaly >= MEDIUM
```

- **Zero new IPC mechanisms** — dossier packets share the existing v11 `memfd` arena
- **Zero new threads beyond one** — single daemon thread, sleeping the majority of the time
- **Zero kernel interaction** — every read is a standard file open on `/proc`

---

## File Layout

```
phase1_tracker.py      ← observer hunter module (standalone, importable)
phase1_prototype.py    ← v12 full stack + hunter thread integrated
```

Keeping the hunter as a separate importable module:
- Allows standalone testing against any target PID
- Isolates the attribution logic for later C/Rust port
- Keeps `phase1_prototype.py` readable — hunter integration is a single thread spawn

---

## Validation Plan

A successful Phase 1 run confirms:

1. **Hunter stays IDLE** during clean epochs (no reader running) — zero false activations
2. **Hunter triggers** correctly when reader v5 is started and anomaly crosses MEDIUM
3. **Dossier populated** with correct `pid`, `exe` (points to Python binary), `cmdline`
   (contains `process_reader_v5.py`), `loginuid` matching the test user
4. **`VIRTUAL_ENV` key present** in `environ_keys` if reader launched from a venv
5. **Dossier emitted** through IPC arena with correct SHAKE-256 masking — readable on readback
6. **Hunter returns to IDLE** after reader process exits and anomaly drops to LOW for K epochs

---

## Open Questions / Future Extensions

- **Repeat-offender tracking**: if the same `loginuid` appears across multiple separate game
  sessions, the dossier can be cross-correlated server-side to build a behavioural profile.
- **Binary hash**: add `sha256(/proc/[pid]/exe)` to the dossier to fingerprint the exact reader
  build, not just its path.
- **Child process tracking**: some readers fork workers — hunter should follow the full process
  tree of any attributed suspect (`/proc/[pid]/task/*`, `/proc/[pid]/children`).
- **Network context**: `/proc/[pid]/net/tcp` can reveal open sockets — useful if the reader
  is exfiltrating data over a network connection in the same session.

---

*Phase 1 design finalised. Next step: implement `phase1_tracker.py`, then integrate into `phase1_prototype.py`.*
