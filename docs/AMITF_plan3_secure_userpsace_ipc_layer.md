# AMITF (Adaptive Memory Integration and Telemetry Framework)
## Phase 0 Blueprint: Secure Cross-Platform Inter-Process Communication (IPC)

This document expands on the Phase 0 architecture by detailing the **Secure User-Space IPC Layer**. When deploying your telemetry framework alongside a target process (like an engine or a game client), you must pass data between the two applications without leaving detectable footprints in standard system logs or creating predictable, static memory buffers that a hardware DMA card can track.

---

## 1. Architectural Philosophy: The Hidden Bridge

Traditional IPC mechanisms like standard TCP/UDP local sockets or named pipes introduce noticeable latency and leave clear trace signatures in operating system networking stacks. 

AMITF utilizes a **Volatile Shared Memory Arena** combined with **Per-Packet Rotating XOR Masking**. Instead of establishing a permanent stream, both programs map into an anonymous, RAM-backed file descriptor with no filesystem path.

```
┌───────────────────────────────┐          ┌───────────────────────────────┐
│     Target Game Process       │          │   AMITF Telemetry Framework   │
│   (e.g., CS2 Game Client)     │          │    (Polymorphic Exec Engine)  │
└───────────────┬───────────────┘          └───────────────┬───────────────┘
                │ Maps into anonymous arena                 │ Maps into anonymous arena
                ▼                                           ▼
        ┌───────────────────────────────────────────────────────┐
        │       RAM-Backed Shared Memory Arena (IPC)            │
        │  - Linux: memfd_create() — no /dev/shm path           │
        │  - Windows: Unnamed pagefile mapping (NULL name)      │
        │                                                       │
        │  [ Header: Obfuscated Sync Ring Buffer ]              │
        │    |──► [ Encrypted Telemetry Frame ]                 │
        └───────────────────────────────────────────────────────┘
```

### Anti-DMA Defenses Implemented in this Layer:
1. **Zero-Storage Footprint:** The shared buffer lives entirely in volatile RAM. No data ever hits the storage drive.
2. **Zero Filesystem Trace:** On Linux, `memfd_create()` creates a fully anonymous file descriptor — invisible to `ls /dev/shm` or any filesystem scanner. On Windows, an unnamed `CreateFileMapping()` call leaves no named object in the kernel object namespace.
3. **Ephemeral Ring Buffers:** Telemetry coordinates are structured as a fast Ring Buffer (Circular Queue). Data frames overwrite each other at high frequencies (e.g., every frame packet), preventing a DMA card from pulling historical position telemetry.
4. **Per-Packet Rotating XOR Masks:** Each field (X, Y, Z) gets its own independent mask, and masks rotate every packet derived from `(tpm_seed + packet_id)`. This defeats the delta-XOR attack: even if a DMA card captures two consecutive frames and XORs them, it recovers only noise — not plaintext deltas.

> **Why per-packet matters:** A single epoch-wide XOR mask means `frame1_x XOR frame2_x = real_x1 XOR real_x2` — the delta leaks in plaintext. Per-packet masks break this because each frame's mask is unique and unknown to the attacker.

---

## 2. Phase 0 IPC Implementation Code

This complete, cross-platform blueprint combines a **C Shared Library** for platform-native memory mappings and a **Python Orchestrator** to simulate the two distinct processes communicating in real-time.

### File 1: `secure_ipc.c`
*This C module creates and destroys anonymous shared memory handles natively across Linux and Windows. No named objects, no filesystem paths.*

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif

// Cross-platform function to create a truly anonymous shared memory arena in RAM.
// Linux: uses memfd_create() — no /dev/shm path, invisible to ls.
// Windows: uses unnamed CreateFileMapping (NULL name) — no kernel object namespace entry.
void* create_shared_arena(size_t size, int* out_handle) {
#ifdef _WIN32
    // NULL name = unnamed mapping, no entry in the kernel object namespace
    HANDLE hMapFile = CreateFileMappingA(
        INVALID_HANDLE_VALUE,    // Use paging file instead of a physical disk file
        NULL,                    // Default security
        PAGE_READWRITE,          // Read/write access
        0,                       // Maximum object size (high-order DWORD)
        (DWORD)size,             // Maximum object size (low-order DWORD)
        NULL                     // NULL = unnamed, leaves no traceable named object
    );
    if (hMapFile == NULL) return NULL;

    *out_handle = (int)(intptr_t)hMapFile;
    return MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, size);
#else
    // memfd_create: anonymous in-memory fd, no path in /dev/shm, invisible to scanners
    // MFD_CLOEXEC: fd is automatically closed on exec(), preventing leaks to child processes
    int fd = memfd_create("amitf_arena", MFD_CLOEXEC);
    if (fd == -1) return NULL;

    if (ftruncate(fd, size) == -1) {
        close(fd);
        return NULL;
    }

    *out_handle = fd;
    return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
#endif
}

// Cleans up memory mappings. No shm_unlink needed — there is no filesystem path to remove.
void close_shared_arena(void* address, size_t size, int handle) {
#ifdef _WIN32
    UnmapViewOfFile(address);
    CloseHandle((HANDLE)(intptr_t)handle);
#else
    munmap(address, size);
    close(handle);
    // No shm_unlink — memfd_create leaves no named path to unlink
#endif
}
```

#### Compilation Commands:
*   **On Linux:** `gcc -shared -o libsecure_ipc.so -fPIC secure_ipc.c -lrt`
*   **On Windows (via MinGW):** `gcc -shared -o libsecure_ipc.dll secure_ipc.c`

> **Note:** `memfd_create` requires Linux kernel 3.17+. Available on all modern distributions including SteamOS.

---

### File 2: `ipc_simulator.py`
*This script defines an encrypted data layout structure and simulates both sides of the application pipeline: a client writing telemetry updates and the AMITF engine reading and processing them. Uses per-packet rotating masks to defeat delta-XOR attacks.*

```python
import ctypes
import hashlib
import os
import sys
import time
import secrets

# 1. Platform Library Linking
lib_name = "./libsecure_ipc.so" if sys.platform != "win32" else "./libsecure_ipc.dll"
secure_ipc = ctypes.CDLL(os.path.abspath(lib_name))

# 2. Define the Low-Latency Shared Memory Packet Layout
# This structure must match byte-for-byte in both applications.
class TelemetryPacket(ctypes.Structure):
    _fields_ = [
        ("packet_id", ctypes.c_uint32),    # Incremental sequence tracking
        ("x_coord",   ctypes.c_uint32),    # Per-packet XOR-masked coordinate
        ("y_coord",   ctypes.c_uint32),    # Per-packet XOR-masked coordinate
        ("z_coord",   ctypes.c_uint32),    # Per-packet XOR-masked coordinate
    ]


def get_packet_masks(tpm_seed: bytes, packet_id: int) -> tuple:
    """
    Derives three independent per-field masks from (tpm_seed + packet_id).

    Rotating per-packet defeats the delta-XOR attack: since each packet uses
    a unique mask, an attacker XORing two consecutive captured frames gets
    noise, not plaintext coordinate deltas.
    """
    combined = tpm_seed + packet_id.to_bytes(4, byteorder=sys.byteorder)
    h = hashlib.shake_256(combined)
    mask_x = int.from_bytes(h.digest(4),       byteorder=sys.byteorder)
    mask_y = int.from_bytes(h.digest(8)[4:8],  byteorder=sys.byteorder)
    mask_z = int.from_bytes(h.digest(12)[8:12], byteorder=sys.byteorder)
    return mask_x, mask_y, mask_z


class AMITF_IPCEngine:
    def __init__(self, size=1024):
        self.arena_size = size
        self.handle = ctypes.c_int(0)

        # Call C to mount our anonymous shared RAM region (no filesystem path)
        raw_ptr = secure_ipc.create_shared_arena(
            self.arena_size,
            ctypes.byref(self.handle)
        )
        if not raw_ptr:
            raise MemoryError("[AMITF IPC] Failed to allocate volatile shared memory region.")

        # Cast the raw physical pointer to our Telemetry Packet structure
        self.shared_packet = TelemetryPacket.from_address(raw_ptr)
        self.raw_address = raw_ptr
        print(f"[AMITF IPC] Secure Bridge opened at memory address: {hex(self.raw_address)}")

    def simulate_game_client_write(self, x, y, z, packet_num, tpm_seed: bytes):
        """
        Simulates how the target application obfuscates telemetry and
        writes it into the shared memory page using per-packet masks.
        Each field gets an independent mask derived from (tpm_seed + packet_id).
        """
        mask_x, mask_y, mask_z = get_packet_masks(tpm_seed, packet_num)
        self.shared_packet.packet_id = packet_num
        self.shared_packet.x_coord = int(x) ^ mask_x
        self.shared_packet.y_coord = int(y) ^ mask_y
        self.shared_packet.z_coord = int(z) ^ mask_z

    def simulate_framework_read(self, tpm_seed: bytes):
        """
        Simulates the AMITF engine fetching the obfuscated packet,
        deriving the same per-packet masks, and recovering true coordinates.
        Both sides derive masks identically from the shared TPM seed + packet_id.
        """
        p_id = self.shared_packet.packet_id
        mask_x, mask_y, mask_z = get_packet_masks(tpm_seed, p_id)

        true_x = self.shared_packet.x_coord ^ mask_x
        true_y = self.shared_packet.y_coord ^ mask_y
        true_z = self.shared_packet.z_coord ^ mask_z

        return p_id, true_x, true_y, true_z

    def shutdown(self):
        secure_ipc.close_shared_arena(
            self.raw_address,
            self.arena_size,
            self.handle
        )
        print("[AMITF IPC] Volatile bridge successfully destroyed and unlinked.")


if __name__ == "__main__":
    print("--- AMITF Phase 0 Secure User-Space IPC Test ---")
    ipc = AMITF_IPCEngine()

    try:
        # Generate the TPM seed for this session epoch
        # In production this comes from the hardware TPM via /dev/tpm0 or TBS.dll
        tpm_seed = secrets.token_bytes(32)
        print(f"[AMITF IPC] Active TPM Epoch Seed: {tpm_seed.hex()}")

        # Step 1: Simulate Target Client writing state coordinates (packet #1)
        print("\n[Game Client] Sending encrypted position matrices...")
        ipc.simulate_game_client_write(x=1425, y=8210, z=340, packet_num=1, tpm_seed=tpm_seed)

        # Show what a DMA card actually sees in raw physical RAM right now
        print(f"[DMA Card Sniff Trace] Raw RAM -> X: {ipc.shared_packet.x_coord}, "
              f"Y: {ipc.shared_packet.y_coord}, Z: {ipc.shared_packet.z_coord}")
        print("[DMA Card Sniff Trace] (These values are meaningless without the TPM seed + packet_id)")

        # Step 2: Simulate writing a second packet to demonstrate mask rotation
        ipc.simulate_game_client_write(x=1430, y=8215, z=341, packet_num=2, tpm_seed=tpm_seed)
        print(f"[DMA Card Sniff Trace] Packet #2 raw RAM -> X: {ipc.shared_packet.x_coord}, "
              f"Y: {ipc.shared_packet.y_coord}")
        print("[DMA Card Sniff Trace] XORing packet #1 and #2 raw values yields noise, not delta coords.")

        # Step 3: AMITF reads and recovers packet #2
        time.sleep(0.1)
        pkt_id, rx_x, rx_y, rx_z = ipc.simulate_framework_read(tpm_seed=tpm_seed)

        print("\n[AMITF Framework] Intercepted volatile packet stream:")
        print(f" -> Sequential Packet ID : {pkt_id}")
        print(f" -> Reconstructed Coords -> X: {rx_x}, Y: {rx_y}, Z: {rx_z}")

    finally:
        ipc.shutdown()
```

---

## 3. Transitioning the IPC Layer into Rust Production

When this design paradigm scales into native Rust for live instrumentation tests, the architectural rules map precisely to low-overhead mechanics:

1. **Zero-Copy Serialization:** Instead of serializing data packets to JSON or structured protocol bytes (which wastes precious CPU cycles), Rust treats shared memory maps as direct structural views with zero conversion costs:
   ```rust
   // Rust equivalent of byte-perfect physical alignment structures
   #[repr(C)]
   struct TelemetryPacket {
       packet_id: u32,
       x_coord:   u32,
       y_coord:   u32,
       z_coord:   u32,
   }
   ```

2. **Atomic Synchronization Locks:** To prevent race conditions between the target game client writing data and framework threads reading it, embed lock-free atomics (`std::sync::atomic::AtomicU32`) directly into the shared struct header. This avoids heavy OS synchronization objects (Mutexes, Semaphores) that external anticheats watch for, keeping the framework hidden in user land.

3. **Anonymous fd on Linux:** Use the `memfd` crate or a direct `libc::memfd_create()` syscall — same semantics as the C implementation, same zero-filesystem-trace guarantee.

4. **Per-Packet Mask Derivation in Rust:** The `sha3` crate (`shake256`) provides the same SHAKE-256 primitive used in the Python implementation, ensuring cross-language compatibility if both sides need to interoperate during testing.
