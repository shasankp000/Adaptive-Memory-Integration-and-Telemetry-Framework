# AMITF (Adaptive Memory Integration and Telemetry Framework)
## Phase 0 Blueprint: Secure Cross-Platform Inter-Process Communication (IPC)

This document expands on the Phase 0 architecture by detailing the **Secure User-Space IPC Layer**. When deploying your telemetry framework alongside a target process (like an engine or a game client), you must pass data between the two applications without leaving detectable footprints in standard system logs or creating predictable, static memory buffers that a hardware DMA card can track.

---

## 1. Architectural Philosophy: The Hidden Bridge

Traditional IPC mechanisms like standard TCP/UDP local sockets or named pipes introduce noticeable latency and leave clear trace signatures in operating system networking stacks. 

AMITF utilizes a **Volatile Shared Memory Arena** combined with **Pointer-XOR Masking**. Instead of establishing a permanent stream, both programs map into an anonymous, RAM-backed shared file descriptor. 

```
┌───────────────────────────────┐          
┌───────────────────────────────┐
│     Target Game Process       │          
│   AMITF Telemetry Framework   │
│   (e.g., CS2 Game Client)     │          
│    (Polymorphic Exec Engine)  │
└───────────────┬───────────────┘          
└───────────────┬───────────────┘
│ Maps into anonymous arena     |          
│ Maps into anonymous arena▼    |                                    
▼┌─────────────────────────────┐│-----+                    
| RAM-Backed Shared Memory Arena (IPC)|                 │
│  - Linux: /dev/shm (shm_open)  |
|  - Windows: Pagefile           |
|   (CreateFileMapping)          │
│                                |------+                                          
│[ Header: Obfuscated Sync Ring Buffer ]| 
|  |──► [ Encrypted Telemetry Frame ]   │ 
└───────────────────────────────────────┘
```

### Anti-DMA Defenses Implemented in this Layer:
1. **Zero-Storage Footprint:** The shared buffer is created inside volatile RAM (using `/dev/shm` on Linux and a pagefile-backed mapping on Windows). No data ever hits the storage drive.
2. **Ephemeral Ring Buffers:** Telemetry coordinates are structured as a fast Ring Buffer (Circular Queue). Data frames overwrite each other at high frequencies (e.g., every frame packet), preventing a DMA card from pulling historical position telemetry.
3. **XOR Obfuscation at Rest:** Before the target process dumps telemetry coordinates into the shared RAM slots, it XOR-encrypts the bytes using a shifting mask. Even if a DMA card scrapes the shared page memory segment, the values appear as erratic noise.

---

## 2. Phase 0 IPC Implementation Code

This complete, cross-platform blueprint combines a **C Shared Library** for platform-native memory mappings and a **Python Orchestrator** to simulate the two distinct processes communicating in real-time.

### File 1: `secure_ipc.c`
*This C module creates, attaches, and detaches anonymous shared memory handles natively across Linux and Windows user space.*

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

// Cross-platform function to open or create a shared memory arena in RAM
void* create_shared_arena(const char* name, size_t size, int* out_handle) {
#ifdef _WIN32
    HANDLE hMapFile = CreateFileMappingA(
        INVALID_HANDLE_VALUE,    // Use paging file instead of a physical disk file
        NULL,                    // Default security
        PAGE_READWRITE,          // Read/write access
        0,                       // Maximum object size (high-order DWORD)
        (DWORD)size,             // Maximum object size (low-order DWORD)
        name                     // Name of mapping object
    );
    if (hMapFile == NULL) return NULL;
    
    *out_handle = (int)(intptr_t)hMapFile;
    return MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, size);
#else
    // Linux maps directly into volatile RAM via /dev/shm
    int fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    if (fd == -1) return NULL;
    
    // Configure the size of the volatile shared memory file descriptor
    if (ftruncate(fd, size) == -1) {
        close(fd);
        return NULL;
    }
    
    *out_handle = fd;
    return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
#endif
}
### Anti-DMA Defenses Implemented in this Layer:
1. **Zero-Storage Footprint:** The shared buffer is created inside volatile RAM (using `/dev/shm` on Linux and a pagefile-backed mapping on Windows). No data ever hits the storage drive.
2. **Ephemeral Ring Buffers:** Telemetry coordinates are structured as a fast Ring Buffer (Circular Queue). Data frames overwrite each other at high frequencies (e.g., every frame packet), preventing a DMA card from pulling historical position telemetry.
3. **XOR Obfuscation at Rest:** Before the target process dumps telemetry coordinates into the shared RAM slots, it XOR-encrypts the bytes using a shifting mask. Even if a DMA card scrapes the shared page memory segment, the values appear as erratic noise.

---

## 2. Phase 0 IPC Implementation Code

This complete, cross-platform blueprint combines a **C Shared Library** for platform-native memory mappings and a **Python Orchestrator** to simulate the two distinct processes communicating in real-time.

### File 1: `secure_ipc.c`
*This C module creates, attaches, and detaches anonymous shared memory handles natively across Linux and Windows user space.*

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

// Cross-platform function to open or create a shared memory arena in RAM
void* create_shared_arena(const char* name, size_t size, int* out_handle) {
#ifdef _WIN32
    HANDLE hMapFile = CreateFileMappingA(
        INVALID_HANDLE_VALUE,    // Use paging file instead of a physical disk file
        NULL,                    // Default security
        PAGE_READWRITE,          // Read/write access
        0,                       // Maximum object size (high-order DWORD)
        (DWORD)size,             // Maximum object size (low-order DWORD)
        name                     // Name of mapping object
    );
    if (hMapFile == NULL) return NULL;
    
    *out_handle = (int)(intptr_t)hMapFile;
    return MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, size);
#else
    // Linux maps directly into volatile RAM via /dev/shm
    int fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    if (fd == -1) return NULL;
    
    // Configure the size of the volatile shared memory file descriptor
    if (ftruncate(fd, size) == -1) {
        close(fd);
        return NULL;
    }
    
    *out_handle = fd;
    return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
#endif
}

// Cleans up memory mappings and unlinks the shared resource identifiers
void close_shared_arena(const char* name, void* address, size_t size, int handle) {
#ifdef _WIN32
    UnmapViewOfFile(address);
    CloseHandle((HANDLE)(intptr_t)handle);
#else
    munmap(address, size);
    close(handle);
    shm_unlink(name);
#endif
}
```

#### Compilation Commands:
*   **On Linux:** `gcc -shared -o libsecure_ipc.so -fPIC secure_ipc.c -lrt`
*   **On Windows (via MinGW):** `gcc -shared -o libsecure_ipc.dll secure_ipc.c`

---

### File 2: `ipc_simulator.py`
*This script defines an encrypted data layout structure and simulates both sides of the application pipeline: a client writing telemetry updates and the AMITF engine reading and processing them.*

```python
import ctypes
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
        ("x_coord", ctypes.c_uint32),      # XOR-masked coordinate data
        ("y_coord", ctypes.c_uint32),      # XOR-masked coordinate data
        ("z_coord", ctypes.c_uint32),      # XOR-masked coordinate data
    ]

class AMITF_IPCEngine:
    def __init__(self, name="AMITF_SecureBridge", size=1024):
        self.arena_name = name.encode('utf-8')
        self.arena_size = size
        self.handle = ctypes.c_int(0)
        
        # Call C to mount our anonymous shared RAM region
        raw_ptr = secure_ipc.create_shared_arena(
            self.arena_name, 
            self.arena_size, 
            ctypes.byref(self.handle)
        )
        if not raw_ptr:
            raise MemoryError("[AMITF IPC] Failed to allocate volatile shared memory region.")
            
        # Cast the raw physical pointer to our Telemetry Packet structure
        self.shared_packet = TelemetryPacket.from_address(raw_ptr)
        self.raw_address = raw_ptr
        print(f"[AMITF IPC] Secure Bridge opened at memory address: {hex(self.raw_address)}")

    def simulate_game_client_write(self, x, y, z, packet_num, xor_mask):
        """
        Simulates how the target application obfuscates telemetry and 
        writes it into the shared memory page.
        """
        # Mask the data at rest to blind any passive hardware PCIe memory scanners
        self.shared_packet.packet_id = packet_num
        self.shared_packet.x_coord = int(x) ^ xor_mask
        self.shared_packet.y_coord = int(y) ^ xor_mask
        self.shared_packet.z_coord = int(z) ^ xor_mask

    def simulate_framework_read(self, xor_mask):
        """
        Simulates the AMITF engine fetching the obfuscated packet,
        unmasking it in registers, and processing the variables.
        """
        # Read the current snapshot from the volatile mapping
        p_id = self.shared_packet.packet_id
        masked_x = self.shared_packet.x_coord
        masked_y = self.shared_packet.y_coord
        masked_z = self.shared_packet.z_coord
        
        # Decrypt values inside local memory boundaries
        true_x = masked_x ^ xor_mask
        true_y = masked_y ^ xor_mask
        true_z = masked_z ^ xor_mask
        
        return p_id, true_x, true_y, true_z

    def shutdown(self):
        secure_ipc.close_shared_arena(
            self.arena_name, 
            self.raw_address, 
            self.arena_size, 
            self.handle
        )
        print("[AMITF IPC] Volatile bridge successfully destroyed and unlinked.")

if __name__ == "__main__":
    print("--- AMITF Phase 0 Secure User-Space IPC Test ---")
    ipc = AMITF_IPCEngine()
    
    try:
        # Generate a shifting mask simulating keys originating from the TPM
        epoch_xor_mask = int.from_bytes(secrets.token_bytes(4), byteorder=sys.byteorder)
        print(f"[AMITF IPC] Active Epoch Mask: {hex(epoch_xor_mask)}")
        
        # Step 1: Simulate Target Client writing state coordinates
        print("\n[Game Client] Sending encrypted position matrices...")
        ipc.simulate_game_client_write(x=1425, y=8210, z=340, packet_num=1, xor_mask=epoch_xor_mask)
        
        # Print what a DMA card actually sees looking at the raw memory buffer right now
        print(f"[DMA Card Sniff Trace] Physical RAM reveals raw variables -> X: {ipc.shared_packet.x_coord}, Y: {ipc.shared_packet.y_coord}")
        
        # Step 2: Simulate AMITF reading and recovering data coordinates
        time.sleep(0.1) # Microsecond delay emulation
        pkt_id, rx_x, rx_y, rx_z = ipc.simulate_framework_read(xor_mask=epoch_xor_mask)
        
        print("\n[AMITF Framework] Intercepted volatile packet string stream:")
        print(f" -> Sequential Packet ID: {pkt_id}")
        print(f" -> Reconstructed Coordinates -> X: {rx_x}, Y: {rx_y}, Z: {rx_z}")
        
    finally:
        ipc.shutdown()
```

---

## 3. Transitioning the IPC Layer into Rust Production

When you scale this design paradigm into native Rust for your live instrumentation tests, the architectural rules map precisely to low-overhead mechanics:

1. **Zero-Copy Serialization:** Instead of serializing data packets to JSON or structured protocol bytes (which wastes precious CPU cycles), Rust treats shared memory maps as direct structural views. You can safely map the memory region to an optimized struct with zero conversion costs using casting tricks:
   ```rust
   // Rust equivalent of byte-perfect physical alignment structures
   #[repr(C)]
   struct TelemetryPacket {
       packet_id: u32,
       x_coord: u32,
       y_coord: u32,
       z_coord: u32,
   }
   ```
2. **Atomic Synchronization Locks:** To prevent standard race conditions between the target game client writing data and your framework threads reading them, you can embed lock-free atomics (`std::sync::atomic::AtomicU32`) right into the shared struct header. This avoids using heavy OS synchronization objects (like Mutexes or Semaphores) that external anticheats watch for, allowing your framework to stay completely hidden in user land.

// Cleans up memory mappings and unlinks the shared resource identifiers
void close_shared_arena(const char* name, void* address, size_t size, int handle) {
#ifdef _WIN32
    UnmapViewOfFile(address);
    CloseHandle((HANDLE)(intptr_t)handle);
#else
    munmap(address, size);
    close(handle);
    shm_unlink(name);
#endif
}
```

#### Compilation Commands:
*   **On Linux:** `gcc -shared -o libsecure_ipc.so -fPIC secure_ipc.c -lrt`
*   **On Windows (via MinGW):** `gcc -shared -o libsecure_ipc.dll secure_ipc.c`

---

### File 2: `ipc_simulator.py`
*This script defines an encrypted data layout structure and simulates both sides of the application pipeline: a client writing telemetry updates and the AMITF engine reading and processing them.*

```python
import ctypes
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
        ("x_coord", ctypes.c_uint32),      # XOR-masked coordinate data
        ("y_coord", ctypes.c_uint32),      # XOR-masked coordinate data
        ("z_coord", ctypes.c_uint32),      # XOR-masked coordinate data
    ]

class AMITF_IPCEngine:
    def __init__(self, name="AMITF_SecureBridge", size=1024):
        self.arena_name = name.encode('utf-8')
        self.arena_size = size
        self.handle = ctypes.c_int(0)
        
        # Call C to mount our anonymous shared RAM region
        raw_ptr = secure_ipc.create_shared_arena(
            self.arena_name, 
            self.arena_size, 
            ctypes.byref(self.handle)
        )
        if not raw_ptr:
            raise MemoryError("[AMITF IPC] Failed to allocate volatile shared memory region.")
            
        # Cast the raw physical pointer to our Telemetry Packet structure
        self.shared_packet = TelemetryPacket.from_address(raw_ptr)
        self.raw_address = raw_ptr
        print(f"[AMITF IPC] Secure Bridge opened at memory address: {hex(self.raw_address)}")

    def simulate_game_client_write(self, x, y, z, packet_num, xor_mask):
        """
        Simulates how the target application obfuscates telemetry and 
        writes it into the shared memory page.
        """
        # Mask the data at rest to blind any passive hardware PCIe memory scanners
        self.shared_packet.packet_id = packet_num
        self.shared_packet.x_coord = int(x) ^ xor_mask
        self.shared_packet.y_coord = int(y) ^ xor_mask
        self.shared_packet.z_coord = int(z) ^ xor_mask

    def simulate_framework_read(self, xor_mask):
        """
        Simulates the AMITF engine fetching the obfuscated packet,
        unmasking it in registers, and processing the variables.
        """
        # Read the current snapshot from the volatile mapping
        p_id = self.shared_packet.packet_id
        masked_x = self.shared_packet.x_coord
        masked_y = self.shared_packet.y_coord
        masked_z = self.shared_packet.z_coord
        
        # Decrypt values inside local memory boundaries
        true_x = masked_x ^ xor_mask
        true_y = masked_y ^ xor_mask
        true_z = masked_z ^ xor_mask
        
        return p_id, true_x, true_y, true_z

    def shutdown(self):
        secure_ipc.close_shared_arena(
            self.arena_name, 
            self.raw_address, 
            self.arena_size, 
            self.handle
        )
        print("[AMITF IPC] Volatile bridge successfully destroyed and unlinked.")

if __name__ == "__main__":
    print("--- AMITF Phase 0 Secure User-Space IPC Test ---")
    ipc = AMITF_IPCEngine()
    
    try:
        # Generate a shifting mask simulating keys originating from the TPM
        epoch_xor_mask = int.from_bytes(secrets.token_bytes(4), byteorder=sys.byteorder)
        print(f"[AMITF IPC] Active Epoch Mask: {hex(epoch_xor_mask)}")
        
        # Step 1: Simulate Target Client writing state coordinates
        print("\n[Game Client] Sending encrypted position matrices...")
        ipc.simulate_game_client_write(x=1425, y=8210, z=340, packet_num=1, xor_mask=epoch_xor_mask)
        
        # Print what a DMA card actually sees looking at the raw memory buffer right now
        print(f"[DMA Card Sniff Trace] Physical RAM reveals raw variables -> X: {ipc.shared_packet.x_coord}, Y: {ipc.shared_packet.y_coord}")
        
        # Step 2: Simulate AMITF reading and recovering data coordinates
        time.sleep(0.1) # Microsecond delay emulation
        pkt_id, rx_x, rx_y, rx_z = ipc.simulate_framework_read(xor_mask=epoch_xor_mask)
        
        print("\n[AMITF Framework] Intercepted volatile packet string stream:")
        print(f" -> Sequential Packet ID: {pkt_id}")
        print(f" -> Reconstructed Coordinates -> X: {rx_x}, Y: {rx_y}, Z: {rx_z}")
        
    finally:
        ipc.shutdown()
```

---

## 3. Transitioning the IPC Layer into Rust Production

When this design pardigm will scale into native Rust for your live instrumentation tests, the architectural rules map precisely to low-overhead mechanics:

1. **Zero-Copy Serialization:** Instead of serializing data packets to JSON or structured protocol bytes (which wastes precious CPU cycles), Rust treats shared memory maps as direct structural views. You can safely map the memory region to an optimized struct with zero conversion costs using casting tricks:
   ```rust
   // Rust equivalent of byte-perfect physical alignment structures
   #[repr(C)]
   struct TelemetryPacket {
       packet_id: u32,
       x_coord: u32,
       y_coord: u32,
       z_coord: u32,
   }
   ```
2. **Atomic Synchronization Locks:** To prevent standard race conditions between the target game client writing data and your framework threads reading them, you can embed lock-free atomics (`std::sync::atomic::AtomicU32`) right into the shared struct header. This avoids using heavy OS synchronization objects (like Mutexes or Semaphores) that external anticheats watch for, allowing your framework to stay completely hidden in user land.
