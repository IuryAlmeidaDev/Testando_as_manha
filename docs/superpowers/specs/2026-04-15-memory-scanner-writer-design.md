# Memory Scanner & Writer - Design Spec

**Date:** 2026-04-15  
**Author:** Iury Almeida  
**Repo:** https://github.com/IuryAlmeidaDev/Testando_as_manha

---

## Overview

A Windows GUI application for scanning and modifying memory values in running processes (x86 and x64). Functionality similar to Cheat Engine, built in C++ with wxWidgets.

---

## Technology Stack

| Component | Choice |
|-----------|--------|
| Language | C++17 |
| GUI Framework | wxWidgets 3.2+ |
| Build System | CMake |
| Package Manager | vcpkg |
| Platform API | Windows WinAPI |
| Architecture | MVC (Model: Engine, View: GUI, Controller: Events) |

---

## Architecture

```
MemoryScannerWriter/
├── CMakeLists.txt
├── src/
│   ├── main.cpp
│   ├── gui/
│   │   ├── MainFrame.h
│   │   └── MainFrame.cpp
│   ├── engine/
│   │   ├── ProcessManager.h
│   │   ├── ProcessManager.cpp
│   │   ├── MemoryEngine.h
│   │   └── MemoryEngine.cpp
│   └── models/
│       ├── ScanResult.h
│       └── ScanResult.cpp
└── vcpkg.json
```

### Components

1. **ProcessManager** — Enumerates running processes, opens handles with appropriate access rights
2. **MemoryEngine** — Wraps ReadProcessMemory/WriteProcessMemory, performs scans across memory regions
3. **MainFrame** — wxWidgets GUI, user interactions, displays results

---

## Features (v1)

### Core
1. **Process Selection** — List all running processes with PID and name; select target process
2. **Memory Scanner** — Initial scan for values; supports all data types
3. **Scan Filters** — Subsequent scans filtering by: unchanged, increased, decreased, exact value
4. **Results View** — Display found addresses with current values
5. **Memory Writer** — Modify value at selected address

### Supported Data Types
- `int8` (char)
- `int16` (short)
- `int32` (int/long)
- `int64` (long long)
- `float`
- `double`
- `byte` (unsigned char)
- `string` (text)

### Architecture Support
- x86 (32-bit) processes
- x64 (64-bit) processes
- WOW64 process emulation awareness

---

## Data Flow

```
User selects process
        ↓
User enters value + data type
        ↓
Scanner iterates memory pages (ReadProcessMemory)
        ↓
Matches stored in ScanResult list
        ↓
User applies filter (next scan)
        ↓
User selects address
        ↓
User enters new value
        ↓
Writer calls WriteProcessMemory
```

---

## Memory Regions

Scan these memory regions:
- `MEM_COMMIT` pages only
- Exclude `PAGE_GUARD` and `PAGE_NOACCESS`
- Read permission required (`PAGE_READONLY`, `PAGE_READWRITE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`)

---

## Error Handling

- **Access Denied** — Skip protected memory, log if verbose mode
- **Process Exited** — Detect handle invalidation, prompt to reselect
- **Invalid Address** — Validate before write, show error message
- **Out of Memory** — Handle gracefully, show status message

---

## UI Layout

```
┌─────────────────────────────────────────────────────────────┐
│ [Process: ▼ Select Process    ] [Refresh]                   │
├─────────────────────────────────────────────────────────────┤
│ Search: [________] Type: [▼ Int32] [Next Scan] [Reset]     │
├─────────────────────────────────────────────────────────────┤
│ Results                                          Count: 0  │
│ ┌─────────────────────────────────────────────────────────┐│
│ │ Address      │ Value        │ Type                      ││
│ │──────────────│──────────────│───────────────────────────││
│ │              │              │                           ││
│ └─────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────┤
│ Write: [________] Type: [▼ Int32] [Write to Selected]       │
└─────────────────────────────────────────────────────────────┘
```

---

## Build Instructions

### Prerequisites
- Visual Studio 2022 with C++ desktop development
- vcpkg installed

### Build
```bash
cmake -B build -DCMAKE_TOOLCHAIN_FILE=[vcpkg-root]/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

### Run
```bash
./build/Release/MemoryScannerWriter.exe
```

---

## Security Note

This tool is for educational and legitimate debugging purposes. Always ensure you have appropriate rights to modify the target process memory. Use responsibly.
