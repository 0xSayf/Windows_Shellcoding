# Shellcode Extractor

A Windows x86-64 shellcode development utility that resolves API functions at runtime without relying on the Import Address Table (IAT), then extracts the resulting shellcode bytes from the compiled binary.

---

## Overview

This tool demonstrates a self-contained shellcode stub that:

- Walks the **Process Environment Block (PEB)** to locate loaded modules without calling `LoadLibrary`
- Parses the **PE export directory** manually to resolve function addresses without calling `GetProcAddress`
- Executes a target function (`Beep`) entirely through dynamic resolution
- Prints the raw shellcode bytes between labeled assembly landmarks so you can copy them directly

---

## Files

| File | Description |
|---|---|
| `shellcode.c` | Main source — PEB walker, export resolver, shellcode stub, and byte extractor |
| `shellcode.h` | Type definitions for `PEB`, `PEB_LDR_DATA`, `LDR_DATA_TABLE_ENTRY`, and `UNICODE_STRING` |

---

## How It Works

### 1. `ft_LoadLib` — PEB-based module lookup

Reads the PEB from `gs:[0x60]` (x86-64 TEB offset), then walks the `InMemoryOrderModuleList` doubly-linked list to find a loaded DLL by name, returning its base address. No calls to `LoadLibrary` or any other import.

### 2. `Lgetprocadd` — PE export table resolver

Given a module base address, it manually parses:

- `IMAGE_DOS_HEADER` → `e_lfanew`
- `IMAGE_OPTIONAL_HEADER` → `DataDirectory[0]` (export directory RVA)
- `IMAGE_EXPORT_DIRECTORY` → `AddressOfNames`, `AddressOfNameOrdinals`, `AddressOfFunctions`

It walks the name table comparing against the requested function name and returns the resolved function pointer.

### 3. Shellcode stub extraction

Assembly labels `StartAddress` and `EndAddress` bracket the stub. After execution, the program computes `EndAddress - StartAddress` and prints each byte as `\xNN`, ready to paste into a payload array.

---

## Build

Requires the MinGW-w64 cross-compiler targeting Windows x86-64.

```bash
x86_64-w64-mingw32-gcc shellcode.c -O -masm=intel -o shellcode.exe -Wno-int-conversion
```

| Flag | Purpose |
|---|---|
| `-O` | Basic optimization (keeps inlined functions inlined) |
| `-masm=intel` | Use Intel syntax for inline assembly |
| `-Wno-int-conversion` | Suppress pointer/integer cast warnings common in low-level PE parsing |

---

## Usage

Run the compiled binary on a Windows x86-64 machine:

```
shellcode.exe
```

Example output:

```
Start address: 0x00007FF6ABCD1000
End address:   0x00007FF6ABCD10A3
UCHAR payload[] = {\x48\x83\xe4\xf0\x48\x89\xe5...};
```

Copy the `payload[]` line into your loader or injector.

---

## Key Design Decisions

- All helper functions are declared `inline __attribute__((always_inline))` to ensure they compile into the stub body rather than as separate callable functions (which would require a working call stack and relocated addresses).
- Stack alignment is explicitly enforced (`and rsp, 0xfffffffffffffff0`) and a shadow space is allocated (`sub rsp, 0x400`) before any Win64 ABI calls.
- String literals for module and function names are declared as local `CHAR` arrays so they live on the stack inside the stub, avoiding absolute data section references.

---

## Requirements

- **Build host:** Linux or Windows with `x86_64-w64-mingw32-gcc` installed
- **Execution target:** Windows x86-64
- **Dependencies:** None — the shellcode stub has no imports by design

---

## Disclaimer

This code is intended for **educational purposes**, **CTF challenges**, and **authorized security research** only. Do not use on systems you do not own or have explicit permission to test.
