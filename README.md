Windows Dynamic API Resolver (PoC)
A research-oriented implementation of manual Portable Executable (PE) parsing, demonstrating dynamic API resolution at runtime without reliance on the Windows Loader (kernel32.dll imports).

Overview
This project explores the mechanics of Windows process memory and the Windows Loader. By bypassing standard library linking and resolving functions directly from the Process Environment Block (PEB), this utility demonstrates how a process can locate and execute arbitrary Windows APIs from memory.

Key Technical Concepts
PEB Traversal: Direct access to the GS segment register to locate the PEB structure.

Memory Parsing: Manual iteration through the LDR_DATA_TABLE_ENTRY structures to identify loaded modules (KERNEL32.dll).

Export Address Table (EAT) Analysis: Parsing the IMAGE_EXPORT_DIRECTORY to extract function addresses by name without using GetProcAddress.

Position Independent Code (PIC): Development of self-contained code patterns for in-memory execution.

Technical Architecture
The project is built on three core pillars of Windows Internals:

Environment Inspection: The ft_LoadLib function queries the PEB to walk the InMemoryOrderModuleList. This allows the program to dynamically find the base address of any loaded DLL in the current process space.

Symbol Resolution: The Lgetprocadd function performs a manual lookup of the Export Address Table. It parses the AddressOfNames, AddressOfNameOrdinals, and AddressOfFunctions arrays to resolve the absolute address of specific exported functions (e.g., Beep).

In-Memory Serialization: The main function demonstrates how to calculate the memory boundaries of the functional code, allowing the program to output its own machine code as a byte array.

Usage
Compilation
The project utilizes x86_64-w64-mingw32-gcc. Ensure you are using the provided header (shellcode.h) which contains the necessary structure definitions.

Bash
x86_64-w64-mingw32-gcc shellcode.c -O -masm=intel -o shellcode.exe -Wno-int-conversion
Execution
Running the compiled executable will:

Resolve the address of Beep from KERNEL32.dll at runtime.

Execute the Beep function to verify successful resolution.

Calculate and print the hex-encoded byte array of the logic, demonstrating the capability for position-independent execution.

Security Research Context
This implementation is designed for educational purposes in the field of cybersecurity research. Understanding these techniques is critical for:

EDR Development: Improving heuristic detection of dynamic API resolution and memory-resident threats.

Malware Analysis: Analyzing how sophisticated threats hide their import tables to evade static analysis.

Systems Programming: Deepening understanding of the Windows OS architecture and the transition between user-mode and kernel-mode.

Future Development
Direct Syscall Implementation: Transitioning from resolving Win32 APIs to invoking Nt* functions directly via the syscall instruction to further reduce the process footprint.

Hash-Based Resolution: Replacing string-based function name comparison with CRC32 or DJB2 hashing to further obfuscate the intent of the API calls.

Disclaimer: This project is for educational use only. The author is not responsible for any misuse of the techniques demonstrated.
