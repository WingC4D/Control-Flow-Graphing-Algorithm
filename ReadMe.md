# Control Flow Graphing Algorithm

## Overview

A lightweight, dependency-free Control Flow Graph (CFG) generator and Length Disassembly Engine (LDE) written from scratch in C++. Designed specifically for x64 Windows environments, this engine parses complex instruction sets (including `ModR/M`, `SIB`, and `REX` prefixes) to accurately map execution flow, resolve relative jumps, and dynamically split basic blocks upon interlacing execution paths.

## Technologies Used

<p align="center"> 
  <a href="https://skillicons.dev">
    <img src="https://skillicons.dev/icons?i=cpp,visualstudio,windows,py,vscode"/>
  </a>
</p>

## Key Features

- **Custom Length Disassembler Engine (LDE):** Completely self-contained x86/x64 instruction length decoding using a highly optimized 256-byte trait map, avoiding heavy external dependencies like Capstone or Zydis.
- **Dynamic Basic Block Generation:** Models the target function as a directed graph, correctly capturing `flowTo` and `flowFrom` relationships.
- **Execution Path Bifurcation:** Accurately calculates jump dispositions and splits basic blocks on the fly when evaluating conditional (`jcc`) and unconditional branching.
- **Prologue & Register State Capture:** Properly identifies non-volatile register preservation and REX prefix boundaries (e.g., `r12`, `r13`).

## Stress Testing & Proof of Concept

The engine has been successfully stress-tested against `CreateProcessInternalW` inside `KernelBase.dll`—one of the most cyclomatically complex functions in the Windows API.

**Results on `CreateProcessInternalW`:**

- Successfully mapped **860 distinct basic blocks**.
- Traced execution paths reaching a branch height (logical nesting depth) of **139 levels**.
- Zero crashes, infinite loops, or instruction boundary misalignments during the trace.

## Tech Stack

Development Environment:

- Windows 11
- C++ -  Visual Studio Community 2026, MSVC.
- Python Visual Studio Code 1.15.

Algorithm & Legth Disassembly Engine Development:

- C++ 23 (`<print>`, `using enum`, `constexpr` bitmasks, etc.)

Log Testing:

- Python 3.13

## Technical Details & Use Cases

This architecture is built with reverse engineering, exploit development, and malware analysis in mind. By keeping the binary footprint minimal and completely self-contained, this algorithm facilitates:

- **Legacy x64\x86 Length Disassembly**: Handles length analysis to all x64\x86 instructions (except EVEX, due to me not finding a function containing these instructions.)
- **Function Mappiing:** Safely graphs a function's execution flow, with complex cyclomatic properties.
- **Automated Analysis:** Deep programmatic insight into function execution without relying on a debugger. (Binary Analysis)
