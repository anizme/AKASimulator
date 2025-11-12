
# AKA_Simulator – Chip Simulator 
AKA_Simulator is a chip simulator built on top of the **Unicorn Engine**, currently using AkaUT format for I/O.

It executes ELF binaries compiled from embedded source code and produces:
- Simulation runtime logs
- Testpath file: format in source code AKA_mark()/\*content to be written in testpath file\*/
- Trace file: contains actual and expected value of variables that need to trace, format in source code: AKAS_assert_u32/64(expected_var_name, actual_var_name).

---
## Input  
1. Path to ELF file
2. Path for output of simulator
3. (Optional) Path to stub_info file
---
## Output  
- Simulation runtime log: output_directory/simulation/elf_file_name.log
- Test path: output_directory/test-driver/elf_file_name.tp
- Trace file: output_directory/execution-results/elf_file_name.trc
---
## Dependencies  
- Build system: **Ninja** or **Make** (any CMake-supported)  
- Build generator: **CMake**
- Target OS: Ubuntu 
- Cross-compiler: **Clang**  
---
- Uses ELFIO for ELF loading
- Uses Unicorn Engine for emulation
- Uses Capstone for disassembly
- Uses llvm-symbolizer for source mapping

## How to Build  
On **Ubuntu**:  
This script should be changed if you already had ELF file, just comment out the corresponding phase that you have done
```bash
./script.sh
```
---
## Project Structure
```
akas/
├── core/ # All simulation logic
├── architecture/ # Chip architecture metadata
└── io_utils/ # Configuration, file I/O, utilities
```

## Modules
### ARCHITECTURE MODULE
#### Responsibility:
Define chip architectures as metadata.
No simulation logic inside.
#### Components:
- Architecture Interface — Base contract for chip definitions
- MemoryMapDescriptor — Flash, SRAM, peripherals
- CPUDescriptor — Registers, instruction mode, boot info
- Chip Implementations:
    - STM32F103C8T6 (Cortex-M3, Flash 64KB, SRAM 20KB)
    - STM32F407VG (Cortex-M4, Flash 1MB, SRAM 192KB)

### CORE ENGINE
#### Responsibility:
All simulation logic from ELF loading to instruction execution and tracing.

#### Components:
- ELFLoader — Parse ELF, extract symbols and segments
- SimulationEngine — Control the Unicorn runtime
- MemoryManager — Setup and manage memory regions
- HookDispatcher — Register and dispatch Unicorn hooks
- SimulationTracer — Trace execution, disassemble, map to source lines
- ErrorDetector — Detect runtime errors (div0, invalid access, etc.)
- StubManager — Redirect stubbed functions

### I/O & UTILS MODULE
#### Responsibility:
Handle configuration, file I/O, and utilities.
No simulation or execution logic.
#### Components:
- ConfigurationManager — Read and validate config.json
- Logging — Colored console & file logging (Debug → Error)
- Output Writers
- ExecutionLogWriter → execution.log
- TraceFileWriter → trace.trc
- TestPathWriter → testpath.tp
- Utilities — String formatting, file helpers, symbolizer wrapper

## Overall flow
```mermaid
    [1] Main
     │
     ▼
[2] I/O Module: ConfigurationManager
     │ Read config.json
     │
     ├──> SimulationConfig {
     │      chip: "stm32f103c8t6",
     │      binary: "firmware.elf",
     │      stubs: "stubs.txt"
     │    }
     │
     ▼
[3] Architecture Module: ArchitectureFactory
     │ Create STM32F103C8T6
     │
     ├──> MemoryMapDescriptor
     ├──> CPUDescriptor
     └──> BootDescriptor
     │
     ▼
[4] Core Module: ELFLoader
     │ Load firmware.elf
     │
     ├──> Parse segments
     ├──> Find symbols (main, AKAS_assert...)
     └──> Binary data + symbol table
     │
     ▼
[5] Core Module: ExecutionEngine.initialize()
     │
     ├──> MemoryManager.setup(MemoryMapDescriptor)
     ├──> Write binary data to memory
     ├──> StubManager.load(stubs.txt)
     ├──> HookDispatcher.registerHooks()
     └──> SimulationTracer.initialize()
     │
     ▼
[6] Core Module: ExecutionEngine.run()
     │ Unicorn executes
     │
     ├──> Each instruction → Hook triggered
     ├──> HookDispatcher → dispatch events
     ├──> SimulationTracer → capture & buffer
     │    ├─ Disassemble instruction
     │    ├─ Map to source line
     │    ├─ Track assertions
     │    └─ Track markers
     ├──> ErrorDetector → check errors
     └──> StubManager → check redirects
     │
     ▼
[7] Core Module: SimulationTracer
     │ Has buffered data:
     │
     ├──> instruction_traces[]
     ├──> assertion_events[]
     └──> marker_events[]
     │
     ▼
[8] I/O Module: Output Writers
     │ Fetch data from SimulationTracer
     │
     ├──> ExecutionLogWriter.write(instruction_traces)
     │    → execution.log
     │
     ├──> TraceFileWriter.write(assertion_events)
     │    → trace.trc (JSON)
     │
     └──> TestPathWriter.write(marker_events)
          → testpath.tp

```