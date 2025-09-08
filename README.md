# AKA_Simulator – Chip Simulator 
AKA_Simulator is a chip simulator built on top of the **Unicorn Engine**.  
It executes ELF binaries compiled from embedded source code and produces execution logs as well as coverage reports.  

---
## Input  

1. Place your source files in:
> akas_working_space/test_driver/akas_source/
2. (Optional) Use **AkaUT** (branch `simulation/build_env`) to generate a **test driver** in case you want a real UT test driver.  
3. (Optional) Copy the generated test driver into:
>akas_working_space/test_driver/
4. Build source files into ELF format at 
>akas_working_space/test_driver/

As long as `firmware.elf` exists at the correct path, the simulator can run your code.  
"You can do anything with your target source files provided that the ELF file named fireware.elf and path for ELF file: akas_working_space/test_driver/firmware.elf"

---

## Output  

- **Execution logs**: `akas_working_space/emulation_log/`  
- **Test report**: `akas_working_space/test_report/` 

---
## Supported Chips  
### STM32F103C8T6
- CPU: **ARM Cortex-M3**  
- ISA: **Thumb-2**  

### ESP32-C3FH4 (planned)  
- CPU: **RISC-V RV32** (32-bit)  
- ISA: **RV32IMC**

---

## Dependencies  
- Build system: **Ninja** or **Make** (any CMake-supported)  
- Build generator: **CMake**  
- Cross-compiler: **Clang**  

---

## How to Build  

On **Ubuntu**:  
This script should be changed if you already had ELF file, just comment out the corresponding phase that you have done

```bash
./script.sh
