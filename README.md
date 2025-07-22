# Simulator for chip
This AKA_Simulator is built based on Unicorn engine
- Input: source files that coded for chip, put them in elf_builder/input_source/ directory
- Output: status when executing

## 1. Supported chips
### 1.1. STM32F103C8T6
- CPU: Cortex-M3
- Instruction set: Thumb 2

## 2. Dependencies:
1. A build system: Ninja or Make or anything that CMake supported
2. Build system builder: CMake
3. Cross compiler: [gcc-arm-none-eabi](https://developer.arm.com/downloads/-/gnu-rm)

## 3. How to build
Make sure your host have all dependencies mentioned above

- Ubuntu: 
> chmod +x script.sh

> ./script.sh
