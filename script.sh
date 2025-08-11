#!/bin/bash

echo "[Step 1] Build firmware ELF using ARM compiler"
echo "→ Firmware not found. Building firmware..."
cmake -S elf -B elf/build -DCMAKE_TOOLCHAIN_FILE=toolchain/gcc-arm-none-eabi.cmake
cmake --build elf/build
echo "[Finish step 1] Firmware built successfully."

echo
echo "[Step 2] Build the simulator"
cmake -S . -B build
cmake --build build
echo "[Finish step 2] Build complete. Check if the simulator binary is located in build/akas_simulator/"

echo "[Step 3] Run the simulator"
build/akas_simulator/stm32f103c8t6_emulator elf/firmware.elf akas_output/emulation_log/emulation.log
echo "[Finish step 3] Simulator is running. You can now interact with it."

echo "[Step 4] Test report genertion"
g++ akas_report_generator/Generator.cpp -o akas_report_generator/Generator
akas_report_generator/Generator akas_output/emulation_log/code_line_emulation.log akas_output/test_report
echo "[Finish step 4] Test report generated successfully. Check the akas_output/test_report directory."
read -p "Press Enter to continue..."
