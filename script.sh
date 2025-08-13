#!/bin/bash

echo "[Step 1] Build firmware ELF using ARM compiler"
cmake -S akas_working_space/test_driver -B akas_working_space/test_driver/build -DCMAKE_TOOLCHAIN_FILE=toolchain/gcc-arm-none-eabi.cmake
cmake --build akas_working_space/test_driver/build
echo "[Finish step 1] Firmware built successfully."

echo "[Step 2] Build the simulator"
# cmake -S . -B build
cmake --build build
echo "[Finish step 2] Build complete. Check if the simulator binary is located in build/akas_simulator/"

echo "[Step 3] Run the simulator"
build/akas_simulator/akas_emulator akas_working_space/test_driver/firmware.elf akas_working_space/emulation_log/emulation.log
echo "[Finish step 3] Emulation completed successfully. Check the akas_working_space/emulation_log directory for logs."

echo "[Step 4] Test report genertion"
cmake -S akas_generator/test_reporter -B akas_generator/test_reporter/build
cmake --build akas_generator/test_reporter/build
akas_generator/test_reporter/build/akas_reporter akas_working_space/test_case/uut_int_int_charmul_MyStructmul_intmul_size_t_manual_0.json akas_working_space/emulation_log/actuals_emulation.log akas_working_space/emulation_log/code_line_emulation.log
echo "[Finish step 4] Test report generated successfully. Check the akas_output/test_report directory."

read -p "Press Enter to continue..."
