echo "[Step 1] elf firmware file should be built by Clang"
cmake -S akas_working_space/test_driver -B akas_working_space/test_driver/build -DCMAKE_TOOLCHAIN_FILE=toolchain/clang-arm-none-eabi.cmake
cmake --build akas_working_space/test_driver/build
echo "[Finish step 1] Firmware built successfully."

echo "[Step 2] Build the simulator"
cmake -S . -B build
cmake --build build
echo "[Finish step 2] Build complete. Check if the simulator binary is located in build/akas_simulator/"

echo "[Step 3] Run the simulator"
build/akas_simulator/akas_emulator akas_working_space/test_driver/firmware.elf akas_working_space/emulation_log/emulation.log
echo "[Finish step 3] Emulation completed successfully. Check the akas_working_space/emulation_log directory for logs."


read -p "Press Enter to continue..."
