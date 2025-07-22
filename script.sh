echo "[Step 1] Build firmware ELF using ARM compiler"
cmake -S elf_builder -B build/elf_builder -DCMAKE_TOOLCHAIN_FILE=build/elf_builder/toolchain/gcc-arm-none-eabi.cmake
cmake --build build/elf_builder
echo "[Finish step 1] Check if ELF file is located in build/elf_builder/firmware.elf"

echo "[Step 2] Build the simulator"
cmake -S . -B build
cmake --build build
echo "[Finish step 2] Hehe"

read -p "Press Enter to continue..."
