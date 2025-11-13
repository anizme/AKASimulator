## Test step 1
Logging testing
```
cmake -S . -B build
cmake --build build
./test_step1
```

## Test step 2
Create an architecture based on chip name
```
cmake -S . -B build
cmake --build build
build/test_step2
```

## Test step 3
1. Test step 3.1 - ELFLoader
build/test_step3_1 <path_to_your_elf_file>
```
cmake -S . -B build
cmake --build build
build/test_step3_1 /home/anizme/Documents/AKA/Simulation/AKASimulator/akas_working_space/test_driver/firmware.elf
```

2. Test step 3.2 - Memory mapping
```
cmake -S . -B build
cmake --build build
build//test_step3_2
```