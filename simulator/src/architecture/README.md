# Architecture Module

This module defines **metadata** for different chip architectures.

## Purpose

- Define memory layouts (Flash, SRAM, peripherals)
- Define CPU characteristics (registers, instruction set, features)
- Define boot configuration (vector table, boot modes)
- **NO EXECUTION LOGIC** - pure metadata only

## Architecture
```
IArchitecture (interface)
    ├── getChipName()
    ├── getMemoryMap()
    ├── getCPUDescriptor()
    └── getBootDescriptor()

ARM/
    ├── ARMCortexM3Base (base class)
    └── chips/
        ├── STM32F103C8T6
        └── STM32F407VG
```

## Adding a New Chip

### Example: STM32F103RB (128KB Flash, 20KB RAM)
```cpp
// src/architecture/arm/chips/STM32F103RB.hpp
#pragma once
#include "../ARMCortexM3.hpp"

namespace Simulator {
namespace ARM {

class STM32F103RB : public ARMCortexM3Base {
public:
    std::string getChipName() const override {
        return "stm32f103rb";
    }
    
    std::string getDescription() const override {
        return "STM32F103RB (ARM Cortex-M3, 128KB Flash, 20KB SRAM)";
    }
    
    MemoryMapDescriptor getMemoryMap() const override {
        MemoryMapDescriptor map;
        
        // Different Flash size!
        map.addFlash(0x08000000, 128 * 1024);  // 128KB instead of 64KB
        map.addSRAM(0x20000000, 20 * 1024);
        
        // Same peripherals as F103C8T6...
        // (copy from STM32F103C8T6.hpp)
        
        return map;
    }
    
    // Other methods inherited from ARMCortexM3Base
};

} // namespace ARM
} // namespace Simulator
```

### Register it:
```cpp
// src/architecture/ArchitectureFactory.hpp
#include "arm/chips/STM32F103RB.hpp"

void registerAllArchitectures() {
    auto& factory = ArchitectureFactory::instance();
    
    factory.registerArchitecture<ARM::STM32F103C8T6>();
    factory.registerArchitecture<ARM::STM32F407VG>();
    factory.registerArchitecture<ARM::STM32F103RB>();  // <-- Add this
}
```

That's it! The new chip is now available.

## Usage Example
```cpp
#include "architecture/ArchitectureFactory.hpp"

// Create architecture
auto result = ArchitectureFactory::instance().create("stm32f103c8t6");
if (!result) {
    std::cerr << "Error: " << result.errorMessage() << std::endl;
    return;
}

auto arch = result.value();

// Get memory map
auto map = arch->getMemoryMap();
std::cout << "Flash: " << map.getFlashSize() / 1024 << " KB" << std::endl;
std::cout << "SRAM: " << map.getSRAMSize() / 1024 << " KB" << std::endl;

// Iterate regions
for (const auto& region : map.getRegions()) {
    std::cout << region.name << ": 0x" << std::hex << region.base_address << std::endl;
}

// Get CPU info
auto cpu = arch->getCPUDescriptor();
std::cout << "CPU: " << cpu.architecture << std::endl;
std::cout << "FPU: " << (cpu.has_fpu ? "Yes" : "No") << std::endl;
```

## Design Principles

1. **Metadata only** - No execution logic
2. **Builder pattern** - Easy to construct descriptors
3. **Inheritance** - Share common characteristics (ARMCortexM3Base)
4. **Factory pattern** - Create instances by string name
5. **Type safety** - Strong typing with Result<T>

## Files

- `IArchitecture.hpp` - Main interface
- `Descriptors.hpp` - Data structures (MemoryMapDescriptor, CPUDescriptor, etc.)
- `ArchitectureFactory.hpp` - Factory for creating instances
- `ArchitectureRegistry.cpp` - Registration of all chips
- `arm/ARMCortexM3.hpp` - Base for Cortex-M3 chips
- `arm/chips/*.hpp` - Specific chip implementations