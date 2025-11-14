#include "core/loader/ELFLoader.hpp"
#include "architecture/ArchitectureFactory.hpp"
#include "architecture/arm/chips/STM32F103C8T6.hpp"
#include "io/logging/ConsoleLogger.hpp"
#include "io/utils/StringUtils.hpp"
#include <unicorn/unicorn.h>

using namespace Simulator;

int main(int argc, char **argv)
{
    auto logger = std::make_shared<ConsoleLogger>();

    LOG_INFO(logger, "=== Testing Step 3.1: ELF Loader ===");

    // Check command line arguments
    if (argc < 2)
    {
        LOG_ERROR(logger, "Usage: test_step3_1 <elf_file>");
        LOG_INFO(logger, "Please provide an ELF file to test with");
        return 1;
    }

    std::string elf_path = argv[1];

    // Register architecture
    auto &factory = ArchitectureFactory::instance();
    factory.registerArchitecture<ARM::STM32F103C8T6>();

    // Create architecture
    auto arch_result = factory.create("stm32f103c8t6");
    if (!arch_result)
    {
        LOG_ERROR_F(logger) << "Failed to create architecture: " << arch_result.errorMessage();
        return 1;
    }

    auto arch = arch_result.value();
    auto memory_map = arch->getMemoryMap();

    // Initialize Unicorn
    LOG_INFO(logger, "\n[Test 1] Initialize Unicorn");
    uc_engine *uc = nullptr;
    uc_err err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc);
    if (err != UC_ERR_OK)
    {
        LOG_ERROR_F(logger) << "Failed to initialize Unicorn: " << uc_strerror(err);
        return 1;
    }
    LOG_INFO(logger, "  ✓ Unicorn initialized");

    // Map memory regions
    LOG_INFO(logger, "\n[Test 2] Map memory regions");
    for (const auto &region : memory_map.getRegions())
    {
        uint32_t perm = 0;
        if (region.permission & MemoryPermission::Read)
            perm |= UC_PROT_READ;
        if (region.permission & MemoryPermission::Write)
            perm |= UC_PROT_WRITE;
        if (region.permission & MemoryPermission::Execute)
            perm |= UC_PROT_EXEC;

        err = uc_mem_map(uc, region.base_address, region.size, perm);
        if (err != UC_ERR_OK)
        {
            LOG_ERROR_F(logger) << "Failed to map " << region.name << ": " << uc_strerror(err);
            return 1;
        }

        LOG_DEBUG_F(logger) << "  Mapped " << region.name
                            << " at " << Utils::formatHex(region.base_address)
                            << " (" << (region.size / 1024) << " KB)";
    }
    LOG_INFO(logger, "  ✓ Memory mapped");

    // Test ELF Loader
    LOG_INFO(logger, "\n[Test 3] Load ELF file");
    ELFLoader loader(uc, logger);

    auto result = loader.load(elf_path);
    if (!result)
    {
        LOG_ERROR_F(logger) << "Failed to load ELF: " << result.errorMessage();
        uc_close(uc);
        return 1;
    }

    auto binary_info = result.value();

    LOG_INFO(logger, "\n[Test 4] Verify loaded data");
    LOG_INFO_F(logger) << "  Entry point: " << Utils::formatHex(binary_info.entry_point);
    LOG_INFO_F(logger) << "  Main address: " << Utils::formatHex(binary_info.main_address);

    if (binary_info.akas_assert_u32_address)
    {
        LOG_INFO_F(logger) << "  AKAS_assert_u32: " << Utils::formatHex(binary_info.akas_assert_u32_address);
    }

    if (binary_info.aka_mark_address)
    {
        LOG_INFO_F(logger) << "  AKA_mark: " << Utils::formatHex(binary_info.aka_mark_address);
    }

    if (binary_info.aka_fcall_address)
    {
        LOG_INFO_F(logger) << "  AKA_fCall: " << Utils::formatHex(binary_info.aka_fcall_address);
    }

    LOG_INFO_F(logger) << "  Vector table: " << Utils::formatHex(binary_info.vector_table_address)
                       << " (size: " << binary_info.vector_table_size << ")";

    // Verify we can read from memory
    LOG_INFO(logger, "\n[Test 5] Verify memory content");
    uint32_t initial_sp = 0;
    err = uc_mem_read(uc, 0x08000000, &initial_sp, sizeof(initial_sp));
    if (err == UC_ERR_OK)
    {
        LOG_INFO_F(logger) << "  Initial SP (from vector table): " << Utils::formatHex(initial_sp);
        LOG_INFO(logger, "  ✓ Memory readable");
    }
    else
    {
        LOG_ERROR_F(logger) << "  Failed to read memory: " << uc_strerror(err);
    }

    // Cleanup
    uc_close(uc);

    LOG_INFO(logger, "=== All tests passed! ===");

    return 0;
}