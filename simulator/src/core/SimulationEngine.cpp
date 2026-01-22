#include "SimulationEngine.hpp"
#include "core/ArchitectureMapper.hpp"
#include "io/utils/StringUtils.hpp"
#include "io/writers/SimulationLogWriter.hpp"
#include "io/writers/TraceFileWriter.hpp"
#include "io/writers/TestPathWriter.hpp"

namespace Simulator
{

    SimulationEngine::SimulationEngine(ArchitecturePtr architecture, LoggerPtr logger)
        : architecture_(architecture), logger_(logger),
          cpu_descriptor_(architecture->getCPUDescriptor()),
          uc_(nullptr), uc_initialized_(false),
          boot_mode_(BootMode::Flash),
          binary_loaded_(false), stubs_loaded_(false)
    {
    }

    SimulationEngine::~SimulationEngine()
    {
        // Cleanup in reverse order

        // Remove hooks first (before closing Unicorn)
        if (hook_dispatcher_)
        {
            hook_dispatcher_->removeHooks();
        }

        // Clear components
        stub_manager_.reset();
        error_detector_.reset();
        tracer_.reset();
        hook_dispatcher_.reset();
        memory_manager_.reset();
        elf_loader_.reset();

        // Close Unicorn last
        if (uc_initialized_ && uc_)
        {
            uc_close(uc_);
            uc_ = nullptr;
            uc_initialized_ = false;
        }
    }

    Result<void> SimulationEngine::initialize(BootMode boot_mode)
    {
        LOG_INFO(logger_, "=== Initializing Simulation Engine ===");

        boot_mode_ = boot_mode;

        // 1. Initialize Unicorn
        auto uc_result = initializeUnicorn();
        if (!uc_result)
        {
            return uc_result;
        }

        // 2. Setup memory regions
        LOG_INFO(logger_, "\n[Step 2/4] Setting up memory regions...");
        memory_manager_ = std::make_shared<MemoryManager>(uc_, architecture_, logger_);
        auto mem_result = memory_manager_->setupMemoryRegions(boot_mode_);
        if (!mem_result)
        {
            return mem_result;
        }

        // 3. Create components
        LOG_INFO(logger_, "\n[Step 3/4] Creating components...");
        elf_loader_ = std::make_shared<ELFLoader>(uc_, logger_);
        hook_dispatcher_ = std::make_shared<HookDispatcher>(uc_, logger_);

        LOG_INFO(logger_, "=== Initialization Complete ===");

        return Result<void>::Success();
    }

    Result<void> SimulationEngine::initializeUnicorn()
    {
        LOG_INFO(logger_, "\n[Step 1/4] Initializing Unicorn Engine...");

        // Map architecture to Unicorn constants
        uc_arch arch = ArchitectureMapper::getUnicornArch(cpu_descriptor_.arch_type);
        uc_mode mode = ArchitectureMapper::getUnicornMode(cpu_descriptor_.isa);

        LOG_DEBUG_F(logger_) << "  CPU: " << ArchitectureMapper::getCPUInfo(cpu_descriptor_);
        LOG_DEBUG_F(logger_) << "  Unicorn arch=" << arch << ", mode=" << mode;

        // Check if supported
        if (!ArchitectureMapper::isUnicornSupported(cpu_descriptor_.arch_type))
        {
            return Result<void>::Error(
                "Architecture not supported by Unicorn: " +
                std::string(ArchitectureMapper::getArchitectureName(cpu_descriptor_.arch_type)));
        }

        // Initialize Unicorn
        uc_err err = uc_open(arch, mode, &uc_);
        if (err != UC_ERR_OK)
        {
            return Result<void>::Error(
                "Failed to initialize Unicorn: " + std::string(uc_strerror(err)));
        }

        uc_initialized_ = true;
        LOG_INFO(logger_, "  ✓ Unicorn initialized");

        return Result<void>::Success();
    }

    Result<void> SimulationEngine::loadBinary(const std::string &elf_path)
    {
        LOG_INFO(logger_, "=== Loading Binary ===");

        if (!uc_initialized_)
        {
            return Result<void>::Error("Engine not initialized. Call initialize() first.");
        }

        // Load ELF
        auto result = elf_loader_->load(elf_path);
        if (!result)
        {
            return Result<void>::Error("Failed to load ELF: " + result.errorMessage());
        }

        binary_info_ = result.value();
        binary_loaded_ = true;

        // Setup CPU state
        auto cpu_result = setupCPUState();
        if (!cpu_result)
        {
            return cpu_result;
        }

        // Copy boot alias (0x00000000 points to Flash/SRAM)
        auto alias_result = copyBootAlias();
        if (!alias_result)
        {
            return alias_result;
        }

        LOG_INFO(logger_, "=== Binary Loaded Successfully ===");

        return Result<void>::Success();
    }

    Result<void> SimulationEngine::setupCPUState()
    {
        LOG_INFO(logger_, "Setting up initial CPU state...");

        // Read initial stack pointer (first word in vector table)
        uint32_t initial_sp;
        uc_err err = uc_mem_read(uc_, binary_info_.vector_table_address,
                                 &initial_sp, sizeof(initial_sp));
        if (err != UC_ERR_OK)
        {
            return Result<void>::Error(
                "Failed to read initial SP: " + std::string(uc_strerror(err)));
        }

        // Read reset handler (second word in vector table)
        uint32_t reset_handler;
        err = uc_mem_read(uc_, binary_info_.vector_table_address + 4,
                          &reset_handler, sizeof(reset_handler));
        if (err != UC_ERR_OK)
        {
            return Result<void>::Error(
                "Failed to read reset handler: " + std::string(uc_strerror(err)));
        }

        // Set SP
        err = uc_reg_write(uc_, UC_ARM_REG_SP, &initial_sp);
        if (err != UC_ERR_OK)
        {
            return Result<void>::Error(
                "Failed to set SP: " + std::string(uc_strerror(err)));
        }

        // Set PC (with Thumb bit for ARM)
        uint32_t pc = reset_handler | 1; // Set Thumb bit
        err = uc_reg_write(uc_, UC_ARM_REG_PC, &pc);
        if (err != UC_ERR_OK)
        {
            return Result<void>::Error(
                "Failed to set PC: " + std::string(uc_strerror(err)));
        }

        LOG_INFO_F(logger_) << "  Initial SP: " << Utils::formatHex(initial_sp);
        LOG_INFO_F(logger_) << "  Reset Handler: " << Utils::formatHex(reset_handler);
        LOG_INFO(logger_, "  ✓ CPU state initialized");

        return Result<void>::Success();
    }

    Result<void> SimulationEngine::copyBootAlias()
    {
        LOG_INFO(logger_, "Setting up boot alias (0x00000000)...");

        auto boot_desc = architecture_->getBootDescriptor();
        auto mem_map = architecture_->getMemoryMap();

        // Determine source based on boot mode
        Address source_addr;
        Size copy_size;

        switch (boot_mode_)
        {
        case BootMode::Flash:
            source_addr = mem_map.getFlashBase();
            copy_size = std::min(boot_desc.boot_alias_size, mem_map.getFlashSize());
            break;

        case BootMode::SRAM:
            source_addr = mem_map.getSRAMBase();
            copy_size = std::min(boot_desc.boot_alias_size, mem_map.getSRAMSize());
            break;

        case BootMode::SystemMemory:
        {
            auto *sys_mem = mem_map.findRegion("SystemMemory");
            if (!sys_mem)
            {
                LOG_WARNING(logger_, "  System Memory not found, using Flash");
                source_addr = mem_map.getFlashBase();
                copy_size = std::min(boot_desc.boot_alias_size, mem_map.getFlashSize());
            }
            else
            {
                source_addr = sys_mem->base_address;
                copy_size = std::min(boot_desc.boot_alias_size, sys_mem->size);
            }
            break;
        }
        }

        // Allocate buffer and copy
        std::vector<uint8_t> buffer(copy_size);

        uc_err err = uc_mem_read(uc_, source_addr, buffer.data(), copy_size);
        if (err != UC_ERR_OK)
        {
            return Result<void>::Error(
                "Failed to read from source: " + std::string(uc_strerror(err)));
        }

        err = uc_mem_write(uc_, boot_desc.boot_alias_base, buffer.data(), copy_size);
        if (err != UC_ERR_OK)
        {
            return Result<void>::Error(
                "Failed to write to boot alias: " + std::string(uc_strerror(err)));
        }

        LOG_INFO_F(logger_) << "  Copied " << (copy_size / 1024) << " KB from "
                            << Utils::formatHex(source_addr) << " to "
                            << Utils::formatHex(boot_desc.boot_alias_base);
        LOG_INFO(logger_, "  ✓ Boot alias setup complete");

        return Result<void>::Success();
    }

    Result<void> SimulationEngine::loadStubs(const std::string &stub_file)
    {
        LOG_INFO(logger_, "=== Loading Stubs ===");

        if (!binary_loaded_)
        {
            return Result<void>::Error("Binary not loaded. Call loadBinary() first.");
        }

        stub_manager_ = std::make_shared<StubManager>(uc_, logger_);
        stub_manager_->arch_type = cpu_descriptor_.arch_type;
        stub_manager_->isa = cpu_descriptor_.isa;

        // Load stub definitions
        auto load_result = stub_manager_->loadStubFile(stub_file);
        if (!load_result)
        {
            return load_result;
        }

        // Resolve addresses
        auto resolve_result = stub_manager_->resolveAddresses(binary_info_.file_path);
        if (!resolve_result)
        {
            return resolve_result;
        }

        stubs_loaded_ = true;
        LOG_INFO(logger_, "=== Stubs Loaded Successfully ===");

        return Result<void>::Success();
    }

    Result<void> SimulationEngine::setupHooks(const ExecutionConfig &config)
    {
        LOG_INFO(logger_, "Setting up hooks...");

        // Create tracer
        if (config.enable_instruction_trace)
        {
            tracer_ = std::make_shared<SimulationTracer>(
                uc_, binary_info_, logger_, cpu_descriptor_);
            auto tracer_result = tracer_->initialize();
            if (!tracer_result)
            {
                return tracer_result;
            }
            hook_dispatcher_->registerHandler(tracer_);
            LOG_DEBUG(logger_, "  ✓ Tracer registered");
        }

        // Create error detector
        if (config.enable_error_detection)
        {
            error_detector_ = std::make_shared<ErrorDetector>(
                uc_, binary_info_, logger_);
            auto error_result = error_detector_->initialize();
            if (!error_result)
            {
                return error_result;
            }
            hook_dispatcher_->registerHandler(error_detector_);
            LOG_DEBUG(logger_, "  ✓ Error detector registered");
        }

        // Register stub manager
        if (config.enable_stubs && stubs_loaded_)
        {
            hook_dispatcher_->registerHandler(stub_manager_);
            LOG_DEBUG(logger_, "  ✓ Stub manager registered");
        }

        // Setup hooks with Unicorn
        auto hook_result = hook_dispatcher_->setupHooks();
        if (!hook_result)
        {
            return hook_result;
        }

        LOG_INFO(logger_, "  ✓ All hooks setup complete");

        return Result<void>::Success();
    }

    Result<SimulationStatus> SimulationEngine::execute(const ExecutionConfig &config)
    {
        LOG_INFO(logger_, "=== Starting Execution ===");

        if (!binary_loaded_)
        {
            return Result<SimulationStatus>::Error("No binary loaded");
        }

        // Setup hooks
        auto hook_result = setupHooks(config);
        if (!hook_result)
        {
            return Result<SimulationStatus>::Error(
                "Failed to setup hooks: " + hook_result.errorMessage());
        }

        // Get entry point
        Address entry = binary_info_.entry_point;
        if (cpu_descriptor_.isa != ISA::Thumb || cpu_descriptor_.isa == ISA::Thumb2)
        {
            entry = binary_info_.entry_point | 1;
        }

        LOG_INFO_F(logger_) << "Entry point: " << Utils::formatHex(entry);
        LOG_INFO_F(logger_) << "Instruction limit: "
                            << (config.instruction_limit == 0 ? "unlimited" : std::to_string(config.instruction_limit));

        // Execute
        LOG_INFO(logger_, "\n--- Execution Started ---");

        uc_err err = uc_emu_start(uc_, entry, 0xFFFFFFFF,
                                  config.timeout_ms * 1000, // Convert ms to us
                                  config.instruction_limit);

        LOG_INFO(logger_, "--- Execution Stopped ---\n");

        // Check results
        if (error_detector_ && error_detector_->hasError())
        {
            LOG_ERROR_F(logger_) << "Execution error: "
                                 << error_detector_->getErrorMessage();
            return Result<SimulationStatus>::Success(SimulationStatus::Error, 
                error_detector_->getErrorMessage() + " #AT " + tracer_->getInstructionTraces().back().source_info.toString());
        }

        if (err == UC_ERR_OK)
        {
            LOG_INFO(logger_, "✓ Execution completed successfully");
            return Result<SimulationStatus>::Success(SimulationStatus::Success);
        }

        // Handle Unicorn errors
        std::string error_msg = std::string(uc_strerror(err)) + " at " + tracer_->getInstructionTraces().back().source_info.toString();

        LOG_ERROR_F(logger_) << "Unicorn error: " << error_msg;
        return Result<SimulationStatus>::Success(SimulationStatus::Error, error_msg);
    }

    Result<void> SimulationEngine::generateOutputs(
        const std::string &log_file,
        const std::string &trace_file,
        const std::string &testpath_file)
    {

        LOG_INFO(logger_, "=== Generating Output Files ===");

        if (!tracer_)
        {
            return Result<void>::Error("No tracer available. Enable instruction tracing.");
        }

        // 1. Execution log
        if (!log_file.empty())
        {
            SimulationLogWriter log_writer(
                log_file,
                tracer_->getInstructionTraces(),
                binary_info_,
                logger_);

            auto result = log_writer.write();
            if (!result)
            {
                LOG_ERROR_F(logger_) << "Failed to write execution log: "
                                     << result.errorMessage();
            }
        }

        // 2. Trace file (JSON)
        if (!trace_file.empty())
        {
            TraceFileWriter trace_writer(
                trace_file,
                tracer_->getAssertionEvents(),
                logger_);

            auto result = trace_writer.write();
            if (!result)
            {
                LOG_ERROR_F(logger_) << "Failed to write trace file: "
                                     << result.errorMessage();
            }
        }

        // 3. Test path file
        if (!testpath_file.empty())
        {
            TestPathWriter path_writer(
                testpath_file,
                tracer_->getMarkers(),
                logger_);

            auto result = path_writer.write();
            if (!result)
            {
                LOG_ERROR_F(logger_) << "Failed to write test path file: "
                                     << result.errorMessage();
            }
        }

        LOG_INFO(logger_, "=== Output Generation Complete ===");

        return Result<void>::Success();
    }

} // namespace Simulator