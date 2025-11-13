#include "SimulationTracer.hpp"
#include "io/utils/StringUtils.hpp"
#include "core/ArchitectureMapper.hpp"
#include <fstream>
#include <regex>

namespace Simulator
{

    SimulationTracer::SimulationTracer(uc_engine *uc,
                                       const BinaryInfo &binary_info,
                                       LoggerPtr logger,
                                       CPUDescriptor cpu_descriptor)
        : uc_(uc), binary_info_(binary_info), logger_(logger),
          capstone_handle_(0), enable_instruction_trace_(true),
          instruction_count_(0), main_return_address_(0),
          cpu_descriptor_(cpu_descriptor)
    {
    }

    SimulationTracer::~SimulationTracer()
    {
        if (capstone_handle_)
        {
            cs_close(&capstone_handle_);
        }
    }

    Result<void> SimulationTracer::initialize()
    {
        LOG_INFO(logger_, "Initializing SimulationTracer...");

        // Map architecture metadata to Capstone constants
        cs_arch arch = ArchitectureMapper::getCapstoneArch(cpu_descriptor_.arch_type);
        cs_mode mode = ArchitectureMapper::getCapstoneMode(cpu_descriptor_.isa);

        LOG_DEBUG_F(logger_) << "  Capstone config: arch=" << arch
                             << ", mode=" << mode
                             << " (ISA: " << ArchitectureMapper::getISAName(cpu_descriptor_.isa) << ")";

        cs_err err = cs_open(arch, mode, &capstone_handle_);
        if (err != CS_ERR_OK)
        {
            return Result<void>::Error("Failed to initialize Capstone: " +
                                       std::string(cs_strerror(err)));
        }

        cs_option(capstone_handle_, CS_OPT_DETAIL, CS_OPT_ON);
        LOG_DEBUG(logger_, "  ✓ Capstone initialized");

        // Initialize Symbolizer
        symbolizer_ = std::make_unique<Symbolizer>(binary_info_.file_path, logger_);
        LOG_DEBUG(logger_, "  ✓ Symbolizer initialized");

        LOG_INFO(logger_, "SimulationTracer ready");
        return Result<void>::Success();
    }
    void SimulationTracer::onCodeExecution(const CodeHookEvent &event)
    {
        instruction_count_++;

        Address address = event.address;

        // Check for main entry
        if (address == binary_info_.main_address && main_return_address_ == 0)
        {
            // Capture LR (return address)
            uint32_t lr;
            uc_reg_read(uc_, UC_ARM_REG_LR, &lr);
            main_return_address_ = lr & ~1U; // Clear Thumb bit

            LOG_INFO_F(logger_) << "Entered main(), return address: "
                                << Utils::formatHex(main_return_address_);
        }

        // Check for main return
        if (main_return_address_ != 0 && address == main_return_address_)
        {
            LOG_INFO(logger_, "Main returned, stopping execution");
            uc_emu_stop(uc_);
            return;
        }

        // Check for AKAS_assert_u32
        if (address == binary_info_.akas_assert_u32_address)
        {
            handleAssertU32(address);
        }

        // Check for AKAS_assert_u64
        if (address == binary_info_.akas_assert_u64_address)
        {
            handleAssertU64(address);
        }

        // Check for AKA_mark
        if (address == binary_info_.aka_mark_address)
        {
            handleMark(address);
        }

        // Trace instruction
        if (enable_instruction_trace_)
        {
            handleInstructionTrace(event);
        }
    }

    void SimulationTracer::handleInstructionTrace(const CodeHookEvent &event)
    {
        InstructionTrace trace;
        trace.address = event.address;
        trace.bytes = event.instruction_bytes;

        // Disassemble
        if (disassembleInstruction(event, trace))
        {
            // Resolve source location
            trace.source_info = symbolizer_->resolve(event.address);

            // Store trace (limit to prevent memory issues)
            if (instruction_traces_.size() < 100000)
            {
                instruction_traces_.push_back(trace);
            }
        }
    }

    bool SimulationTracer::disassembleInstruction(const CodeHookEvent &event,
                                                  InstructionTrace &trace)
    {
        cs_insn *insn;
        size_t count = cs_disasm(capstone_handle_,
                                 event.instruction_bytes.data(),
                                 event.instruction_bytes.size(),
                                 event.address, 1, &insn);

        if (count > 0)
        {
            trace.mnemonic = insn->mnemonic;
            trace.operands = insn->op_str;
            cs_free(insn, count);
            return true;
        }

        return false;
    }

    void SimulationTracer::handleAssertU32(Address address)
    {
        LOG_DEBUG_F(logger_) << "AKAS_assert_u32 called at " << Utils::formatHex(address);

        AssertionEvent event;
        event.address = address;

        // Read R0 (actual value)
        uint32_t actual;
        uc_reg_read(uc_, UC_ARM_REG_R0, &actual);
        event.actual_value = actual;

        // Read R1 (expected value)
        uint32_t expected;
        uc_reg_read(uc_, UC_ARM_REG_R1, &expected);
        event.expected_value = expected;

        // Read AKA_fCall global variable
        if (binary_info_.aka_fcall_address != 0)
        {
            uint32_t fcall;
            uc_mem_read(uc_, binary_info_.aka_fcall_address, &fcall, sizeof(fcall));
            event.fcall_count = fcall;
        }
        else
        {
            event.fcall_count = 0;
        }

        // Get source info to extract variable names
        SourceInfo src = symbolizer_->resolve(address);
        if (src.isValid())
        {
            std::string line = readSourceLine(src);

            // Parse: akas_assert_u32(actual_var, EXPECTED_var);
            std::regex pattern(R"(\(\s*(\w+)\s*,\s*(\w+)\s*\))");
            std::smatch match;
            if (std::regex_search(line, match, pattern))
            {
                event.actual_name = match[1].str();
                event.expected_name = match[2].str();
            }
        }

        assertion_events_.push_back(event);

        LOG_DEBUG_F(logger_) << "  Actual: " << event.actual_name
                             << " = " << actual;
        LOG_DEBUG_F(logger_) << "  Expected: " << event.expected_name
                             << " = " << expected;
        LOG_DEBUG_F(logger_) << "  FCall: " << event.fcall_count;
    }

    void SimulationTracer::handleAssertU64(Address address)
    {
        LOG_DEBUG_F(logger_) << "AKAS_assert_u64 called at " << Utils::formatHex(address);
        // TODO: Implement u64 assertion handling
        // Similar to u32 but read 64-bit values
    }

    void SimulationTracer::handleMark(Address address)
    {
        LOG_DEBUG_F(logger_) << "AKA_mark called at " << Utils::formatHex(address);

        // Get source line and extract marker comment
        SourceInfo src = symbolizer_->resolve(address);
        if (src.isValid())
        {
            std::string line = readSourceLine(src);

            // Look for /* marker_text */
            std::regex pattern(R"(/\*(.*?)\*/)");
            std::smatch match;
            if (std::regex_search(line, match, pattern))
            {
                std::string marker = Utils::trim(match[1].str());
                markers_.push_back(marker);

                LOG_DEBUG_F(logger_) << "  Marker: " << marker;
            }
        }
    }

    std::string SimulationTracer::readSourceLine(const SourceInfo &info)
    {
        if (!info.isValid())
        {
            return "";
        }

        std::ifstream file(info.filename);
        if (!file.is_open())
        {
            return "";
        }

        std::string line;
        for (int i = 1; i <= info.line_number && std::getline(file, line); ++i)
        {
            // Keep reading until we reach the target line
        }

        // If column is specified, extract substring from column onwards
        if (info.column_number > 0 && info.column_number < (int)line.size())
        {
            line = line.substr(info.column_number);
        }

        return Utils::trim(line);
    }

} // namespace Simulator