#include "ErrorDetector.hpp"
#include "io/utils/StringUtils.hpp"
#include <sstream>

namespace Simulator
{

    ErrorDetector::ErrorDetector(uc_engine *uc,
                                 const BinaryInfo &binary_info,
                                 LoggerPtr logger)
        : uc_(uc), binary_info_(binary_info), logger_(logger),
          capstone_handle_(0), error_detected_(false),
          error_type_(SimulationError::None)
    {
    }

    ErrorDetector::~ErrorDetector()
    {
        if (capstone_handle_)
        {
            cs_close(&capstone_handle_);
        }
    }

    Result<void> ErrorDetector::initialize()
    {
        LOG_INFO(logger_, "Initializing ErrorDetector...");

        // Initialize Capstone
        cs_err err = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &capstone_handle_);
        if (err != CS_ERR_OK)
        {
            return Result<void>::Error("Failed to initialize Capstone");
        }

        cs_option(capstone_handle_, CS_OPT_DETAIL, CS_OPT_ON);

        LOG_INFO(logger_, "ErrorDetector ready");
        return Result<void>::Success();
    }

    void ErrorDetector::onCodeExecution(const CodeHookEvent &event)
    {
        // Don't check if error already detected
        if (error_detected_)
        {
            return;
        }

        // Check for null pointer call (PC in vector table)
        detectNullPointerCall(event.address);

        // Check for division by zero
        detectDivisionByZero(event.address,
                             event.instruction_bytes.data(),
                             event.instruction_bytes.size());
    }

    void ErrorDetector::detectNullPointerCall(Address address)
    {
        // Check if PC is in vector table region
        Address vt_start = binary_info_.vector_table_address;
        Address vt_end = vt_start + binary_info_.vector_table_size;

        if (address >= vt_start && address < vt_end)
        {
            std::ostringstream oss;
            oss << "Null function call detected: PC = " << Utils::formatHex(address)
                << " (inside vector table region)";

            error_message_ = oss.str();
            error_type_ = SimulationError::NullPointerDereference;
            error_detected_ = true;

            LOG_ERROR(logger_, error_message_);
            uc_emu_stop(uc_);
        }
    }

    void ErrorDetector::detectDivisionByZero(Address address,
                                             const uint8_t *code,
                                             size_t size)
    {
        cs_insn *insn;
        size_t count = cs_disasm(capstone_handle_, code, size, address, 1, &insn);

        if (count == 0)
        {
            return;
        }

        // Check for UDIV or SDIV instruction
        if (insn->id == ARM_INS_UDIV || insn->id == ARM_INS_SDIV)
        {
            // Division instruction: UDIV/SDIV Rd, Rn, Rm
            // Rd = Rn / Rm
            // Need to check if Rm (divisor) is zero

            if (insn->detail->arm.op_count >= 3)
            {
                cs_arm_op *divisor_op = &insn->detail->arm.operands[2];

                if (divisor_op->type == ARM_OP_REG)
                {
                    // Map Capstone register to Unicorn register
                    int uc_reg = mapCapstoneRegToUnicorn(static_cast<arm_reg>(divisor_op->reg));
                    if (uc_reg != -1)
                    {
                        uint32_t divisor_value;
                        uc_reg_read(uc_, uc_reg, &divisor_value);

                        if (divisor_value == 0)
                        {
                            std::ostringstream oss;
                            oss << "Division by zero at " << Utils::formatHex(address)
                                << ": " << insn->mnemonic << " " << insn->op_str;

                            error_message_ = oss.str();
                            error_type_ = SimulationError::DivisionByZero;
                            error_detected_ = true;

                            LOG_ERROR(logger_, error_message_);
                            uc_emu_stop(uc_);
                        }
                    }
                }
            }
        }

        cs_free(insn, count);
    }

    // Helper to map Capstone ARM register to Unicorn register
    int ErrorDetector::mapCapstoneRegToUnicorn(arm_reg reg) const
    {
        switch (reg)
        {
        case ARM_REG_R0:
            return UC_ARM_REG_R0;
        case ARM_REG_R1:
            return UC_ARM_REG_R1;
        case ARM_REG_R2:
            return UC_ARM_REG_R2;
        case ARM_REG_R3:
            return UC_ARM_REG_R3;
        case ARM_REG_R4:
            return UC_ARM_REG_R4;
        case ARM_REG_R5:
            return UC_ARM_REG_R5;
        case ARM_REG_R6:
            return UC_ARM_REG_R6;
        case ARM_REG_R7:
            return UC_ARM_REG_R7;
        case ARM_REG_R8:
            return UC_ARM_REG_R8;
        case ARM_REG_R9:
            return UC_ARM_REG_R9;
        case ARM_REG_R10:
            return UC_ARM_REG_R10;
        case ARM_REG_R11:
            return UC_ARM_REG_R11;
        case ARM_REG_R12:
            return UC_ARM_REG_R12;
        case ARM_REG_SP:
            return UC_ARM_REG_SP;
        case ARM_REG_LR:
            return UC_ARM_REG_LR;
        case ARM_REG_PC:
            return UC_ARM_REG_PC;
        default:
            return -1;
        }
    }

} // namespace Simulator