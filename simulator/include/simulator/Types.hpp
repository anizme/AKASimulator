#pragma once

#include <cstdint>
#include <string>
#include <memory>
#include <vector>
#include <map>
#include <functional>
#include <stdexcept>

namespace Simulator
{

    // ============================================================================
    // BASIC TYPES
    // ============================================================================

    using Address = uint64_t;
    using Size = uint64_t;
    using Byte = uint8_t;
    using Word = uint32_t;

    // ============================================================================
    // ENUMERATIONS
    // ============================================================================

    enum class MemoryPermission : uint8_t
    {
        None = 0,
        Read = 1 << 0,
        Write = 1 << 1,
        Execute = 1 << 2,
        ReadWrite = Read | Write,
        ReadExecute = Read | Execute,
        All = Read | Write | Execute
    };

    // Bitwise operators for MemoryPermission
    inline MemoryPermission operator|(MemoryPermission a, MemoryPermission b)
    {
        return static_cast<MemoryPermission>(
            static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
    }

    inline bool operator&(MemoryPermission a, MemoryPermission b)
    {
        return (static_cast<uint8_t>(a) & static_cast<uint8_t>(b)) != 0;
    }

    enum class BootMode
    {
        Flash,
        SystemMemory,
        SRAM
    };

    enum class ArchitectureType
    {
        ARMCortexM3,
        ARMCortexM4,
        ARMCortexM7,
        ARMCortexA,
        RISCV32,
        RISCV64,
        AVR,
        x86,
        Unknown
    };

    enum class ISA
    {
        ARM,    // 32-bit ARM
        Thumb,  // ARM Thumb (16-bit)
        Thumb2, // ARM Thumb-2 (mixed 16/32-bit)
        ARM64,  // 64-bit ARM
        RISCV32,
        RISCV64,
        AVR,
        x86,
        x86_64,
        Unknown
    };

    enum class ExecutionStatus
    {
        NotStarted,
        Running,
        Paused,
        Success,
        Error,
        Timeout,
        Stopped
    };

    enum class SimulationError
    {
        None,
        DivisionByZero,
        NullPointerDereference,
        InvalidMemoryAccess,
        InvalidInstruction,
        StackOverflow,
        UnknownError
    };

    // ============================================================================
    // RESULT TYPE (for error handling)
    // ============================================================================

    template <typename T>
    class Result
    {
    public:
        // Success constructor
        static Result<T> Success(T value)
        {
            Result<T> r;
            r.success_ = true;
            r.value_ = std::move(value);
            return r;
        }

        // Error constructor
        static Result<T> Error(const std::string &message)
        {
            Result<T> r;
            r.success_ = false;
            r.error_message_ = message;
            return r;
        }

        bool isSuccess() const { return success_; }
        bool isError() const { return !success_; }

        const T &value() const
        {
            if (!success_)
            {
                throw std::runtime_error("Accessing value of failed Result: " + error_message_);
            }
            return value_;
        }

        T &value()
        {
            if (!success_)
            {
                throw std::runtime_error("Accessing value of failed Result: " + error_message_);
            }
            return value_;
        }

        const std::string &errorMessage() const { return error_message_; }

        // Implicit bool conversion
        operator bool() const { return success_; }

        // Get value or default
        T valueOr(const T &default_value) const
        {
            return success_ ? value_ : default_value;
        }

    private:
        Result() : success_(false) {}

        bool success_;
        T value_;
        std::string error_message_;
    };

    // Specialization for void
    template <>
    class Result<void>
    {
    public:
        static Result<void> Success()
        {
            Result<void> r;
            r.success_ = true;
            return r;
        }

        static Result<void> Error(const std::string &message)
        {
            Result<void> r;
            r.success_ = false;
            r.error_message_ = message;
            return r;
        }

        bool isSuccess() const { return success_; }
        bool isError() const { return !success_; }

        const std::string &errorMessage() const { return error_message_; }

        operator bool() const { return success_; }

    private:
        Result() : success_(false) {}

        bool success_;
        std::string error_message_;
    };

    // ============================================================================
    // MEMORY REGION DESCRIPTOR
    // ============================================================================

    struct MemoryRegion
    {
        std::string name;
        Address base_address;
        Size size;
        MemoryPermission permission;

        MemoryRegion(const std::string &n, Address addr, Size sz, MemoryPermission perm)
            : name(n), base_address(addr), size(sz), permission(perm) {}
    };

    // ============================================================================
    // SOURCE INFO (for tracing)
    // ============================================================================

    struct SourceInfo
    {
        std::string filename;
        int line_number;
        int column_number;
        std::string function_name;

        SourceInfo() : line_number(0), column_number(0) {}

        bool isValid() const
        {
            return !filename.empty() && filename != "??" && line_number > 0;
        }

        std::string toString() const
        {
            if (!isValid())
            {
                return "unknown";
            }
            std::string result = filename + ":" + std::to_string(line_number);
            if (column_number > 0)
            {
                result += ":" + std::to_string(column_number);
            }
            if (!function_name.empty() && function_name != "??")
            {
                result += " (" + function_name + ")";
            }
            return result;
        }
    };

    // ============================================================================
    // BINARY INFO (from ELF loader)
    // ============================================================================

    struct BinaryInfo
    {
        std::string file_path;
        Address entry_point;
        Address main_address;

        // Symbol addresses for custom hooks
        Address akas_assert_u32_address;
        Address akas_assert_u64_address;
        Address aka_mark_address;
        Address aka_fcall_address; // Global variable address

        // Vector table info
        Address vector_table_address;
        Size vector_table_size;

        BinaryInfo()
            : entry_point(0), main_address(0),
              akas_assert_u32_address(0), akas_assert_u64_address(0),
              aka_mark_address(0), aka_fcall_address(0),
              vector_table_address(0), vector_table_size(0) {}
    };

    // ============================================================================
    // ASSERTION EVENT (for trace output)
    // ============================================================================

    struct AssertionEvent
    {
        Address address;
        std::string actual_name;
        uint64_t actual_value;
        std::string expected_name;
        uint64_t expected_value;
        uint32_t fcall_count;

        AssertionEvent() : address(0), actual_value(0), expected_value(0), fcall_count(0) {}
    };

    // ============================================================================
    // INSTRUCTION TRACE EVENT
    // ============================================================================

    struct InstructionTrace
    {
        Address address;
        std::vector<Byte> bytes;
        std::string mnemonic;
        std::string operands;
        SourceInfo source_info;

        InstructionTrace() : address(0) {}
    };

} // namespace Simulator