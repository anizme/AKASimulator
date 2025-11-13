#pragma once

#include "simulator/Types.hpp"
#include "core/hooks/HookDispatcher.hpp"
#include "io/logging/ILogger.hpp"
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>

namespace Simulator
{

    /**
     * @brief Detects runtime errors during execution
     *
     * Responsibilities:
     * - Division by zero detection
     * - Null pointer dereference detection
     * - Invalid memory access detection
     * - Stack overflow detection (optional)
     */
    class ErrorDetector : public IHookHandler
    {
    public:
        /**
         * @brief Constructor
         * @param uc Unicorn engine instance
         * @param binary_info Binary information
         * @param logger Logger
         */
        ErrorDetector(uc_engine *uc,
                      const BinaryInfo &binary_info,
                      LoggerPtr logger);

        ~ErrorDetector();

        /**
         * @brief Initialize detector
         */
        Result<void> initialize();

        /**
         * @brief Hook handler
         */
        void onCodeExecution(const CodeHookEvent &event) override;

        /**
         * @brief Check if error was detected
         */
        bool hasError() const { return error_detected_; }

        /**
         * @brief Get error type
         */
        SimulationError getError() const { return error_type_; }

        /**
         * @brief Get error message
         */
        const std::string &getErrorMessage() const { return error_message_; }

    private:
        uc_engine *uc_;
        BinaryInfo binary_info_;
        LoggerPtr logger_;

        csh capstone_handle_;

        bool error_detected_;
        SimulationError error_type_;
        std::string error_message_;

        // Detection methods
        void detectDivisionByZero(Address address, const uint8_t *code, size_t size);
        void detectNullPointerCall(Address address);
        
        // Helper to map registers
        int mapCapstoneRegToUnicorn(arm_reg reg) const;
    };

} // namespace Simulator