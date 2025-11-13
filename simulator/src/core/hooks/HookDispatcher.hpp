#pragma once

#include "simulator/Types.hpp"
#include "io/logging/ILogger.hpp"
#include <unicorn/unicorn.h>
#include <functional>
#include <vector>
#include <memory>

namespace Simulator
{

    /**
     * @brief Hook event types
     */
    struct CodeHookEvent
    {
        Address address;
        uint32_t size;
        std::vector<Byte> instruction_bytes;
    };

    struct MemoryHookEvent
    {
        Address address;
        uint32_t size;
        bool is_write;
        int64_t value; // For write operations
    };

    /**
     * @brief Hook handler interface
     */
    class IHookHandler
    {
    public:
        virtual ~IHookHandler() = default;

        virtual void onCodeExecution(const CodeHookEvent &event) {}
        virtual void onMemoryAccess(const MemoryHookEvent &event) {}
    };

    using HookHandlerPtr = std::shared_ptr<IHookHandler>;

    /**
     * @brief Manages Unicorn hooks and dispatches events
     *
     * Responsibilities:
     * - Register hooks with Unicorn
     * - Dispatch events to registered handlers
     * - Manage hook lifecycle
     */
    class HookDispatcher
    {
    public:
        /**
         * @brief Constructor
         * @param uc Unicorn engine instance
         * @param logger Logger
         */
        HookDispatcher(uc_engine *uc, LoggerPtr logger);
        ~HookDispatcher();

        /**
         * @brief Register a hook handler
         * @param handler Handler to register
         */
        void registerHandler(HookHandlerPtr handler);

        /**
         * @brief Setup all hooks with Unicorn
         * @return Success or error
         */
        Result<void> setupHooks();

        /**
         * @brief Remove all hooks
         */
        void removeHooks();

    private:
        uc_engine *uc_;
        LoggerPtr logger_;

        std::vector<HookHandlerPtr> handlers_;

        uc_hook code_hook_;
        uc_hook memory_hook_;

        bool hooks_installed_;

        // Static callbacks for Unicorn
        static void codeHookCallback(uc_engine *uc, uint64_t address,
                                     uint32_t size, void *user_data);

        static bool memoryHookCallback(uc_engine *uc, uc_mem_type type,
                                       uint64_t address, int size,
                                       int64_t value, void *user_data);

        // Dispatch to handlers
        void dispatchCodeHook(const CodeHookEvent &event);
        void dispatchMemoryHook(const MemoryHookEvent &event);
    };

} // namespace Simulator