#include "HookDispatcher.hpp"

namespace Simulator
{

    HookDispatcher::HookDispatcher(uc_engine *uc, LoggerPtr logger)
        : uc_(uc), logger_(logger), code_hook_(0), memory_hook_(0),
          hooks_installed_(false)
    {
    }

    HookDispatcher::~HookDispatcher()
    {
        removeHooks();
    }

    void HookDispatcher::registerHandler(HookHandlerPtr handler)
    {
        handlers_.push_back(handler);
        LOG_DEBUG_F(logger_) << "Registered hook handler (total: " << handlers_.size() << ")";
    }

    Result<void> HookDispatcher::setupHooks()
    {
        LOG_INFO(logger_, "Setting up hooks...");

        // Setup code hook (trace all instructions)
        uc_err err = uc_hook_add(uc_, &code_hook_, UC_HOOK_CODE,
                                 (void *)codeHookCallback, this, 1, 0);
        if (err != UC_ERR_OK)
        {
            std::string error_msg = "Failed to add code hook: " + std::string(uc_strerror(err));
            LOG_ERROR(logger_, error_msg);
            return Result<void>::Error(error_msg);
        }

        LOG_DEBUG(logger_, "  ✓ Code hook installed");

        // Setup memory hook (for invalid access detection)
        err = uc_hook_add(uc_, &memory_hook_,
                         UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
                         (void*)memoryHookCallback, this, 1, 0);
        if (err != UC_ERR_OK) {
            std::string error_msg = "Failed to add memory hook: " + std::string(uc_strerror(err));
            LOG_ERROR(logger_, error_msg);
            return Result<void>::Error(error_msg);
        }

        LOG_DEBUG(logger_, "  ✓ Memory hook installed");

        hooks_installed_ = true;
        LOG_INFO(logger_, "Hooks setup complete");

        return Result<void>::Success();
    }

    void HookDispatcher::removeHooks()
    {
        if (hooks_installed_)
        {
            if (code_hook_)
            {
                uc_hook_del(uc_, code_hook_);
                code_hook_ = 0;
            }
            if (memory_hook_)
            {
                uc_hook_del(uc_, memory_hook_);
                memory_hook_ = 0;
            }
            hooks_installed_ = false;
            LOG_DEBUG(logger_, "Hooks removed");
        }
    }

    void HookDispatcher::codeHookCallback(uc_engine *uc, uint64_t address,
                                          uint32_t size, void *user_data)
    {
        HookDispatcher *dispatcher = static_cast<HookDispatcher *>(user_data);

        // Read instruction bytes
        CodeHookEvent event;
        event.address = address;
        event.size = size;
        event.instruction_bytes.resize(size);

        uc_err err = uc_mem_read(uc, address, event.instruction_bytes.data(), size);
        if (err != UC_ERR_OK)
        {
            // Failed to read instruction - skip
            return;
        }

        dispatcher->dispatchCodeHook(event);
    }

    bool HookDispatcher::memoryHookCallback(uc_engine *uc, uc_mem_type type,
                                            uint64_t address, int size,
                                            int64_t value, void *user_data)
    {
        HookDispatcher *dispatcher = static_cast<HookDispatcher *>(user_data);

        MemoryHookEvent event;
        event.address = address;
        event.size = size;
        event.is_write = (type == UC_MEM_WRITE || type == UC_MEM_WRITE_UNMAPPED);
        event.value = value;

        dispatcher->dispatchMemoryHook(event);

        return false; // Don't continue execution on invalid memory access
    }

    void HookDispatcher::dispatchCodeHook(const CodeHookEvent &event)
    {
        for (auto &handler : handlers_)
        {
            handler->onCodeExecution(event);
        }
    }

    void HookDispatcher::dispatchMemoryHook(const MemoryHookEvent &event)
    {
        for (auto &handler : handlers_)
        {
            handler->onMemoryAccess(event);
        }
    }

} // namespace Simulator