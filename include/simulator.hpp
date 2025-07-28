// include/simulator.hpp

#pragma once
#include <unicorn/unicorn.h>
#include <functional>
#include <memory>
#include <vector>
#include <unordered_map>

class Simulator
{
public:
    // Hook callback types
    using MemWriteCallback = std::function<void(uc_engine* uc, uint64_t addr, int size, int64_t value)>;
    using MemReadCallback = std::function<void(uc_engine* uc, uint64_t addr, int size)>;
    using CodeExecutionCallback = std::function<void(uc_engine* uc, uint64_t addr, int size)>;
    using InterruptCallback = std::function<void(uc_engine* uc, uint32_t intno)>;

    Simulator(uint32_t flash_base, uint32_t flash_size,
              uint32_t ram_base, uint32_t ram_size);

    ~Simulator();

    bool load_code(uint32_t addr, const std::vector<uint8_t>& code);
    
    // Memory hooks
    void add_mem_write_hook(uint32_t start, uint32_t end, MemWriteCallback callback);
    void add_mem_read_hook(uint32_t start, uint32_t end, MemReadCallback callback);
    
    // Code execution hooks
    void add_code_execution_hook(uint32_t start, uint32_t end, CodeExecutionCallback callback);
    
    // Interrupt hooks
    void add_interrupt_hook(InterruptCallback callback);
    
    // Register access
    uint32_t read_register(int reg_id);
    void write_register(int reg_id, uint32_t value);
    
    // Execution control
    void run(uint32_t pc, uint32_t timeout_ms = 0);
    void stop();

private:
    uc_engine* uc_;
    
    // Store all hook resources
    struct HookResource {
        uc_hook hook;
        std::unique_ptr<void, void(*)(void*)> callback;
    };
    
    std::vector<HookResource> hooks_;
    
    // Static callback wrappers
    static void mem_write_proxy(uc_engine* uc, uc_mem_type type,
                              uint64_t addr, int size,
                              int64_t value, void* user_data);
                              
    static void mem_read_proxy(uc_engine* uc, uc_mem_type type,
                             uint64_t addr, int size,
                             int64_t value, void* user_data);
                             
    static void code_exec_proxy(uc_engine* uc, uint64_t addr,
                              uint32_t size, void* user_data);
                              
    static void interrupt_proxy(uc_engine* uc, uint32_t intno, void* user_data);
};