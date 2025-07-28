// src/simulator.cpp

#include "simulator.hpp"
#include <stdexcept>
#include <iostream>

Simulator::Simulator(uint32_t flash_base, uint32_t flash_size,
                     uint32_t ram_base, uint32_t ram_size) : uc_(nullptr)
{
    uc_err err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc_);
    if (err != UC_ERR_OK)
    {
        throw std::runtime_error("Failed to init Unicorn: " + std::string(uc_strerror(err)));
    }

    // Map memory regions
    if (uc_mem_map(uc_, flash_base, flash_size, UC_PROT_ALL) != UC_ERR_OK ||
        uc_mem_map(uc_, ram_base, ram_size, UC_PROT_ALL) != UC_ERR_OK)
    {
        uc_close(uc_);
        throw std::runtime_error("Failed to map memory regions");
    }
}

Simulator::~Simulator()
{
    // Unicorn will automatically remove all hooks when closed
    uc_close(uc_);
}

bool Simulator::load_code(uint32_t addr, const std::vector<uint8_t>& code)
{
    return uc_mem_write(uc_, addr, code.data(), code.size()) == UC_ERR_OK;
}

// Static callback proxies
void Simulator::mem_write_proxy(uc_engine* uc, uc_mem_type type,
                               uint64_t addr, int size,
                               int64_t value, void* user_data)
{
    auto cb = static_cast<MemWriteCallback*>(user_data);
    (*cb)(uc, addr, size, value);
}

void Simulator::mem_read_proxy(uc_engine* uc, uc_mem_type type,
                             uint64_t addr, int size,
                             int64_t value, void* user_data)
{
    auto cb = static_cast<MemReadCallback*>(user_data);
    (*cb)(uc, addr, size);
}

void Simulator::code_exec_proxy(uc_engine* uc, uint64_t addr,
                              uint32_t size, void* user_data)
{
    auto cb = static_cast<CodeExecutionCallback*>(user_data);
    (*cb)(uc, addr, size);
}

void Simulator::interrupt_proxy(uc_engine* uc, uint32_t intno, void* user_data)
{
    auto cb = static_cast<InterruptCallback*>(user_data);
    (*cb)(uc, intno);
}

// Hook management
void Simulator::add_mem_write_hook(uint32_t start, uint32_t end, MemWriteCallback callback)
{
    auto cb_ptr = new MemWriteCallback(std::move(callback));
    uc_hook hook;
    
    uc_err err = uc_hook_add(uc_, &hook, UC_HOOK_MEM_WRITE,
                           reinterpret_cast<void*>(mem_write_proxy),
                           cb_ptr, start, end);
    
    if (err != UC_ERR_OK) {
        delete cb_ptr;
        throw std::runtime_error("Failed to add memory write hook: " + std::string(uc_strerror(err)));
    }
    
    hooks_.push_back({hook, {cb_ptr, [](void* p) { delete static_cast<MemWriteCallback*>(p); }}});
}

void Simulator::add_mem_read_hook(uint32_t start, uint32_t end, MemReadCallback callback)
{
    auto cb_ptr = new MemReadCallback(std::move(callback));
    uc_hook hook;
    
    uc_err err = uc_hook_add(uc_, &hook, UC_HOOK_MEM_READ,
                           reinterpret_cast<void*>(mem_read_proxy),
                           cb_ptr, start, end);
    
    if (err != UC_ERR_OK) {
        delete cb_ptr;
        throw std::runtime_error("Failed to add memory read hook: " + std::string(uc_strerror(err)));
    }
    
    hooks_.push_back({hook, {cb_ptr, [](void* p) { delete static_cast<MemReadCallback*>(p); }}});
}

void Simulator::add_code_execution_hook(uint32_t start, uint32_t end, CodeExecutionCallback callback)
{
    auto cb_ptr = new CodeExecutionCallback(std::move(callback));
    uc_hook hook;
    
    uc_err err = uc_hook_add(uc_, &hook, UC_HOOK_CODE,
                           reinterpret_cast<void*>(code_exec_proxy),
                           cb_ptr, start, end);
    
    if (err != UC_ERR_OK) {
        delete cb_ptr;
        throw std::runtime_error("Failed to add code execution hook: " + std::string(uc_strerror(err)));
    }
    
    hooks_.push_back({hook, {cb_ptr, [](void* p) { delete static_cast<CodeExecutionCallback*>(p); }}});
}

void Simulator::add_interrupt_hook(InterruptCallback callback)
{
    auto cb_ptr = new InterruptCallback(std::move(callback));
    uc_hook hook;
    // UC_HOOK_INTR does not have a range, so we use 1 and 0 for begin and end
    uc_err err = uc_hook_add(uc_, &hook, UC_HOOK_INTR,
                           reinterpret_cast<void*>(interrupt_proxy),
                           cb_ptr,
                           1,
                           0);
    if (err != UC_ERR_OK) {
        delete cb_ptr;
        throw std::runtime_error("Failed to add interrupt hook: " + std::string(uc_strerror(err)));
    }
    
    hooks_.push_back({hook, {cb_ptr, [](void* p) { delete static_cast<InterruptCallback*>(p); }}});
}

// Execution control
void Simulator::run(uint32_t pc, uint32_t timeout_ms)
{
    uc_err err = uc_emu_start(uc_, pc, 0, 0, timeout_ms * 1000);
    if (err && err != UC_ERR_OK) {
        throw std::runtime_error("Emulation failed: " + std::string(uc_strerror(err)));
    }
}

void Simulator::stop()
{
    uc_emu_stop(uc_);
}

// Register access
uint32_t Simulator::read_register(int reg_id)
{
    uint32_t value;
    uc_err err = uc_reg_read(uc_, reg_id, &value);
    if (err != UC_ERR_OK) {
        throw std::runtime_error("Failed to read register: " + std::string(uc_strerror(err)));
    }
    return value;
}

void Simulator::write_register(int reg_id, uint32_t value)
{
    uc_err err = uc_reg_write(uc_, reg_id, &value);
    if (err != UC_ERR_OK) {
        throw std::runtime_error("Failed to write register: " + std::string(uc_strerror(err)));
    }
}