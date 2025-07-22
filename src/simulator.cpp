// src/simulator.cpp

#include "simulator.hpp"
#include <stdexcept>

Simulator::Simulator(uint32_t flash_base, uint32_t flash_size,
                     uint32_t ram_base, uint32_t ram_size)
{
    uc_err err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc_);
    if (err != UC_ERR_OK)
    {
        throw std::runtime_error("Failed to init Unicorn");
    }

    uc_mem_map(uc_, flash_base, flash_size, UC_PROT_ALL);
    uc_mem_map(uc_, ram_base, ram_size, UC_PROT_ALL);
}

Simulator::~Simulator()
{
    uc_close(uc_);
}

bool Simulator::load_code(uint32_t addr, const std::vector<uint8_t> &code)
{
    return uc_mem_write(uc_, addr, code.data(), code.size()) == UC_ERR_OK;
}

static void mem_write_hook_callback(uc_engine *uc, uc_mem_type type,
                                   uint64_t addr, int size,
                                   int64_t value, void *user_data)
{
    auto &cb = *static_cast<Simulator::HookCallback *>(user_data);
    cb(uc, addr, size, value);
}

void Simulator::add_mem_write_hook(uint32_t start, uint32_t end,
                                 HookCallback callback)
{
    auto cb = std::make_unique<HookCallback>(callback);
    uc_hook hook;
    
    uc_hook_add(uc_, &hook, UC_HOOK_MEM_WRITE, 
               reinterpret_cast<void*>(mem_write_hook_callback), 
               cb.get(), start, end);
    
    hooks_.push_back(std::move(cb));
}

void Simulator::run(uint32_t pc, uint32_t timeout_ms)
{
    uc_emu_start(uc_, pc, 0, 0, timeout_ms * 1000);
}

uint32_t Simulator::read_register(int reg_id)
{
    uint32_t value;
    uc_reg_read(uc_, reg_id, &value);
    return value;
}