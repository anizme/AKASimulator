// include/simulator.hpp

#pragma once
#include <unicorn/unicorn.h>
#include <functional>
#include <memory>

class Simulator
{
public:
    using HookCallback = std::function<void(uc_engine *uc, uint64_t addr,
                                            int size, int64_t value)>;

    Simulator(uint32_t flash_base, uint32_t flash_size, uint32_t ram_base, uint32_t ram_size);
    ~Simulator();

    bool load_code(uint32_t addr, const std::vector<uint8_t> &code);
    void add_mem_write_hook(uint32_t start, uint32_t end, HookCallback callback);
    void run(uint32_t pc, uint32_t timeout_ms = 0);
    uint32_t read_register(int reg_id);

private:
    uc_engine *uc_;
    std::vector<std::unique_ptr<HookCallback>> hooks_;
};