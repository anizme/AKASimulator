#pragma once

#include <vector>
#include <unordered_map>
#include <string>
#include <unicorn/unicorn.h>


namespace STM32F103C8T6
{
    struct FunctionInfo
    {
        std::string signature;
        uint32_t address;
        uint32_t stub_address;
    };

    class StubManager
    {
    public:
        explicit StubManager();
        ~StubManager();

        static const std::string STUB_FUNCTION_PREFIX;

        bool initialize(std::string &stub_file);
        bool setUpAddresses(const std::string &elf_path);
        FunctionInfo* getFunctionInfoByAddress(uint32_t address);
        void redirectCall(uc_engine *engine, FunctionInfo* funcInfo);

    private:
        std::vector<FunctionInfo> called_functions_ {};
    };
    
} // namespace STM32F103C8T6