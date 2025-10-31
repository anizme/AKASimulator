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
        int numberOfCalls = 0;
        int currentCall = 0;
    };

    class StubManager
    {
    public:
        explicit StubManager();
        ~StubManager();

        static const std::string STUB_FUNCTION_PREFIX;

        bool initialize(std::string &stub_file);
        bool setUpAddresses(const std::string &elf_path);

        void addStubFunction(const std::string &signature, uint32_t address);
        FunctionInfo* getFunctionInfoByAddress(uint32_t address);
        uint32_t getStubFunctionAddress(const std::string &signature) const;
        std::vector<FunctionInfo> &getCalledFunctions() { return called_functions_; }

        void redirectCall(uc_engine *engine, FunctionInfo* funcInfo);

    private:
        std::vector<FunctionInfo> called_functions_ {};
        std::unordered_map<std::string, uint32_t> stub_function_map_ {};
        
        bool findStubFunctionAddressByNumberOfCalls(const std::string &elf_path, std::string &signature, int numberOfCalls);
    };
    
} // namespace STM32F103C8T6