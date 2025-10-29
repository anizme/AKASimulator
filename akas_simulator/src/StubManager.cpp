#include "StubManager.hpp"
#include "Utils.hpp"

namespace STM32F103C8T6
{

    StubManager::StubManager() 
    {
    }

    StubManager::~StubManager()
    {
    }

    bool StubManager::initialize(std::string &stub_file)
    {
        //Todo
        return true;
    }

    void StubManager::addStubFunction(const std::string &signature, uint32_t address)
    {
        stub_function_map_[signature] = address;
    }

    FunctionInfo* StubManager::getFunctionInfoByAddress(uint32_t address)
    {
        for (FunctionInfo &func : called_functions_) {
            if (address == func.address) {
                return &func;
            }
        }

        return nullptr;
    }

    uint32_t StubManager::getStubFunctionAddress(const std::string &signature) const
    {
        auto it = stub_function_map_.find(signature);
        if (it != stub_function_map_.end())
        {
            return it->second;
        }
        return -1;
    }

    void StubManager::redirectCall(uc_engine* engine, FunctionInfo* funcInfo) {
        ++funcInfo->number_of_calls;

        std::string stub_func_signature = StubManager::STUB_FUNCTION_PREFIX 
                                            + std::to_string(funcInfo->number_of_calls) 
                                            + "_" + funcInfo->signature;

        uint32_t stub_address = getStubFunctionAddress(stub_func_signature);
        if (stub_address == -1) {
            std::cerr << "[ERROR] Stub function " << stub_func_signature << " doesn't exist" << std::endl;
            return;
        }
        
        uint32_t stub_addr_thumb = stub_address | 1; // Set Thumb bit
        uc_err err = uc_reg_write(engine, UC_ARM_REG_PC, &stub_addr_thumb);
        if (err != UC_ERR_OK) {
            std::cerr << "[ERROR] Failed to redirect call from " 
                      << funcInfo->signature << " to " << stub_func_signature
                      << uc_strerror(err) 
                      << std::endl;
            return;
        }

        std::cout << "[HOOK] Redirected successfully from " 
                  << funcInfo->signature << " to " << stub_func_signature 
                  << " at 0x" << std::hex << stub_address << std::dec << std::endl;
    }

    bool StubManager::setUpAddresses(const std::string &elf_path)
    {
        for (FunctionInfo &func_info : called_functions_)
        {
            uint32_t addr = 0;
            if (!Utils::findFunctionAddress(elf_path, func_info.signature, addr))
            {
                std::cerr << "Failed to find address of " << func_info.signature << std::endl;
                return false;
            }
            func_info.address = addr;
            
            if (!(findStubFunctionAddressByNumberOfCalls(elf_path, func_info.signature, func_info.number_of_calls)))
            {
                return false;
            }
        }

        return true;
    }

    bool StubManager::findStubFunctionAddressByNumberOfCalls(const std::string &elf_path, std::string &signature, int number_of_calls)
    {
        for (int i = 0; i < number_of_calls; ++i)
        {
            uint32_t addr = 0;
            std::string stub_func_signature = StubManager::STUB_FUNCTION_PREFIX + std::to_string(i) + "_" + signature;
            if (!Utils::findFunctionAddress(elf_path, stub_func_signature, addr))
            {
                std::cerr << "Failed to find stub function: " << stub_func_signature << std::endl;
                return false;
            }

            addStubFunction(stub_func_signature, addr);
        }
        
        return true;
    }

} // namespace STM32F103C8T6