#include "StubManager.hpp"
#include "Utils.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

namespace STM32F103C8T6
{

    StubManager::StubManager() 
    {
    }

    StubManager::~StubManager()
    {
    }

    const std::string StubManager::STUB_FUNCTION_PREFIX = "AKA_stub_";

    bool StubManager::initialize(std::string &stub_file)
    {
        std::cout << "[Initialize] Stub Manager..." << std::endl;

        std::ifstream file(stub_file);
        if (!file.is_open()) {
            std::cerr << "Failed to open " << stub_file << "\n";
            return false;
        }

        std::string function_signature;
        while (file >> function_signature) {
            FunctionInfo func {function_signature, 0, 0};
            called_functions_.push_back(func);
        }

        std::cout << "Stub Manager initialized successfully\n";

        file.close();
        return true;
    }

    bool StubManager::setUpAddresses(const std::string &elf_path)
    {
        std::cout << "[Setup] Stub addresses..." << std::endl;

        for (FunctionInfo &func_info : called_functions_)
        {
            uint32_t addr = 0;
            if (!Utils::findFunctionAddress(elf_path, func_info.signature, addr))
            {
                std::cerr << "Failed to find address of " << func_info.signature << std::endl;
                return false;
            }
            func_info.address = addr;
            
            uint32_t stub_addr = 0;
            std::string stub_func_signature = StubManager::STUB_FUNCTION_PREFIX + func_info.signature;
            if (!Utils::findFunctionAddress(elf_path, stub_func_signature, stub_addr))
            {
                std::cerr << "Failed to find address of stub function: " << stub_func_signature << std::endl;
                return false;
            }
            func_info.stub_address = stub_addr;
        }

        return true;
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

    void StubManager::redirectCall(uc_engine* engine, FunctionInfo* funcInfo) {
        std::string stub_func_signature = StubManager::STUB_FUNCTION_PREFIX + funcInfo->signature;
        if (funcInfo->stub_address == 0) {
            std::cerr << "[ERROR] Stub function " 
                      << stub_func_signature
                      << " doesn't exist" 
                      << std::endl;
            return;
        }
        
        uint32_t stub_addr_thumb = funcInfo->stub_address | 1; // Set Thumb bit
        uc_err err = uc_reg_write(engine, UC_ARM_REG_PC, &stub_addr_thumb);
        if (err != UC_ERR_OK) {
            std::cerr << "[ERROR] Failed to redirect call from " 
                      << funcInfo->signature << " to " << stub_func_signature
                      << uc_strerror(err) << std::endl;
            return;
        }

        std::cout << "[HOOK] Redirected successfully from " 
                  << funcInfo->signature << " to " << stub_func_signature 
                  << " at 0x" << std::hex << funcInfo->stub_address 
                  << std::dec << std::endl;
    }

} // namespace STM32F103C8T6