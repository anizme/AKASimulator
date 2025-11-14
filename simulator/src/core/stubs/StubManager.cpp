#include "StubManager.hpp"
#include "io/utils/FileUtils.hpp"
#include "io/utils/StringUtils.hpp"
#include "io/logging/ILogger.hpp"
#include <elfio/elfio.hpp>
#include <fstream>
#include <sstream>

namespace Simulator
{

    StubManager::StubManager(uc_engine *uc, LoggerPtr logger)
        : uc_(uc), logger_(logger)
    {
    }

    Result<void> StubManager::loadStubFile(const std::string &stub_file)
    {
        LOG_INFO_F(logger_) << "Loading stub file: " << stub_file;

        if (!Utils::fileExists(stub_file))
        {
            return Result<void>::Error("Stub file not found: " + stub_file);
        }

        std::ifstream file(stub_file);
        if (!file.is_open())
        {
            return Result<void>::Error("Failed to open stub file: " + stub_file);
        }

        std::string line;
        int line_num = 0;
        while (std::getline(file, line))
        {
            line_num++;
            line = Utils::trim(line);

            // Skip empty lines and comments
            if (line.empty() || line[0] == '#')
            {
                continue;
            }

            FunctionStub stub;
            stub.function_name = line;
            stubs_.push_back(stub);

            LOG_DEBUG_F(logger_) << "  Stub: " << line;
        }

        LOG_INFO_F(logger_) << "Loaded " << stubs_.size() << " stubs";

        return Result<void>::Success();
    }

    Result<void> StubManager::resolveAddresses(const std::string &elf_path)
    {
        LOG_INFO(logger_, "Resolving stub addresses...");

        int resolved = 0;

        for (auto &stub : stubs_)
        {
            // Find original function address
            if (!findFunctionAddress(elf_path, stub.function_name,
                                     stub.function_address))
            {
                LOG_WARNING_F(logger_) << "Function not found: " << stub.function_name;
                continue;
            }

            // Find stub function (prefixed with AKA_stub_)
            std::string stub_func_name = "AKA_stub_" + stub.function_name;
            if (!findFunctionAddress(elf_path, stub_func_name,
                                     stub.stub_address))
            {
                LOG_WARNING_F(logger_) << "Stub function not found: " << stub_func_name;
                continue;
            }

            // Register in map
            address_to_stub_[stub.function_address] = &stub;
            resolved++;

            LOG_DEBUG_F(logger_) << "  " << stub.function_name
                                 << ": " << Utils::formatHex(stub.function_address)
                                 << " -> " << Utils::formatHex(stub.stub_address);
        }

        LOG_INFO_F(logger_) << "Resolved " << resolved << "/" << stubs_.size() << " stubs";

        if (resolved == 0)
        {
            return Result<void>::Error("No stubs resolved");
        }

        return Result<void>::Success();
    }

    void StubManager::onCodeExecution(const CodeHookEvent &event)
    {
        // Check if this address is a stubbed function
        auto it = address_to_stub_.find(event.address);
        if (it != address_to_stub_.end())
        {
            FunctionStub *stub = it->second;

            LOG_DEBUG_F(logger_) << "Redirecting " << stub->function_name
                                 << " to stub at " << Utils::formatHex(stub->stub_address);

            // Redirect PC to stub function (with Thumb bit set)
            if (isa == ISA::Thumb || isa == ISA::Thumb2)
            {
                stub->stub_address |= 1; // Set Thumb bit
            }
            uint32_t stub_pc = stub->stub_address;
            uc_reg_write(uc_, UC_ARM_REG_PC, &stub_pc);
        }
    }

    bool StubManager::findFunctionAddress(const std::string &elf_path,
                                          const std::string &func_name,
                                          Address &address)
    {
        ELFIO::elfio reader;
        if (!reader.load(elf_path))
        {
            return false;
        }

        // Find symbol table
        ELFIO::section *symtab = nullptr;
        for (int i = 0; i < reader.sections.size(); ++i)
        {
            auto sec = reader.sections[i];
            if (sec->get_type() == ELFIO::SHT_SYMTAB)
            {
                symtab = sec;
                break;
            }
        }

        if (!symtab)
        {
            return false;
        }

        ELFIO::symbol_section_accessor symbols(reader, symtab);

        for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j)
        {
            std::string name;
            ELFIO::Elf64_Addr value;
            ELFIO::Elf_Xword size;
            unsigned char bind, type, other;
            ELFIO::Elf_Half section_index;

            symbols.get_symbol(j, name, value, size, bind, type, section_index, other);

            if (name == func_name &&
                type == ELFIO::STT_FUNC &&
                section_index != ELFIO::SHN_UNDEF)
            {
                if (isa == ISA::Thumb || isa == ISA::Thumb2)
                {
                    // Clear Thumb bit
                    address = static_cast<Address>(value & ~1U);
                }

                return true;
            }
        }

        return false;
    }

} // namespace Simulator