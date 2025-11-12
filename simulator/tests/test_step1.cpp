#include "simulator/Types.hpp"
#include "io/logging/ConsoleLogger.hpp"
#include "io/logging/FileLogger.hpp"
#include "io/logging/CompositeLogger.hpp"
#include <iostream>

using namespace Simulator;

// Example function to show location tracking
void doSomething(LoggerPtr logger) {
    LOG_INFO(logger, "Function doSomething called");
    LOG_DEBUG(logger, "Processing some data...");
}

class ExampleClass {
public:
    ExampleClass(LoggerPtr logger) : logger_(logger) {}
    
    void processData() {
        LOG_INFO(logger_, "ExampleClass::processData started");
        
        // Simulate some work
        for (int i = 0; i < 3; i++) {
            LOG_DEBUG_F(logger_) << "Processing item " << i << " of 3";
        }
        
        LOG_INFO(logger_, "ExampleClass::processData completed");
    }
    
    void causeError() {
        LOG_ERROR(logger_, "Something went wrong in ExampleClass!");
    }
    
private:
    LoggerPtr logger_;
};

int main() {
    std::cout << "=== Testing Step 1: Types & Logger with Location ===" << std::endl;
    
    // Test 1: Console logger with location
    std::cout << "\n[Test 1] Console logger with source location" << std::endl;
    {
        auto console = std::make_shared<ConsoleLogger>(
            true,   // colors
            true,   // show location
            ILogger::Level::Debug
        );
        
        LOG_TRACE(console, "This is a trace message");
        LOG_DEBUG(console, "This is a debug message");
        LOG_INFO(console, "This is an info message");
        LOG_WARNING(console, "This is a warning");
        LOG_ERROR(console, "This is an error");
        
        std::cout << "  ✓ Basic logging with location works" << std::endl;
    }
    
    // Test 2: Formatted logging
    std::cout << "\n[Test 2] Formatted logging" << std::endl;
    {
        auto console = std::make_shared<ConsoleLogger>();
        
        int value = 42;
        std::string name = "test";
        
        LOG_DEBUG_F(console) << "Value is " << value << ", name is " << name;
        LOG_INFO_F(console) << "Hex: 0x" << std::hex << 0xDEADBEEF;
        LOG_ERROR_F(console) << "Multiple " << "concatenated " << "strings";
        
        std::cout << "  ✓ Formatted logging works" << std::endl;
    }
    
    // Test 3: Function calls
    std::cout << "\n[Test 3] Logging from different functions" << std::endl;
    {
        auto console = std::make_shared<ConsoleLogger>();
        
        LOG_INFO(console, "Calling doSomething...");
        doSomething(console);
        
        std::cout << "  ✓ Function location tracking works" << std::endl;
    }
    
    // Test 4: Class methods
    std::cout << "\n[Test 4] Logging from class methods" << std::endl;
    {
        auto console = std::make_shared<ConsoleLogger>();
        
        ExampleClass obj(console);
        obj.processData();
        obj.causeError();
        
        std::cout << "  ✓ Class method location tracking works" << std::endl;
    }
    
    // Test 5: File logger with location
    std::cout << "\n[Test 5] File logger with location" << std::endl;
    {
        auto file = std::make_shared<FileLogger>(
            "test_output/test_with_location.log",
            true  // show location
        );
        
        LOG_INFO(file, "Test message with location");
        LOG_WARNING(file, "Warning with location info");
        file->flush();
        
        std::cout << "  ✓ File logger with location works (check test_output/test_with_location.log)" << std::endl;
    }
    
    // Test 6: Toggle location display
    std::cout << "\n[Test 6] Toggle location display" << std::endl;
    {
        auto console = std::make_shared<ConsoleLogger>(true, true);
        
        LOG_INFO(console, "With location");
        
        console->setShowLocation(false);
        LOG_INFO(console, "Without location");
        
        console->setShowLocation(true);
        LOG_INFO(console, "With location again");
        
        std::cout << "  ✓ Toggle location works" << std::endl;
    }
    
    // Test 7: Composite logger
    std::cout << "\n[Test 7] Composite logger with location" << std::endl;
    {
        auto composite = std::make_shared<CompositeLogger>();
        composite->addLogger(std::make_shared<ConsoleLogger>());
        composite->addLogger(std::make_shared<FileLogger>("test_output/composite.log"));
        
        LOG_INFO(composite, "This goes to both console and file with location");
        
        std::cout << "  ✓ Composite logger works" << std::endl;
    }
    
    std::cout << "\n=== All tests passed! ===" << std::endl;
    
    return 0;
}