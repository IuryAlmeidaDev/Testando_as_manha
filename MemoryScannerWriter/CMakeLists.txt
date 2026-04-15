cmake_minimum_required(VERSION 3.15)
project(MemoryScannerWriter LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(wxWidgets REQUIRED COMPONENTS core base adv ui)
include(${wxWidgets_USE_FILE})

add_executable(MemoryScannerWriter
    src/main.cpp
    src/gui/MainFrame.cpp
    src/engine/ProcessManager.cpp
    src/engine/MemoryEngine.cpp
    src/engine/WindowsAPI.cpp
    src/engine/AdvancedTools.cpp
    src/models/ScanResult.cpp
)

target_link_libraries(MemoryScannerWriter PRIVATE ${wxWidgets_LIBRARIES})
target_include_directories(MemoryScannerWriter PRIVATE src)
