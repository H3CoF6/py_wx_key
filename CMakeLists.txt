cmake_minimum_required(VERSION 3.12)
project(wx_key_python)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Python COMPONENTS Interpreter Development REQUIRED)
find_package(pybind11 CONFIG REQUIRED)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/MinHook_134_lib/include
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/xbyak
)

set(SOURCE_FILES
    src/hook_controller.cpp
    src/ipc_manager.cpp
    src/remote_hooker.cpp
    src/remote_scanner.cpp
    src/remote_veh.cpp
    src/shellcode_builder.cpp
    src/syscalls.cpp
    src/veh_hook_manager.cpp
    src/pybind_wrapper.cpp
)

pybind11_add_module(wx_key ${SOURCE_FILES})

target_compile_options(wx_key PRIVATE /utf-8)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(MINHOOK_LIB ${CMAKE_CURRENT_SOURCE_DIR}/vendor/MinHook_134_lib/lib/libMinHook.x64.lib)
else()
    set(MINHOOK_LIB ${CMAKE_CURRENT_SOURCE_DIR}/vendor/MinHook_134_lib/lib/libMinHook.x86.lib)
endif()

target_link_libraries(wx_key PRIVATE 
    ${MINHOOK_LIB}
    Psapi
    version
)

target_compile_definitions(wx_key PRIVATE HOOK_EXPORTS)

