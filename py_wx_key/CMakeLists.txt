cmake_minimum_required(VERSION 3.12)
project(wx_key_python)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Python COMPONENTS Interpreter Development REQUIRED)
find_package(pybind11 CONFIG REQUIRED)

if(WIN32)
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
elseif(UNIX AND NOT APPLE)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
    set(SOURCE_FILES
        src/pybind_wrapper.cpp
        src/linux_hook_controller.cpp
        src/linux_scanner.cpp
        src/linux_hooker.cpp
    )
else()
    message(FATAL_ERROR "wx_key 暂不支持该平台")
endif()

pybind11_add_module(wx_key ${SOURCE_FILES})

if(WIN32)
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
elseif(UNIX AND NOT APPLE)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    target_link_libraries(wx_key PRIVATE Threads::Threads)
endif()

# 假目标 + 真 ptrace 的单元测试（不依赖微信，验证 TRACEME 全链路）
option(WXK_BUILD_TESTS "Build the fake-target hook tests" OFF)
if(WXK_BUILD_TESTS AND UNIX AND NOT APPLE)
    add_executable(fake_wechat ${CMAKE_CURRENT_SOURCE_DIR}/../tests/fake_wechat.cpp)
    # fake_wechat 在子线程里调用 sink（复现真实微信的 worker 线程路径），需要 pthread
    target_link_libraries(fake_wechat PRIVATE Threads::Threads)
    add_executable(test_hooker
        ${CMAKE_CURRENT_SOURCE_DIR}/../tests/test_hooker.cpp
        src/linux_hooker.cpp
    )
    target_include_directories(test_hooker PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(test_hooker PRIVATE Threads::Threads)
    add_executable(test_scanner
        ${CMAKE_CURRENT_SOURCE_DIR}/../tests/test_scanner.cpp
        src/linux_scanner.cpp
    )
    target_include_directories(test_scanner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    # 便捷回归：sink 的 VA 必须现取——每次 rebuild 符号地址都会变，写死必踩坑。
    #   ctest --test-dir build/linux -R fake_target_hook --output-on-failure
    enable_testing()
    find_program(NM_EXECUTABLE nm)
    if(NM_EXECUTABLE)
        add_test(NAME fake_target_hook
            COMMAND bash -c
            "${NM_EXECUTABLE} $<TARGET_FILE:fake_wechat> | awk '/ T sink_write_config/{print \$1}' | xargs -I{} $<TARGET_FILE:test_hooker> $<TARGET_FILE:fake_wechat> {}")
    endif()

    # ptrace 线程亲和性回归：守住"fork 与全部 ptrace 必须同线程"这条前提
    add_executable(test_tracer_thread ${CMAKE_CURRENT_SOURCE_DIR}/../tests/test_tracer_thread.cpp)
    target_link_libraries(test_tracer_thread PRIVATE Threads::Threads)
    add_test(NAME tracer_thread_affinity COMMAND test_tracer_thread)
endif()