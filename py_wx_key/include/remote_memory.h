#ifndef REMOTE_MEMORY_H
#define REMOTE_MEMORY_H

#include <Windows.h>
#include "syscalls.h"

// RAII wrapper for remote allocations using NtAllocateVirtualMemory/NtFreeVirtualMemory
class RemoteMemory {
public:
    RemoteMemory() = default;
    RemoteMemory(HANDLE process, SIZE_T size, ULONG protect) {
        allocate(process, size, protect);
    }

    RemoteMemory(const RemoteMemory&) = delete;
    RemoteMemory& operator=(const RemoteMemory&) = delete;

    RemoteMemory(RemoteMemory&& other) noexcept {
        moveFrom(std::move(other));
    }

    RemoteMemory& operator=(RemoteMemory&& other) noexcept {
        if (this != &other) {
            reset();
            moveFrom(std::move(other));
        }
        return *this;
    }

    ~RemoteMemory() {
        reset();
    }

    bool allocate_near(HANDLE process, SIZE_T size, ULONG protect, uintptr_t targetAddress) {
        reset();
        hProcess = process;
        sizeBytes = size;
        base = nullptr;

        // 定义搜索范围（正负约 2GB 内）
        uintptr_t max_dist = 0x7FFF0000ull;
        uintptr_t min_addr = (targetAddress > max_dist) ? targetAddress - max_dist : 0x10000;
        uintptr_t max_addr = targetAddress + max_dist;

        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t current = targetAddress;

        // 1. 优先向低地址方向精准扫描可用内存块
        while (current > min_addr) {
            if (VirtualQueryEx(process, (LPCVOID)current, &mbi, sizeof(mbi)) == 0) break;

            if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
                // 对齐到 64KB (Windows 内存分配粒度)
                uintptr_t alloc_addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize - size;
                alloc_addr -= alloc_addr % 0x10000;

                if (alloc_addr >= (uintptr_t)mbi.BaseAddress && alloc_addr >= min_addr) {
                    PVOID baseAlloc = (PVOID)alloc_addr;
                    SIZE_T regionSize = size;
                    if (IndirectSyscalls::NtAllocateVirtualMemory(process, &baseAlloc, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, protect) == STATUS_SUCCESS) {
                        base = baseAlloc;
                        return true;
                    }
                }
            }
            // 跳到上一个内存块
            current = (uintptr_t)mbi.BaseAddress - 1;
        }

        // 2. 如果低地址没有，向高地址方向扫描
        current = targetAddress;
        while (current < max_addr) {
            if (VirtualQueryEx(process, (LPCVOID)current, &mbi, sizeof(mbi)) == 0) break;

            if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
                uintptr_t alloc_addr = (uintptr_t)mbi.BaseAddress;
                if (alloc_addr % 0x10000 != 0) {
                    alloc_addr += 0x10000 - (alloc_addr % 0x10000);
                }

                if (alloc_addr + size <= (uintptr_t)mbi.BaseAddress + mbi.RegionSize && alloc_addr <= max_addr) {
                    PVOID baseAlloc = (PVOID)alloc_addr;
                    SIZE_T regionSize = size;
                    if (IndirectSyscalls::NtAllocateVirtualMemory(process, &baseAlloc, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, protect) == STATUS_SUCCESS) {
                        base = baseAlloc;
                        return true;
                    }
                }
            }
            // 跳到下一个内存块
            current = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        }

        // 3. 实在没有 2GB 内的空间，只能回退到远跳（几率极小）
        return allocate(process, size, protect);
    }

    void reset() {
        if (base) {
            SIZE_T regionSize = 0;
            PVOID addr = base;
            IndirectSyscalls::NtFreeVirtualMemory(hProcess, &addr, &regionSize, MEM_RELEASE);
            base = nullptr;
            sizeBytes = 0;
            hProcess = nullptr;
        }
    }

    bool protect(ULONG newProtect, ULONG* oldProtect = nullptr) {
        if (!base || sizeBytes == 0) {
            return false;
        }
        PVOID addr = base;
        SIZE_T regionSize = sizeBytes;
        ULONG oldProt = 0;
        NTSTATUS status = IndirectSyscalls::NtProtectVirtualMemory(
            hProcess,
            &addr,
            &regionSize,
            newProtect,
            &oldProt
        );
        if (oldProtect) {
            *oldProtect = oldProt;
        }
        return status == STATUS_SUCCESS;
    }

    PVOID get() const { return base; }
    SIZE_T size() const { return sizeBytes; }
    bool valid() const { return base != nullptr; }

private:
    void moveFrom(RemoteMemory&& other) {
        hProcess = other.hProcess;
        base = other.base;
        sizeBytes = other.sizeBytes;
        other.hProcess = nullptr;
        other.base = nullptr;
        other.sizeBytes = 0;
    }

    HANDLE hProcess{ nullptr };
    PVOID  base{ nullptr };
    SIZE_T sizeBytes{ 0 };
};

#endif // REMOTE_MEMORY_H
