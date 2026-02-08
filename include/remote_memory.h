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

    bool allocate(HANDLE process, SIZE_T size, ULONG protect) {
        reset();
        hProcess = process;
        sizeBytes = size;
        base = nullptr;
        SIZE_T regionSize = size;
        NTSTATUS status = IndirectSyscalls::NtAllocateVirtualMemory(
            hProcess,
            &base,
            0,
            &regionSize,
            MEM_COMMIT | MEM_RESERVE,
            protect
        );
        if (status != STATUS_SUCCESS) {
            base = nullptr;
            sizeBytes = 0;
            return false;
        }
        return true;
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
