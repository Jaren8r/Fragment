#pragma once

#include <windows.h>
#include "curl.h"
#include "vendor/minhook/include/MinHook.h"

#ifdef DEBUG
#define DebugLog(...) printf(__VA_ARGS__)
#else
#define DebugLog(...)
#endif

BOOL CreateAndEnableHook(const char* name, LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal) {
    MH_STATUS createStatus = MH_CreateHook(pTarget, pDetour, ppOriginal);
    if (createStatus != MH_OK) {
        DebugLog("Failed to create %s hook - %d", name, createStatus);
        return FALSE;
    }

    MH_STATUS enableStatus = MH_EnableHook(pTarget);
    if (enableStatus != MH_OK) {
        DebugLog("Failed to enable %s hook - %d", name, enableStatus);
        return FALSE;
    }

    return TRUE;
}

inline void InitConsole() {
    AllocConsole();

    FILE* pFile;
    //freopen_s(&pFile, "CONOUT$", "w", stdout);
    freopen_s(&pFile, "D:\\Fragment.log", "w+", stdout);
}

inline BOOL MaskCompare(PVOID pBuffer, LPCSTR lpPattern, LPCSTR lpMask) {
    for (PBYTE value = pBuffer; *lpMask; ++lpPattern, ++lpMask, ++value) {
        if (*lpMask == 'x' && *((LPCBYTE) lpPattern)!= *value)
            return FALSE;
    }

    return TRUE;
}

inline LPVOID FindPattern(HMODULE hModule, LPCSTR lpPattern, LPCSTR lpMask) {
    MODULEINFO info = { 0 };

    GetModuleInformation(GetCurrentProcess(), hModule, &info, sizeof(info));

    PBYTE base = info.lpBaseOfDll;
    size_t patternLength = strlen(lpMask);
    PBYTE endOfRange = base + info.SizeOfImage - patternLength;
    PBYTE endOfMemoryRegion = 0;
    MEMORY_BASIC_INFORMATION mbi;

    for (PBYTE pAddress = base; pAddress < endOfRange; ++pAddress) {
        if (pAddress + patternLength > endOfMemoryRegion) {
            if (VirtualQuery(pAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0) {
                continue;
            }

            if (mbi.Protect != PAGE_EXECUTE_READ || (mbi.RegionSize - (pAddress - ((PBYTE) mbi.AllocationBase))) < patternLength) {
                pAddress += mbi.RegionSize;
                continue;
            }

            endOfMemoryRegion = ((PBYTE) mbi.AllocationBase) + mbi.RegionSize;
        }

        if (MaskCompare(pAddress, lpPattern, lpMask)) {
            return pAddress;
        }
    }

    return 0;
}

inline CurlSetoptFn GenerateCaller(LPVOID pFirstParam, LPVOID pCalled) {
    const byte code[] = {
            0x4C, 0x89, 0x44, 0x24, 0x18, // mov qword ptr [rsp + 0x18], r8
            0x89, 0x54, 0x24, 0x10, // mov dword ptr [rsp + 0x10], edx
            0x48, 0x89, 0x4C, 0x24, 0x08, // mov qword ptr [rsp + 8], rcx
            0x57, // push rdi
            0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
            0x4C, 0x8B, 0x4C, 0x24, 0x40, // mov r9, qword ptr [rsp + 0x40]
            0x44, 0x8B, 0x44, 0x24, 0x38, // mov r8d, dword ptr [rsp + 0x38]
            0x48, 0x8B, 0x54, 0x24, 0x30, // mov rdx, qword ptr [rsp + 0x30]
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rcx, 0x0000000000000000 [param1]
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, 0x0000000000000000 [called]
            0xFF, 0xD0, // call rax
            0x48, 0x83, 0xC4, 0x20, // add rsp, 0x20
            0x5F, // pop rdi
            0xC3 // ret
    };

    byte* allocatedCode = VirtualAlloc(NULL, sizeof(code), MEM_COMMIT, PAGE_READWRITE);
    memcpy(allocatedCode, code, sizeof(code));
    memcpy(allocatedCode+36, &pFirstParam, sizeof(pFirstParam));
    memcpy(allocatedCode+46, &pCalled, sizeof(pCalled));

    DWORD dummy;
    VirtualProtect(allocatedCode, sizeof(code), PAGE_EXECUTE_READ, &dummy);

    return (CurlSetoptFn) allocatedCode;
}