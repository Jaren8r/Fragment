#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include "curl.h"
#include "util.h"
#include "vendor/minhook/include/MinHook.h"

static const char PROXY_URL[] = "http://127.0.0.1:9020/";
static const size_t PROXY_URL_LEN = (sizeof(PROXY_URL)/sizeof(PROXY_URL[0])) - sizeof(PROXY_URL[0]);

CURLcode CurlSetoptDetourWithInstance(CurlSetoptFn* CurlSetopt, LPVOID curl, CURLoption option, va_list param) {
    char* newUrl;

    if (option == CURLOPT_URL) {
        char** pUrl = (char **) param;
        DebugLog("[CurlSetopt] ORIG: 0x%p, CURL: 0x%p, URL: %s\n", *CurlSetopt, curl, *pUrl);

        newUrl = malloc(PROXY_URL_LEN + strlen(*pUrl) + 1);
        strcpy(newUrl, PROXY_URL);
        strcpy(newUrl + PROXY_URL_LEN, *pUrl);
        *pUrl = newUrl;
    }

    CURLcode result = (*CurlSetopt)(curl, option, param);

    if (option == CURLOPT_URL) {
        free(newUrl);
    }

    return result;
}

void HookCurl(HMODULE module) {
#ifdef DEBUG
    TCHAR moduleName[MAX_PATH];
    GetModuleBaseName(GetCurrentProcess(), module, moduleName, sizeof(moduleName));
#else
    char* moduleName = 0;
#endif

    LPVOID pCurlSetoptAddress = FindPattern(module, "\x48\x89\x00\x00\x00\x48\x89\x00\x00\x00\x48\x89\x00\x00\x00\x57\x48\x83\xEC\x00\x33\xED\x49\x8B\x00\x48\x8B\x00\x81\xFA", "xx???xx???xx???xxxx?xxxx?xx?xx");
    if (!pCurlSetoptAddress) {
        return;
    }

    DebugLog("[HookCurl] Found curl in %s @ 0x%p\n", moduleName, pCurlSetoptAddress);

    LPVOID ppOriginal = malloc(sizeof(LPVOID));

    CreateAndEnableHook(moduleName, pCurlSetoptAddress, GenerateCaller(ppOriginal, &CurlSetoptDetourWithInstance), ppOriginal);
}

typedef HMODULE(*LoadLibraryAFn)(LPCSTR lpLibFileName);
LoadLibraryAFn LoadLibraryAOriginal = 0;

HMODULE LoadLibraryADetour(LPCSTR lpLibFileName) {
    HMODULE result = LoadLibraryAOriginal(lpLibFileName);

#ifdef DEBUG
    TCHAR moduleName[MAX_PATH];
    GetModuleBaseName(GetCurrentProcess(), result, moduleName, sizeof(moduleName));
    DebugLog("[LoadLibraryA] Loaded %s\n", moduleName);
#endif

    HookCurl(result);

    return result;
}

typedef HMODULE(*LoadLibraryWFn)(LPCWSTR lpLibFileName);
LoadLibraryWFn LoadLibraryWOriginal = 0;

HMODULE LoadLibraryWDetour(LPCWSTR lpLibFileName) {
    HMODULE result = LoadLibraryWOriginal(lpLibFileName);

#ifdef DEBUG
    TCHAR moduleName[MAX_PATH];
    GetModuleBaseName(GetCurrentProcess(), result, moduleName, sizeof(moduleName));
    DebugLog("[LoadLibraryW] Loaded %s\n", moduleName);
#endif

    HookCurl(result);

    return result;
}

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD reason, LPVOID lpvReserved) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;

#ifdef DEBUG
    InitConsole();
#endif

    MH_Initialize();

    HMODULE hMods[1024];
    HANDLE hProcess = GetCurrentProcess();
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            if (hMods[i] == hinstDLL) continue; // Skip current module
            HookCurl(hMods[i]);
        }
    }

    if (!CreateAndEnableHook("LoadLibraryA", &LoadLibraryA, &LoadLibraryADetour, (LPVOID *) &LoadLibraryAOriginal)) {
        return FALSE;
    }

    if (!CreateAndEnableHook("LoadLibraryW", &LoadLibraryW, &LoadLibraryWDetour, (LPVOID *) &LoadLibraryWOriginal)) {
        return FALSE;
    }

    return TRUE;
}