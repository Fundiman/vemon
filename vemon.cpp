#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>

DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return pid;
}

bool InjectDLL(DWORD pid, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                  PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                  FALSE, pid);
    if (!hProcess) return false;

    size_t pathLen = (wcslen(dllPath) + 1) * sizeof(wchar_t);

    LPVOID alloc = VirtualAllocEx(hProcess, nullptr, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!alloc) {
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, alloc, dllPath, pathLen, nullptr)) {
        VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                        (LPTHREAD_START_ROUTINE)LoadLibraryW,
                                        alloc, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        wprintf(L"Usage: vemon.exe <process.exe> <full_path_to_dll>\n");
        return 1;
    }

    const wchar_t* targetProcess = argv[1];
    const wchar_t* dllPath = argv[2];

    DWORD pid = GetProcessIdByName(targetProcess);
    if (!pid) {
        wprintf(L"Process not found: ", targetProcess, L"\n");
        return 1;
    }

    if (InjectDLL(pid, dllPath)) {
        wprintf(L"Successfully injected DLL!\n");
    } else {
        wprintf(L"Failed to inject DLL.\n");
        return 1;
    }

    return 0;
}
