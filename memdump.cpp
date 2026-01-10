#include <windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <string>
#include <vector>

BOOL DumpProcessMemory(DWORD pid, const std::wstring& dumpFile) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = 0;

    // Open binary file using FILE* to support wstring filenames
    FILE* dump = _wfopen(dumpFile.c_str(), L"wb");
    if (!dump) {
        CloseHandle(hProcess);
        return FALSE;
    }

    while (addr < si.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
            if ((mbi.State == MEM_COMMIT) && (mbi.Protect != PAGE_NOACCESS)) {
                std::vector<BYTE> buffer(mbi.RegionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, addr, buffer.data(), mbi.RegionSize, &bytesRead)) {
                    fwrite(buffer.data(), 1, bytesRead, dump);
                }
            }
            addr += mbi.RegionSize;
        } else {
            addr += 0x1000;
        }
    }

    fclose(dump);
    CloseHandle(hProcess);
    return TRUE;
}

void DumpCurrentProcess() {
    WCHAR tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    WCHAR exeName[MAX_PATH];
    GetModuleFileNameW(NULL, exeName, MAX_PATH);
    std::wstring exeBaseName = std::wstring(wcsrchr(exeName, L'\\') ? wcsrchr(exeName, L'\\') + 1 : exeName);
    std::wstring dumpFile = std::wstring(tempPath) + exeBaseName + L".dmp";

    DumpProcessMemory(GetCurrentProcessId(), dumpFile);
}

void DumpChildProcesses() {
    DWORD currentPid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ParentProcessID == currentPid) {
                WCHAR tempPath[MAX_PATH];
                GetTempPathW(MAX_PATH, tempPath);

                std::wstring dumpFile = std::wstring(tempPath) + pe.szExeFile + L".dmp";
                DumpProcessMemory(pe.th32ProcessID, dumpFile);
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
}

void AutoDump() {
    DumpCurrentProcess();
    DumpChildProcesses();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        AutoDump();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
