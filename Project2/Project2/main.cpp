#include <iostream>
#include <windows.h>
#include <sysinfoapi.h>
#include <pdh.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <filesystem>
#include <locale>


typedef LONG NTSTATUS;
typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "wbemuuid.lib")


void SetConsoleToUTF8() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    std::locale::global(std::locale(""));
    std::wcout.imbue(std::locale(""));
    std::wcin.imbue(std::locale(""));
}

void printWindowsVersion() {
    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (hMod) {
        RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
        if (RtlGetVersion) {
            RTL_OSVERSIONINFOW osInfo = { 0 };
            osInfo.dwOSVersionInfoSize = sizeof(osInfo);
            if (RtlGetVersion(&osInfo) == 0) { // STATUS_SUCCESS
                std::wcout << L"\n=== Операционная система ===" << std::endl;
                std::wcout << L"Версия ОС: Windows "
                    << osInfo.dwMajorVersion << L"."
                    << osInfo.dwMinorVersion << L" (Build "
                    << osInfo.dwBuildNumber << L")" << std::endl;
            }
        }
    }
}


void printMemoryInfo() {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(memInfo);
    GlobalMemoryStatusEx(&memInfo);

    std::wcout << L"\n=== Оперативная память ===" << std::endl;
    std::wcout << L"Всего ОЗУ: " << memInfo.ullTotalPhys / (1024 * 1024) << L" МБ" << std::endl;
    std::wcout << L"Доступно ОЗУ: " << memInfo.ullAvailPhys / (1024 * 1024) << L" МБ" << std::endl;
}


void printCPUInfo() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    std::wcout << L"\n=== Процессор ===" << std::endl;
    std::wcout << L"Количество ядер: " << sysInfo.dwNumberOfProcessors << std::endl;
    std::wcout << L"Архитектура: ";
    switch (sysInfo.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        std::wcout << L"x64 (AMD/Intel)" << std::endl;
        break;
    case PROCESSOR_ARCHITECTURE_INTEL:
        std::wcout << L"x86 (32-bit)" << std::endl;
        break;
    case PROCESSOR_ARCHITECTURE_ARM:
        std::wcout << L"ARM" << std::endl;
        break;
    default:
        std::wcout << L"Неизвестно" << std::endl;
    }
}


void printDiskInfo() {
    std::wcout << L"\n=== Диски ===" << std::endl;
    for (char drive = 'A'; drive <= 'Z'; drive++) {
        std::string rootPath = std::string(1, drive) + ":\\";
        DWORD sectorsPerCluster, bytesPerSector, freeClusters, totalClusters;

        if (GetDiskFreeSpaceA(rootPath.c_str(), &sectorsPerCluster, &bytesPerSector, &freeClusters, &totalClusters)) {
            ULONGLONG totalSpace = (ULONGLONG)totalClusters * sectorsPerCluster * bytesPerSector;
            ULONGLONG freeSpace = (ULONGLONG)freeClusters * sectorsPerCluster * bytesPerSector;

            std::wcout << L"Диск " << (wchar_t)drive << L": "
                << freeSpace / (1024 * 1024 * 1024) << L" ГБ свободно из "
                << totalSpace / (1024 * 1024 * 1024) << L" ГБ" << std::endl;
        }
    }
}


void printGPUInfo() {
    std::wcout << L"\n=== Видеокарта ===" << std::endl;

    // Инициализация COM
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::wcerr << L"Ошибка инициализации COM" << std::endl;
        return;
    }

    
    IWbemLocator* pLoc = nullptr;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        std::wcerr << L"Не удалось создать WbemLocator" << std::endl;
        CoUninitialize();
        return;
    }

   
    IWbemServices* pSvc = nullptr;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        std::wcerr << L"Не удалось подключиться к WMI" << std::endl;
        pLoc->Release();
        CoUninitialize();
        return;
    }

    
    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE);
    if (FAILED(hres)) {
        std::wcerr << L"Не удалось установить уровень безопасности" << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    
    IEnumWbemClassObject* pEnumerator = nullptr;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_VideoController"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hres)) {
        std::wcerr << L"Ошибка запроса WMI" << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    
    IWbemClassObject* pclsObj = nullptr;
    ULONG uReturn = 0;
    while (pEnumerator) {
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (uReturn == 0) break;

        VARIANT vtProp;
        hres = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hres)) {
            std::wcout << L"Видеокарта: " << vtProp.bstrVal << std::endl;
            VariantClear(&vtProp);
        }
        pclsObj->Release();
    }

    
    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();
}


int main() {
    SetConsoleToUTF8();
    std::wcout << L"=== Информация о системе by MrDeplix ===" << std::endl;
    printWindowsVersion();
    printCPUInfo();
    printMemoryInfo();
    printDiskInfo();
    printGPUInfo();
    system("pause");
    return 0;
}