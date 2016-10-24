// ReflectiveInject.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<Windows.h>
#include<stdlib.h>
#include"DllLoader.h"
#include<iostream>
using namespace std;

int main()
{
#ifdef  _WIN64
	char * DllFilePath = "E://ReflectDll64.dll";
#else
	char * DllFilePath = "E://ReflectDll.dll";
#endif
	
	DWORD dwProcessId = 0;
	HANDLE ProcessHandle = NULL;
	HANDLE hModule = NULL;
	HANDLE hFile = NULL;
	DWORD dwLength = 0;
	DWORD dwBytesRead = 0;
	LPVOID lpBuffer = NULL;
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES priv = { 0 };

	do 
	{
		//dwProcessId = GetCurrentProcessId();

		cout << "Please Input Process ID" << endl;
		cin >> dwProcessId;

		hFile = CreateFileA(DllFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			printf("Open File Failed!\r\n");
			return 0;
		}

		dwLength = GetFileSize(hFile, NULL);
		if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
		{
			printf("Get FileSize Failed\r\n");
			return 0;
		}

		lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
		if (!lpBuffer)
		{
			printf("Alloc Buffer Failed!\r\n");
		}

		if (ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE)
		{
			printf("Failed to alloc a buffer!");
		}

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		{
			priv.PrivilegeCount = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			{
				AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
			}
			CloseHandle(hToken);
		}

		ProcessHandle = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|
			PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
		if (!ProcessHandle)
		{
			printf("Open Target Process Failed\r\n");
			return 0;
		}
		//自己实现
		hModule = LoadRemoteLibraryR(ProcessHandle, lpBuffer, dwLength, NULL);
		if (!hModule)
		{
			printf("Failed to inject the DLL");
			break;
		}

		printf("Injected the '%s' DLL into process %d.\r\n", DllFilePath, dwProcessId);
		WaitForSingleObject(hModule, -1);
	} while (0);

	if (lpBuffer)
		HeapFree(GetProcessHeap(), 0, lpBuffer);
	if (ProcessHandle)
		CloseHandle(ProcessHandle);

    return 0;
}

