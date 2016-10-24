// RemoteThread.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
using namespace std;
BOOL EnableDebugPrivilege();
BOOL  InjectDllByRemoteThread(ULONG32 ulTargetProcessID, WCHAR* wzDllFullPath);

int _tmain(int argc, _TCHAR* argv[])
{
	if (EnableDebugPrivilege() == FALSE)
	{
		return 0;
	}
	ULONG32  ulProcessID = 0;
	printf("Input ProcessID\r\n");
	cin >> ulProcessID;    		
	WCHAR  wzDllFullPath[MAX_PATH] = { 0 };
#ifdef  _WIN64		
	wcsncat_s(wzDllFullPath, L"E:\\Dll64.dll", 20);
#else												
	wcsncat_s(wzDllFullPath, L"E:\\Dll.dll", 20);
#endif
	InjectDllByRemoteThread(ulProcessID, wzDllFullPath);
	return 0;
}

BOOL  InjectDllByRemoteThread(ULONG32 ulTargetProcessID, WCHAR* wzDllFullPath)
{
	HANDLE  TargetProcessHandle = NULL;
	TargetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ulTargetProcessID);
	if (NULL == TargetProcessHandle)
	{
		printf("failed to open process!!\n");
		return FALSE;
	}
	WCHAR* VirtualAddress = NULL;
	ULONG32 ulDllLength = (ULONG32)_tcslen(wzDllFullPath) + 1;
	//ALLOC Address for Dllpath
	VirtualAddress = (WCHAR*)VirtualAllocEx(TargetProcessHandle, NULL, ulDllLength * sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE);
	if (NULL == VirtualAddress)
	{
		printf("failed to Alloc!!\n");
		CloseHandle(TargetProcessHandle);
		return FALSE;
	}
	// write
	if (FALSE == WriteProcessMemory(TargetProcessHandle, VirtualAddress, (LPVOID)wzDllFullPath, ulDllLength * sizeof(WCHAR), NULL))
	{
		printf("failed to write!!\n");
		VirtualFreeEx(TargetProcessHandle, VirtualAddress, ulDllLength, MEM_DECOMMIT);
		CloseHandle(TargetProcessHandle);
		return FALSE;
	}
	LPTHREAD_START_ROUTINE FunctionAddress = NULL;
	FunctionAddress = (PTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(_T("Kernel32")), "LoadLibraryW");
	HANDLE ThreadHandle = INVALID_HANDLE_VALUE;
	//start
	ThreadHandle = CreateRemoteThread(TargetProcessHandle, NULL, 0, FunctionAddress, VirtualAddress, 0, NULL);
	if (NULL == ThreadHandle)
	{
		VirtualFreeEx(TargetProcessHandle, VirtualAddress, ulDllLength, MEM_DECOMMIT);
		CloseHandle(TargetProcessHandle);
		return FALSE;
	}
	// WaitForSingleObject
	WaitForSingleObject(ThreadHandle, INFINITE);
	VirtualFreeEx(TargetProcessHandle, VirtualAddress, ulDllLength, MEM_DECOMMIT);			// 清理
	CloseHandle(ThreadHandle);
	CloseHandle(TargetProcessHandle);
}

BOOL EnableDebugPrivilege()
{
	HANDLE TokenHandle = NULL;
	TOKEN_PRIVILEGES TokenPrivilege;
	LUID uID;
	//打开权限令牌
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
	{
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &uID))
	{
		CloseHandle(TokenHandle);
		TokenHandle = INVALID_HANDLE_VALUE;
		return FALSE;
	}
	TokenPrivilege.PrivilegeCount = 1;
	TokenPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	TokenPrivilege.Privileges[0].Luid = uID;
	if (!AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivilege, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	//调整权限
	{
		CloseHandle(TokenHandle);
		TokenHandle = INVALID_HANDLE_VALUE;
		return  FALSE;
	}
	CloseHandle(TokenHandle);
	TokenHandle = INVALID_HANDLE_VALUE;
	return TRUE;
}