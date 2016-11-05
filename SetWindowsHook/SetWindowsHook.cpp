// SetWindowsHook.cpp : ¶¨Òå¿ØÖÆÌ¨Ó¦ÓÃ³ÌÐòµÄÈë¿Úµã¡£
//

#include "stdafx.h"
#include <Windows.h>
#include <TlHelp32.h> 
#include<iostream>
using namespace std;


BOOL GetProcessIDByProcessImageName(WCHAR* wzProcessImageName, ULONG32* ulTargetProcessID);
BOOL InjectDllBySetWindowsHook(ULONG32 ulTargetProcessID);
DWORD getThreadID(ULONG32 ulTargetProcessID);
int main()
{
	ULONG32 ulTargetProcessID = 0;

	if (GetProcessIDByProcessImageName(L"sublime_text.exe", &ulTargetProcessID) == FALSE)
	{
		return 0;
	}

	if (InjectDllBySetWindowsHook(ulTargetProcessID) == FALSE)
	{
		return 0;
	}
	return 0;
}

BOOL GetProcessIDByProcessImageName(WCHAR* wzProcessImageName, ULONG32* ulTargetProcessID)
{
	ULONG32 i = 0;
	BOOL   bOk = FALSE;
	HANDLE ToolHelpHandle = NULL;

	PROCESSENTRY32 ProcessEntry32 = { 0 };
	ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);

	ToolHelpHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (ToolHelpHandle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	bOk = Process32First(ToolHelpHandle, &ProcessEntry32);
	do
	{
		if (bOk)
		{
			if (wcsicmp(ProcessEntry32.szExeFile, wzProcessImageName) == 0)
			{
				*ulTargetProcessID = ProcessEntry32.th32ProcessID;

				CloseHandle(ToolHelpHandle);
				ToolHelpHandle = INVALID_HANDLE_VALUE;
				return TRUE;
			}
		}
		else
		{
			break;
		}

		bOk = Process32Next(ToolHelpHandle, &ProcessEntry32);

	} while (1);

	CloseHandle(ToolHelpHandle);
	ToolHelpHandle = INVALID_HANDLE_VALUE;
	return FALSE;
}

DWORD getThreadID(ULONG32 ulTargetProcessID)
{
	HANDLE Handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (Handle != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(Handle, &te))
		{
			do
			{
				//线程是否可用
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
				{
					if (te.th32OwnerProcessID == ulTargetProcessID)
					{
						HANDLE hThread = OpenThread(READ_CONTROL, FALSE, te.th32ThreadID);
						if (!hThread)
						{
							puts("Can't get thread handle");
						}
						else
						{
							return te.th32ThreadID;
						}
					}
				}
			} while (Thread32Next(Handle, &te));
		}
	}
	CloseHandle(Handle);
	return (DWORD)0;
}

BOOL InjectDllBySetWindowsHook(ULONG32 ulTargetProcessID)
{
	HANDLE  TargetProcessHandle = NULL;
	TargetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ulTargetProcessID);

	if (NULL == TargetProcessHandle)
	{
		return FALSE;
	}
	HMODULE DllModule;
#ifdef _WIN64
	DllModule = LoadLibrary(L"E:\\WindowsDll64.dll");
#else
	DllModule = LoadLibrary(L"E:\\WindowsDll.dll");
#endif


	if (DllModule == NULL)
	{
		printf("Can Not Find Dll");
		return FALSE;
	}

	HOOKPROC   Sub_1Address = NULL;
	Sub_1Address = (HOOKPROC)GetProcAddress(DllModule, "Sub_1");
	if (Sub_1Address == NULL)
	{
		printf("Sub_1 do not Exist!");
		return FALSE;
	}

	DWORD ThreadID = getThreadID(ulTargetProcessID);

	HHOOK Handle = SetWindowsHookEx(WH_KEYBOARD,
		Sub_1Address, DllModule, ThreadID);

	if (Handle == NULL)
	{
		printf("Hook Failed!");
		return FALSE;
	}
	printf("Hook Success");
	getchar();
	UnhookWindowsHookEx(Handle);
	FreeLibrary(DllModule);
	return true;
}