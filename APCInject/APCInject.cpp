// APCInject.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include <Windows.h>  
#include <TlHelp32.h>  
#include<iostream>
using namespace std;

#define MAX_PATH 1024
typedef long(__fastcall *pfnRtlAdjustPrivilege64)(ULONG, ULONG, ULONG, PVOID);
pfnRtlAdjustPrivilege64 RtlAdjustPrivilege;
// 用于存储注入模块DLL的路径全名
char* DllFullPath;

int InjectDllWithApc(char* DllFullPath, ULONG pid)
{
#ifdef _WIN64   // x64 OpenProcess提权操作
	RtlAdjustPrivilege = (pfnRtlAdjustPrivilege64)GetProcAddress((HMODULE)(GetModuleHandle(L"ntdll.dll")), "RtlAdjustPrivilege");
	if (RtlAdjustPrivilege == NULL)
	{
		return FALSE;
	}
	BOOLEAN dwRetVal = 0;
	RtlAdjustPrivilege(20, 1, 0, &dwRetVal);  //调整权限
#endif

	HANDLE hProcess, hThread, hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32 = { 0 };

	HMODULE hDll = GetModuleHandle(L"Kernel32.dll");
	int len = strlen(DllFullPath) + 1;
	//打开目标进程，向目标进程写入DLL		
	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, TRUE, pid);
	if (hProcess == NULL)
	{
		printf("failed to open process!!\n");
		return 0;
	}
	//在目标进程申请内存  
	PVOID pszLibFileRemote = (char *)VirtualAllocEx(hProcess, NULL, lstrlen((LPCWSTR)DllFullPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (pszLibFileRemote != NULL)
	{
		//将DLL写入在目标进程申请的空间  
		if (WriteProcessMemory(hProcess, pszLibFileRemote, (void *)DllFullPath, lstrlen((LPCWSTR)DllFullPath) + 1, NULL))
		{
			HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
			THREADENTRY32 te32;
			//创建线程快照
			hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if (hThreadSnap == INVALID_HANDLE_VALUE)
				return 1;
			te32.dwSize = sizeof(THREADENTRY32);
			if (!Thread32First(hThreadSnap, &te32))
			{
				CloseHandle(hThreadSnap);
				return 1;
			}
			do
			{
				//遍历目标进程的线程  
				if (te32.th32OwnerProcessID == pid)
				{
					printf("TID:%d\n", te32.th32ThreadID);

					hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
					if (hThread != 0)
					{//目标线程插入APC  
						if (QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (DWORD)pszLibFileRemote))
						{
							printf("插入APC成功\n");
						}
						else
						{
							printf("插入APC失败\n");
							return 1;
						}
						CloseHandle(hThread);
					}
				}
			} while (Thread32Next(hThreadSnap, &te32));
			CloseHandle(hThreadSnap);
		}
	}
	CloseHandle(hProcess);
	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	ULONG32  ulProcessID = 0;
	printf("Input ProcessID\r\n");
	cin >> ulProcessID;    		//输入需要注入的进程ID
#ifdef  _WIN64		
	DllFullPath = "E:\\Dll64.dll";
#else				
	DllFullPath = "E:\\Dll.dll";
#endif
	InjectDllWithApc(DllFullPath, ulProcessID);
	return 0;
}
