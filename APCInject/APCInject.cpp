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

int InjectDllWithApc(char* DllFullPath, ULONG pid)
{
#ifdef _WIN64   
	RtlAdjustPrivilege = (pfnRtlAdjustPrivilege64)GetProcAddress((HMODULE)(GetModuleHandle(L"ntdll.dll")), "RtlAdjustPrivilege");
	if (RtlAdjustPrivilege == NULL)
	{
		return FALSE;
	}
	BOOLEAN dwRetVal = 0;
	RtlAdjustPrivilege(20, 1, 0, &dwRetVal);  //调整权限
#endif
	HANDLE hProcess, hThread, hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 ThreadEntry32 = { 0 };

	HMODULE hDllModule = GetModuleHandle(L"Kernel32.dll");
	int iLength = strlen(DllFullPath) + 1;		
	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, TRUE, pid);
	if (hProcess == NULL)
	{
		printf("failed to open process!!\n");
		return 0;
	}
	//申请内存  
	PVOID pRemoteAddress = (char *)VirtualAllocEx(hProcess, NULL, lstrlen((LPCWSTR)DllFullPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteAddress != NULL)
	{
		//DLL写入 
		if (WriteProcessMemory(hProcess, pRemoteAddress, (void *)DllFullPath, lstrlen((LPCWSTR)DllFullPath) + 1, NULL))
		{
			HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
			//创建快照
			hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if (hThreadSnap == INVALID_HANDLE_VALUE)
			{
				return 0;
			}
			ThreadEntry32.dwSize = sizeof(THREADENTRY32);
			if (!Thread32First(hThreadSnap, &ThreadEntry32))
			{
				CloseHandle(hThreadSnap);
				return 1;
			}
			do
			{
				//遍历线程  
				if (ThreadEntry32.th32OwnerProcessID == pid)
				{
					printf("TID:%d\n", ThreadEntry32.th32ThreadID);
					hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, ThreadEntry32.th32ThreadID);
					if (hThread != 0)
					{
						//目标线程插入APC  
						if (QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (DWORD)pRemoteAddress))
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
			} while (Thread32Next(hThreadSnap, &ThreadEntry32));
			CloseHandle(hThreadSnap);
		}
	}
	CloseHandle(hProcess);
	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	char* DllFullPath;
	ULONG32  ulProcessID = 0;
	printf("Input ProcessID\r\n");
	cin >> ulProcessID;    		
#ifdef  _WIN64		
	DllFullPath = "E:\\Dll64.dll";
#else				
	DllFullPath = "E:\\Dll.dll";
#endif
	InjectDllWithApc(DllFullPath, ulProcessID);
	return 0;
}
