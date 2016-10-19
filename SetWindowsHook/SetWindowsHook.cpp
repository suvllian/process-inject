// SetWindowsHook.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<iostream>
#include<Windows.h>
#include<TlHelp32.h>
using namespace std;

BOOL SetWinHookInject(WCHAR * wzDllPath, int wzProcessId);
DWORD GetThreadIdByProcessId(int ProcessId);

int _tmain(int argc, char* argv[])
{
	int ProcessID = 0;
	cout << "Input ProcessID" << endl;
	cin >> ProcessID;

#ifdef _WIN64
	WCHAR wzDllFullPath[0x20] = L"E:\\SetWindowDll64.dll";
#else
	WCHAR wzDllFullPath[0x20] = L"E:\\SetWindowDll.dll";
#endif // _WIN64

	if (!SetWinHookInject(wzDllFullPath, ProcessID))
	{
		printf("Set Hook Unsuccess!\r\n");
		return 0;
	}
	printf("Inject Success!\r\n");

	return 0;
}

BOOL SetWinHookInject(WCHAR * wzDllPath, int wzProcessId)
{
	HMODULE ModuleHandle = NULL;
	BOOL    bOk = FALSE;
	DWORD   FunctionAddress = NULL;
	UINT32 dwThreadId = 0;
	HHOOK  g_hHook = NULL;
	PVOID  pShareM = NULL;

	printf("SetWinHKInject Enter!\n");

	ModuleHandle = LoadLibrary(wzDllPath);
	if (!ModuleHandle)
	{
		printf("LoadLibrary error!\n");

		return FALSE;
	}

	FunctionAddress = (DWORD)GetProcAddress(ModuleHandle, "MyMessageProcess");
	if (!FunctionAddress)
	{
		printf("GetProcAddress error!\n");
		FreeLibrary(ModuleHandle);
		return FALSE;
	}

	dwThreadId = GetThreadIdByProcessId(wzProcessId);

	int a = GetLastError();
	if (!dwThreadId)
	{
		FreeLibrary(ModuleHandle);
		return FALSE;
	}

	g_hHook = SetWindowsHookEx(
		WH_GETMESSAGE,
		(HOOKPROC)FunctionAddress,
		ModuleHandle,
		dwThreadId
	);
	a = GetLastError();
	if (!g_hHook)
	{
		printf("[+] SetWindowsHookEx  error!\n");
		FreeLibrary(ModuleHandle);
		return FALSE;
	}
	printf("[!] SetWinHKInject Exit!\n");
	return TRUE;

}

DWORD GetThreadIdByProcessId(int ProcessId)
{
	DWORD m_ThreadId = 0;
	FILETIME RunTime = { 0 };
	const DWORD m_ProcessId = ProcessId;

	HANDLE hThreadSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, m_ProcessId);//获取快照句柄
	if (hThreadSnap == INVALID_HANDLE_VALUE)//如果获取失败返回
	{
		return 0;
	}
	THREADENTRY32 pe32 = { sizeof(pe32) };//快照结构并给予大小
	if (::Thread32First(hThreadSnap, &pe32))
	{
		do
		{
			if (pe32.th32OwnerProcessID == m_ProcessId)//如果进程ID等于你想寻找的进程ID则返回主线程ID
			{
				HANDLE ThreadHandle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, pe32.th32ThreadID);

				FILETIME CreateTime, LoadStopTime, LoadTimeInKerner, LoadTimeInUser;
				::GetThreadTimes(ThreadHandle, &CreateTime, &LoadStopTime, &LoadTimeInKerner, &LoadTimeInUser);
				SYSTEMTIME RealTime;
				::FileTimeToSystemTime(&CreateTime, &RealTime);
				if (CreateTime.dwHighDateTime < RunTime.dwHighDateTime
					|| (RunTime.dwHighDateTime == 0 && RunTime.dwLowDateTime == 0))
				{
					m_ThreadId = pe32.th32ThreadID;
					RunTime = CreateTime;
					return m_ThreadId;
				}
				else
					if (CreateTime.dwHighDateTime == RunTime.dwHighDateTime &&
						CreateTime.dwLowDateTime < RunTime.dwLowDateTime)
					{
						m_ThreadId = pe32.th32ThreadID;
						RunTime = CreateTime;
						return m_ThreadId;
					}
			}
		} while (::Thread32Next(hThreadSnap, &pe32));
	}//否则循环判断尾
	CloseHandle(hThreadSnap);
}

