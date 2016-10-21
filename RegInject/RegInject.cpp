// RegInject.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<Windows.h>
#include <iostream>
using namespace std;


int main()
{
	HKEY	RegistryKeyHandle = NULL;
	WCHAR	wzSubKeyPath[MAX_PATH] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
	LRESULT	Return = ERROR_SUCCESS;
	CHAR	szDllFullPath[MAX_PATH] = { 0 };
	CHAR	LoadAppInitDlls = '1';

#ifdef _WIN64
	strcat_s(szDllFullPath, "E：\\Dll64.dll");
#else
	strcat_s(szDllFullPath, "E：\\Dll.dll");
#endif

	// 1.´ò¿ª×¢²á±í

	Return = RegOpenKeyEx(HKEY_LOCAL_MACHINE,	// Ö÷¼üÃû³Æ
		wzSubKeyPath,							// ×Ó¼üÃû³Æ
		0,
		KEY_ALL_ACCESS,							// ´ò¿ªÈ¨ÏÞ
		&RegistryKeyHandle);

	if (Return != ERROR_SUCCESS)
	{
		printf("Open Registry Error\r\n");
		RegCloseKey(RegistryKeyHandle);
		return 0;
	}

	Return = RegSetValueExA(RegistryKeyHandle,
		"AppInit_DLLs",						// ¼üÖµÏîÃû³Æ
		0,
		REG_SZ,									// ¼üÖµÏîÀàÐÍ
		(CONST BYTE*)szDllFullPath,
		MAX_PATH);

	if (Return != ERROR_SUCCESS)
	{
		printf("Write DllFullPath Error\r\n");
		RegCloseKey(RegistryKeyHandle);
		return 0;
	}

	Return = RegSetValueExA(RegistryKeyHandle,
		"LoadAppInit_DLLs",						// ¼üÖµÏîÃû³Æ
		0,
		REG_DWORD,									// ¼üÖµÏîÀàÐÍ
		(CONST BYTE*)LoadAppInitDlls,
		sizeof(DWORD));

	if (Return != ERROR_SUCCESS)
	{
		printf("Write DllFullPath Error\r\n");
		int a = GetLastError();
		RegCloseKey(RegistryKeyHandle);
		return 0;
	}

	printf("Input Any Key To Exit\r\n");

	getchar();
	getchar();

    return 0;
}

