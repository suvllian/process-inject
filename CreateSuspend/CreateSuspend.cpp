// CreateSuspend.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include<iostream>
using namespace std;

void CreateShellCode(int ret, int str, unsigned char** shellcode, int* shellcodeSize)
{
	unsigned char* retChar = (unsigned char*)&ret;
	unsigned char* strChar = (unsigned char*)&str;
	int api = (int)GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");
	unsigned char* apiChar = (unsigned char*)&api;
	unsigned char sc[] = {
		// Push ret
		0x68, retChar[0], retChar[1], retChar[2], retChar[3],
		// Push all flags
		0x9C,
		// Push all register
		0x60,
		// Push 0x66666666 (later we convert it to the string of "C:\DLLInjectionTest.dll")
		0x68, strChar[0], strChar[1], strChar[2], strChar[3],
		// Mov eax, 0x66666666 (later we convert it to LoadLibrary adress)
		0xB8, apiChar[0], apiChar[1], apiChar[2], apiChar[3],
		// Call eax
		0xFF, 0xD0,
		// Pop all register
		0x61,
		// Pop all flags
		0x9D,
		// Ret
		0xC3
	};

	*shellcodeSize = 22;
	*shellcode = (unsigned char*)malloc(22);
	memcpy(*shellcode, sc, 22);
}

int _tmain(int argc, char* argv[])
{
	// Path to the DLL, which you want to inject
	char DllPath[] = "E:\\Dll.dll";

	unsigned char* ShellCode;
	int ShellCodeLength;

	LPVOID Remote_DllStringPtr;
	LPVOID Remote_ShellCodePtr;

	CONTEXT ctx;

	//创建挂起线程
	PROCESS_INFORMATION pi;
	STARTUPINFOA Startup;
	ZeroMemory(&Startup, sizeof(Startup));
	ZeroMemory(&pi, sizeof(pi));
	CreateProcessA("D:\\火狐\\firefox.exe", NULL, NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, &Startup, &pi);

	Remote_DllStringPtr = VirtualAllocEx(pi.hProcess, NULL, strlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	printf("为DLL路径申请到的地址：%X\n", Remote_DllStringPtr);

	printf("Get EIP\n");
	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(pi.hThread, &ctx);
	printf("EIP: %X\n", ctx.Eip);

	printf("创建ShellCode\n");
	CreateShellCode(ctx.Eip, (int)Remote_DllStringPtr, &ShellCode, &ShellCodeLength);


	printf("Allocating Remote Memory For Shellcode\n");
	Remote_ShellCodePtr = VirtualAllocEx(pi.hProcess, NULL, ShellCodeLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(pi.hProcess, Remote_DllStringPtr, DllPath, strlen(DllPath) + 1, NULL);
	WriteProcessMemory(pi.hProcess, Remote_ShellCodePtr, ShellCode, ShellCodeLength, NULL);

	printf("Set EIP\n");
	ctx.Eip = (DWORD)Remote_ShellCodePtr;
	ctx.ContextFlags = CONTEXT_CONTROL;
	SetThreadContext(pi.hThread, &ctx);

	printf("ResumeThread\n");
	ResumeThread(pi.hThread);

	Sleep(8000);

	VirtualFreeEx(pi.hProcess, Remote_DllStringPtr, strlen(DllPath) + 1, MEM_DECOMMIT);
	VirtualFreeEx(pi.hProcess, Remote_ShellCodePtr, ShellCodeLength, MEM_DECOMMIT);

	return 0;
}
