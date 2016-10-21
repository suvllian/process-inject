#pragma once

#include<Windows.h>
#include<stdio.h>

HANDLE LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter);
DWORD GetLoaderOffset(VOID* lpReflectiveDllBuffer);
DWORD RvaToOffset(DWORD dwRva, UINT_PTR uiBaseAddress);
HMODULE LoadLibraryR(LPVOID lpBuffer, DWORD dwLength);
FARPROC WINAPI GetProcAddressR(HANDLE hModule, LPCSTR lpProcName);

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef ULONG_PTR(WINAPI * REFLECTIVELOADER)(VOID);
typedef BOOL(WINAPI * DLLMAIN)(HINSTANCE, DWORD, LPVOID);


#define DLL_QUERY_HMODULE		6