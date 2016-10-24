#pragma once
#include"stdafx.h"
#include"DllLoader.h"


FARPROC WINAPI GetProcAddressR(HANDLE hModule, LPCSTR lpProcName)
{
	UINT_PTR uiLibraryAddress = 0;
	FARPROC fpResult = NULL;

	if (hModule == NULL)
	{
		return NULL;
	}

	uiLibraryAddress = (UINT_PTR)hModule;

	__try
	{
		UINT_PTR uiAddressArray = 0;
		UINT_PTR uiNameArray = 0;
		UINT_PTR uiNameOrdinals = 0;
		PIMAGE_NT_HEADERS pNtHeaders = NULL;
		PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

		// get the VA of the modules NT Header
		pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

		pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		// get the VA of the export directory
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

		// get the VA for the array of addresses
		uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

		// get the VA for the array of name pointers
		uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

		// get the VA for the array of name ordinals
		uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

		// test if we are importing by name or by ordinal...
		if (((DWORD)lpProcName & 0xFFFF0000) == 0x00000000)
		{
			// import by ordinal...

			// use the import ordinal (- export ordinal base) as an index into the array of addresses
			uiAddressArray += ((IMAGE_ORDINAL((DWORD)lpProcName) - pExportDirectory->Base) * sizeof(DWORD));

			// resolve the address for this imported function
			fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
		}
		else
		{
			// import by name...
			DWORD dwCounter = pExportDirectory->NumberOfNames;
			while (dwCounter--)
			{
				char * cpExportedFunctionName = (char *)(uiLibraryAddress + DEREF_32(uiNameArray));

				// test if we have a match...
				if (strcmp(cpExportedFunctionName, lpProcName) == 0)
				{
					// use the functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

					// calculate the virtual address for the function
					fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));

					// finish...
					break;
				}

				// get the next exported function name
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(WORD);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		fpResult = NULL;
	}

	return fpResult;
}

HANDLE LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter)
{
	BOOL bSuccess = FALSE;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwThreadId = 0;

	__try
	{
		do
		{
			if (!hProcess || !lpBuffer || !dwLength)
			{
				break;
			}

			// 得到加载动态库函数在dll文件中的偏移
			dwReflectiveLoaderOffset = GetLoaderOffset(lpBuffer);
			if (!dwReflectiveLoaderOffset)
			{
				break;
			}


			// alloc memory (RWX) in the host process for the image...
			lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpRemoteLibraryBuffer)
			{
				break;
			}

			// write the image into the host process...
			if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
			{
				break;
			}

			// add the offset to ReflectiveLoader() to the remote library address...
			lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);
			//创建远程线程加载动态库，将加载动态库函数 执行
			// create a remote thread in the host process to call the ReflectiveLoader!
			hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, lpParameter, (DWORD)NULL, &dwThreadId);

		} while (0);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		hThread = NULL;
	}
	return hThread;
}

HMODULE LoadLibraryR(LPVOID lpBuffer, DWORD dwLength)
{
	HMODULE hResult = NULL;
	DWORD  dwLoaderOffset = 0;
	REFLECTIVELOADER  dwReflectLoader = NULL;

	DWORD dwOldProtect1 = 0;
	DWORD dwOldProtect2 = 0;

	DLLMAIN pDllMain = NULL;

	if (lpBuffer == NULL || dwLength == 0)
	{
		return 0;
	}

	__try
	{
		dwLoaderOffset = GetLoaderOffset(lpBuffer);
		if (dwLoaderOffset != 0)
		{
			dwReflectLoader = (REFLECTIVELOADER)((UINT_PTR)lpBuffer + dwLoaderOffset);
		
			if (VirtualProtect(lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect1))
			{
				pDllMain = (DLLMAIN)dwReflectLoader();

				if (pDllMain != NULL)
				{
					if (pDllMain != NULL)
					{
						// call the loaded librarys DllMain to get its HMODULE
						if (!pDllMain(NULL, DLL_QUERY_HMODULE, &hResult))
						{
							hResult = NULL;
						}		
					}
					VirtualProtect(lpBuffer, dwLength, dwOldProtect1, &dwOldProtect2);
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		hResult = NULL;
	}
	return hResult;
}

DWORD GetLoaderOffset(VOID* lpReflectiveDllBuffer)
{
	UINT_PTR uiBaseAddress = 0;
	UINT_PTR uiBaseAddressOfNtHeader = 0;
	UINT_PTR uiDictArray = 0;
	UINT_PTR uiExportFOA = 0;
	UINT_PTR uiNameArray = 0;
	UINT_PTR uiAddressArray = 0;
	UINT_PTR uiNameOrdinals = 0;
	DWORD iCounter = 0;
#ifdef _WIN64
	DWORD dwCompiledArch = 2;
#else
	DWORD dwCompiledArch = 1;
#endif

	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;
	/*Get NT Header Base*/
	uiBaseAddressOfNtHeader = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	if (((PIMAGE_NT_HEADERS)uiBaseAddressOfNtHeader)->OptionalHeader.Magic == 0x10B)
	{
		if (dwCompiledArch != 1)
		{
			return 0;
		}
	}
	else if (((PIMAGE_NT_HEADERS)uiBaseAddressOfNtHeader)->OptionalHeader.Magic == 0x020B) // PE64
	{
		if (dwCompiledArch != 2)
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}

	uiDictArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiBaseAddressOfNtHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	//导出表在文件中的偏移
	uiExportFOA = uiBaseAddress + RvaToOffset(((PIMAGE_DATA_DIRECTORY)uiDictArray)->VirtualAddress, uiBaseAddress);

	// get the File Offset for the array of name pointers
	uiNameArray = uiBaseAddress + RvaToOffset(((PIMAGE_EXPORT_DIRECTORY)uiExportFOA)->AddressOfNames, uiBaseAddress);

	// get the File Offset for the array of addresses
	uiAddressArray = uiBaseAddress + RvaToOffset(((PIMAGE_EXPORT_DIRECTORY)uiExportFOA)->AddressOfFunctions, uiBaseAddress);

	// get the File Offset for the array of name ordinals
	uiNameOrdinals = uiBaseAddress + RvaToOffset(((PIMAGE_EXPORT_DIRECTORY)uiExportFOA)->AddressOfNameOrdinals, uiBaseAddress);

	// get a counter for the number of exported functions...
	iCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportFOA)->NumberOfNames;

	while (iCounter--)
	{
		char* cpExportFunctionName = (char *)(uiBaseAddress + RvaToOffset(DEREF_32(uiNameArray), uiBaseAddress));
	
		if (strstr(cpExportFunctionName, "ReflectiveLoader") != NULL)
		{
			// get the File Offset for the array of addresses
			uiAddressArray = uiBaseAddress + RvaToOffset(((PIMAGE_EXPORT_DIRECTORY)uiExportFOA)->AddressOfFunctions, uiBaseAddress);

			// use the functions name ordinal as an index into the array of name pointers
			uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

			// return the File Offset to the ReflectiveLoader() functions code...
			return RvaToOffset(DEREF_32(uiAddressArray), uiBaseAddress);
		}
		// get the next exported function name
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		uiNameOrdinals += sizeof(WORD);
	}
	return 0;
}

//由RVA得FOA
DWORD RvaToOffset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
	WORD wIndex = 0;
	PIMAGE_SECTION_HEADER pSectionHeaderVA = NULL;
	PIMAGE_NT_HEADERS pNtHeadersVA = NULL;

	pNtHeadersVA = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);
	pSectionHeaderVA = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeadersVA->OptionalHeader) + pNtHeadersVA->FileHeader.SizeOfOptionalHeader);
	//节区起始数据在文件中的偏移
	if (dwRva < pSectionHeaderVA[0].PointerToRawData)
	{
		return dwRva;
	}
	for (wIndex = 0; wIndex < pNtHeadersVA->FileHeader.NumberOfSections; wIndex++)
	{
		if (dwRva >= pSectionHeaderVA[wIndex].VirtualAddress && dwRva < (pSectionHeaderVA[wIndex].VirtualAddress + pSectionHeaderVA[wIndex].SizeOfRawData))
		{
			return (dwRva - pSectionHeaderVA[wIndex].VirtualAddress + pSectionHeaderVA[wIndex].PointerToRawData);
		}
	}
}
