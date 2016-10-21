#include"ReflectiveLoader.h"

HINSTANCE hAppInstance = NULL;

ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }

#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
#else
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(VOID)
#endif
{
	ULONG_PTR uiLibraryAddress;
	ULONG_PTR uiNtHeaderOffset;
	ULONG_PTR uiNtHeaderRva;

	// the kernels base address and later this images newly loaded base address
	ULONG_PTR uiBaseAddress;


	// we will start searching backwards from our callers return address.
	uiLibraryAddress = caller();


	while (1)
	{
		if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			uiNtHeaderOffset = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
			
			if (uiNtHeaderOffset >= sizeof(IMAGE_DOS_HEADER) && uiNtHeaderOffset < 1024)
			{
				uiNtHeaderRva = uiNtHeaderOffset + uiLibraryAddress;
				if (((PIMAGE_NT_HEADERS)uiNtHeaderRva)->Signature == IMAGE_NT_SIGNATURE)
				{
					break;//?
				}
			}
			
		}
		//??
		uiLibraryAddress--;
	}


/*Get PEB*/
#ifdef _WIN64
		uiBaseAddress = __readgsqword(0x60);
#else
		uiBaseAddress = __readfsdword(0x30);
#endif
		uiBaseAddress = ((_PPEB)uiBaseAddress)

}