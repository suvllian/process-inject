/****************************************************************************************
* Copyright (C) 2015
****************************************************************************************/
#include <ntifs.h>

#ifndef CXX_APCInject(Ring0)_H
#define CXX_APCInject(Ring0)_H

#define DEVICE_NAME  L"\\Device\\APCInject(Ring0)Device"
#define LINK_NAME    L"\\??\\APCInject(Ring0)Link"

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment
}KAPC_ENVIRONMENT;


VOID UnloadDriver(PDRIVER_OBJECT DriverObject);
NTSTATUS DefaultPassThrough(PDEVICE_OBJECT  DeviceObject,PIRP Irp);

VOID InjectByApc(IN PCHAR DllName);
void UserLoadDll_End(VOID);
VOID UserLoadDll(IN PCHAR DllPath, IN PVOID SystemArgument1, IN PVOID SystemArgument2);
PEPROCESS FindEProcess(PCHAR FindName);
PETHREAD FindApcThread(IN PEPROCESS EProcess);

extern UCHAR* PsGetProcessImageFileName(PEPROCESS EProcess);

NTSTATUS
InstallApc(ULONG			Process,
	ULONG			Thread,
	ULONG			MAppedAddress,
	PKEVENT			Event,
	PCHAR			CmdLine);

VOID
KernelApcRoutine(PKAPC Apc,
	PKNORMAL_ROUTINE *NormAlRoutine,
	IN OUT PVOID *NormAlContext,
	IN OUT PVOID *SystemArgument1,
	IN OUT PVOID *SystemArgument2);

#endif