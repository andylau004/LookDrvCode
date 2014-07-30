#ifndef _KERNELINTERNAL_H_
#define _KERNELINTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif
#include <ntifs.h>	// extern "C"才能导出KeServiceDescriptorTable
#include <WinDef.h>
#ifdef __cplusplus
}; // extern "C"
#endif

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemModuleInformation = 11,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Reserved[2];
	PBYTE Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_MODULE_INFO_LIST
{
	ULONG ulCount;
	SYSTEM_MODULE_INFORMATION smi[1];
} SYSTEM_MODULE_INFO_LIST, *PSYSTEM_MODULE_INFO_LIST;

typedef struct _SYSTEM_SERVICE_TABLE
{
	PULONG Base;
	PULONG Count;
	ULONG Limit;
	PUCHAR Number;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
	SYSTEM_SERVICE_TABLE Ntoskrnl;
	SYSTEM_SERVICE_TABLE Win32k;
	SYSTEM_SERVICE_TABLE Reserved[2];
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

extern "C" PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;	// 竟然不能放在下面的extern "C" {};中?!!!

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS __stdcall ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

#ifdef __cplusplus
};	// extern "C"
#endif

#endif