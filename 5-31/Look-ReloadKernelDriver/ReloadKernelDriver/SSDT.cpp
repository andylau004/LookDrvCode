#include "SSDT.h"
#include "Module.h"
#include "Common.h"

DWORD g_dwSDTAddress = 0;
PVOID g_pvServiceTable = NULL;
DWORD g_dwServiceLimit = 0;
PSDT_PROXY_TABLE g_pvSDTBuffer = NULL;

#ifdef __cplusplus
extern "C" {
#endif
NTKERNELAPI NTSTATUS ZwSetEvent(HANDLE EventHandle, PLONG PreviousState);
#ifdef __cplusplus
}; // extern "C"
#endif

typedef NTSTATUS (*ZwSetEventFunc)(HANDLE EventHandle, PLONG PreviousState);
#define FAKE_EVENT_HANDLE 0x288C58F1
DWORD g_dwZwSetEventIndex = 0;
ZwSetEventFunc RealZwSetEvent = NULL;
BYTE g_KiFastCallEntryOrgCode[] = {0x2b, 0xe1, 0xc1, 0xe9, 0x02};
BYTE g_KiFastCallEntryHookCode[] = {0xe9, 0x90, 0x90, 0x90, 0x90};
PBYTE g_pProxyJmpCode = NULL;	// KiFastCallEntry jmp到这里, 这里再jmp到真正的hook处理
DWORD g_dwProxyRetAddr = 0;		// The return address of the ProxyKiFastCallEntry
DWORD g_dwServiceRetAddr = 0;	// The return address of services called by KiFastCallEntry

#define DECLARE_FUNC_ADDR(name) \
	DWORD g_dw##name##Addr = 0;
#define GET_FUNC_ADDR(name) \
	RtlInitAnsiString(&astrFuncName, #name); \
	g_dw##name##Addr = GetNtoskrnlExportNameAddress(&astrFuncName, &dwFuncRVA); \
	if(0 == g_dw##name##Addr) \
	{ \
		KdPrint(("[GetSSDTFunctions][GetNtoskrnlExportNameAddress]%s error!\n", #name)); \
		break; \
	} \
	KdPrint(("[GetSSDTFunctions][GetNtoskrnlExportNameAddress]%s Address: 0x%08X, RVA: 0x%08X.\n", #name, g_dw##name##Addr, dwFuncRVA));
#define GET_FUNC_ADDR_WITHOUT_BREAK(name) \
	RtlInitAnsiString(&astrFuncName, #name); \
	g_dw##name##Addr = GetNtoskrnlExportNameAddress(&astrFuncName, &dwFuncRVA); \
	KdPrint(("[GetSSDTFunctions][GetNtoskrnlExportNameAddress]%s Address: 0x%08X, RVA: 0x%08X.\n", #name, g_dw##name##Addr, dwFuncRVA));

// 44
DECLARE_FUNC_ADDR(ZwCreateKey);
DECLARE_FUNC_ADDR(ZwQueryValueKey);
DECLARE_FUNC_ADDR(ZwDeleteKey);
DECLARE_FUNC_ADDR(ZwDeleteValueKey);
DECLARE_FUNC_ADDR(ZwSetValueKey);
DECLARE_FUNC_ADDR(ZwCreateFile);
DECLARE_FUNC_ADDR(ZwSetInformationFile);
DECLARE_FUNC_ADDR(ZwWriteFile);
DECLARE_FUNC_ADDR(ZwOpenThread);
DECLARE_FUNC_ADDR(ZwDeleteFile);
DECLARE_FUNC_ADDR(ZwOpenFile);
DECLARE_FUNC_ADDR(ZwTerminateProcess);
DECLARE_FUNC_ADDR(ZwSetInformationThread);
DECLARE_FUNC_ADDR(ZwRequestWaitReplyPort);
DECLARE_FUNC_ADDR(ZwCreateSection);
DECLARE_FUNC_ADDR(ZwOpenSection);
DECLARE_FUNC_ADDR(ZwCreateSymbolicLinkObject);
DECLARE_FUNC_ADDR(ZwOpenSymbolicLinkObject);
DECLARE_FUNC_ADDR(ZwLoadDriver);
DECLARE_FUNC_ADDR(ZwUnloadDriver);
DECLARE_FUNC_ADDR(ZwQuerySystemInformation);
DECLARE_FUNC_ADDR(ZwSetSystemInformation);
DECLARE_FUNC_ADDR(ZwOpenProcess);
DECLARE_FUNC_ADDR(ZwDeviceIoControlFile);
DECLARE_FUNC_ADDR(ZwOpenKey);
DECLARE_FUNC_ADDR(ZwDuplicateObject);
DECLARE_FUNC_ADDR(ZwFsControlFile);
DECLARE_FUNC_ADDR(ZwReplaceKey);
DECLARE_FUNC_ADDR(ZwRestoreKey);
DECLARE_FUNC_ADDR(ZwAdjustPrivilegesToken);
DECLARE_FUNC_ADDR(ZwUnmapViewOfSection);
DECLARE_FUNC_ADDR(ZwSetSystemTime);
DECLARE_FUNC_ADDR(ZwSetSecurityObject);
DECLARE_FUNC_ADDR(ZwAllocateVirtualMemory);
DECLARE_FUNC_ADDR(ZwFreeVirtualMemory);
DECLARE_FUNC_ADDR(ZwEnumerateValueKey);
DECLARE_FUNC_ADDR(ZwQueryKey);
DECLARE_FUNC_ADDR(ZwEnumerateKey);
DECLARE_FUNC_ADDR(ZwConnectPort);
DECLARE_FUNC_ADDR(ZwSecureConnectPort);
DECLARE_FUNC_ADDR(ZwAlpcConnectPort);
DECLARE_FUNC_ADDR(ZwSetTimer);
DECLARE_FUNC_ADDR(ZwSetInformationProcess);
DECLARE_FUNC_ADDR(ZwMapViewOfSection);

//////////////////////////////////////////////////////////////////////////
// GetSSDTFunctions
BOOL GetSSDTFunctions()
{
	BOOL bRet = FALSE;
	do 
	{
		ANSI_STRING astrFuncName;
		DWORD dwFuncRVA = 0;
		GET_FUNC_ADDR(ZwCreateKey);
		GET_FUNC_ADDR(ZwQueryValueKey);
		GET_FUNC_ADDR(ZwDeleteKey);
		GET_FUNC_ADDR(ZwDeleteValueKey);
		GET_FUNC_ADDR(ZwSetValueKey);
		GET_FUNC_ADDR(ZwCreateFile);
		GET_FUNC_ADDR(ZwSetInformationFile);
		GET_FUNC_ADDR(ZwWriteFile);
		GET_FUNC_ADDR(ZwOpenThread);
		GET_FUNC_ADDR(ZwDeleteFile);
		GET_FUNC_ADDR(ZwOpenFile);
		GET_FUNC_ADDR(ZwTerminateProcess);
		GET_FUNC_ADDR(ZwSetInformationThread);
		GET_FUNC_ADDR(ZwRequestWaitReplyPort);
		GET_FUNC_ADDR(ZwCreateSection);
		GET_FUNC_ADDR(ZwOpenSection);
		GET_FUNC_ADDR(ZwCreateSymbolicLinkObject);
		GET_FUNC_ADDR(ZwOpenSymbolicLinkObject);
		GET_FUNC_ADDR(ZwLoadDriver);
		GET_FUNC_ADDR(ZwUnloadDriver);
		GET_FUNC_ADDR(ZwQuerySystemInformation);
		GET_FUNC_ADDR(ZwSetSystemInformation);
		GET_FUNC_ADDR(ZwOpenProcess);
		GET_FUNC_ADDR(ZwDeviceIoControlFile);
		GET_FUNC_ADDR(ZwOpenKey);
		GET_FUNC_ADDR(ZwDuplicateObject);
		GET_FUNC_ADDR(ZwFsControlFile);
		GET_FUNC_ADDR(ZwReplaceKey);
		GET_FUNC_ADDR(ZwRestoreKey);
		GET_FUNC_ADDR(ZwAdjustPrivilegesToken);
		GET_FUNC_ADDR(ZwUnmapViewOfSection);
		GET_FUNC_ADDR(ZwSetSystemTime);
		GET_FUNC_ADDR(ZwSetSecurityObject);
		GET_FUNC_ADDR(ZwAllocateVirtualMemory);
		GET_FUNC_ADDR(ZwFreeVirtualMemory);
		GET_FUNC_ADDR(ZwEnumerateValueKey);
		GET_FUNC_ADDR(ZwQueryKey);
		GET_FUNC_ADDR(ZwEnumerateKey);
		GET_FUNC_ADDR(ZwConnectPort);
		GET_FUNC_ADDR_WITHOUT_BREAK(ZwSecureConnectPort);
		GET_FUNC_ADDR_WITHOUT_BREAK(ZwAlpcConnectPort);
		GET_FUNC_ADDR(ZwSetTimer);
		GET_FUNC_ADDR(ZwSetInformationProcess);
		GET_FUNC_ADDR(ZwMapViewOfSection);
		bRet = TRUE;
	} while (0);
	return bRet;
}

#define DECLARE_FUNC_INDEX(name) \
	DWORD g_dw##name##Index = 0;
#define GET_FUNC_INDEX(name) \
	if(0xb8 == *(BYTE*)g_dw##name##Addr) \
	{ \
		g_dw##name##Index = *(DWORD*)(g_dw##name##Addr + 1); \
		if(g_dw##name##Index >= 1000) \
		{ \
			g_dw##name##Index = 1000; \
		} \
	} \
	else \
	{ \
		g_dw##name##Index = 1000; \
	} \
	KdPrint(("[InitSSDTData]%s Index: %d.\n", #name, g_dw##name##Index));

// 44
DECLARE_FUNC_INDEX(ZwCreateKey);
DECLARE_FUNC_INDEX(ZwQueryValueKey);
DECLARE_FUNC_INDEX(ZwDeleteKey);
DECLARE_FUNC_INDEX(ZwDeleteValueKey);
DECLARE_FUNC_INDEX(ZwSetValueKey);
DECLARE_FUNC_INDEX(ZwCreateFile);
DECLARE_FUNC_INDEX(ZwSetInformationFile);
DECLARE_FUNC_INDEX(ZwWriteFile);
DECLARE_FUNC_INDEX(ZwOpenThread);
DECLARE_FUNC_INDEX(ZwDeleteFile);
DECLARE_FUNC_INDEX(ZwOpenFile);
DECLARE_FUNC_INDEX(ZwTerminateProcess);
DECLARE_FUNC_INDEX(ZwSetInformationThread);
DECLARE_FUNC_INDEX(ZwRequestWaitReplyPort);
DECLARE_FUNC_INDEX(ZwCreateSection);
DECLARE_FUNC_INDEX(ZwOpenSection);
DECLARE_FUNC_INDEX(ZwCreateSymbolicLinkObject);
DECLARE_FUNC_INDEX(ZwOpenSymbolicLinkObject);
DECLARE_FUNC_INDEX(ZwLoadDriver);
DECLARE_FUNC_INDEX(ZwUnloadDriver);
DECLARE_FUNC_INDEX(ZwQuerySystemInformation);
DECLARE_FUNC_INDEX(ZwSetSystemInformation);
DECLARE_FUNC_INDEX(ZwOpenProcess);
DECLARE_FUNC_INDEX(ZwDeviceIoControlFile);
DECLARE_FUNC_INDEX(ZwOpenKey);
DECLARE_FUNC_INDEX(ZwDuplicateObject);
DECLARE_FUNC_INDEX(ZwFsControlFile);
DECLARE_FUNC_INDEX(ZwReplaceKey);
DECLARE_FUNC_INDEX(ZwRestoreKey);
DECLARE_FUNC_INDEX(ZwAdjustPrivilegesToken);
DECLARE_FUNC_INDEX(ZwUnmapViewOfSection);
DECLARE_FUNC_INDEX(ZwSetSystemTime);
DECLARE_FUNC_INDEX(ZwSetSecurityObject);
DECLARE_FUNC_INDEX(ZwAllocateVirtualMemory);
DECLARE_FUNC_INDEX(ZwFreeVirtualMemory);
DECLARE_FUNC_INDEX(ZwEnumerateValueKey);
DECLARE_FUNC_INDEX(ZwQueryKey);
DECLARE_FUNC_INDEX(ZwEnumerateKey);
DECLARE_FUNC_INDEX(ZwConnectPort);
DECLARE_FUNC_INDEX(ZwSecureConnectPort);
DECLARE_FUNC_INDEX(ZwAlpcConnectPort);
DECLARE_FUNC_INDEX(ZwSetTimer);
DECLARE_FUNC_INDEX(ZwSetInformationProcess);
DECLARE_FUNC_INDEX(ZwMapViewOfSection);

//////////////////////////////////////////////////////////////////////////
// InitSSDTData
BOOL InitSSDTData()
{
	BOOL bRet = FALSE;
	do 
	{
		if(!GetSSDTFunctions())
		{
			break;
		}
		GET_FUNC_INDEX(ZwCreateKey);
		GET_FUNC_INDEX(ZwQueryValueKey);
		GET_FUNC_INDEX(ZwDeleteKey);
		GET_FUNC_INDEX(ZwDeleteValueKey);
		GET_FUNC_INDEX(ZwSetValueKey);
		GET_FUNC_INDEX(ZwCreateFile);
		GET_FUNC_INDEX(ZwSetInformationFile);
		GET_FUNC_INDEX(ZwWriteFile);
		GET_FUNC_INDEX(ZwOpenThread);
		GET_FUNC_INDEX(ZwDeleteFile);
		GET_FUNC_INDEX(ZwOpenFile);
		GET_FUNC_INDEX(ZwTerminateProcess);
		GET_FUNC_INDEX(ZwSetInformationThread);
		GET_FUNC_INDEX(ZwRequestWaitReplyPort);
		GET_FUNC_INDEX(ZwCreateSection);
		GET_FUNC_INDEX(ZwOpenSection);
		GET_FUNC_INDEX(ZwCreateSymbolicLinkObject);
		GET_FUNC_INDEX(ZwOpenSymbolicLinkObject);
		GET_FUNC_INDEX(ZwLoadDriver);
		GET_FUNC_INDEX(ZwUnloadDriver);
		GET_FUNC_INDEX(ZwQuerySystemInformation);
		GET_FUNC_INDEX(ZwSetSystemInformation);
		GET_FUNC_INDEX(ZwOpenProcess);
		GET_FUNC_INDEX(ZwDeviceIoControlFile);
		GET_FUNC_INDEX(ZwOpenKey);
		GET_FUNC_INDEX(ZwDuplicateObject);
		GET_FUNC_INDEX(ZwFsControlFile);
		GET_FUNC_INDEX(ZwReplaceKey);
		GET_FUNC_INDEX(ZwRestoreKey);
		GET_FUNC_INDEX(ZwAdjustPrivilegesToken);
		GET_FUNC_INDEX(ZwUnmapViewOfSection);
		GET_FUNC_INDEX(ZwSetSystemTime);
		GET_FUNC_INDEX(ZwSetSecurityObject);
		GET_FUNC_INDEX(ZwAllocateVirtualMemory);
		GET_FUNC_INDEX(ZwFreeVirtualMemory);
		GET_FUNC_INDEX(ZwEnumerateValueKey);
		GET_FUNC_INDEX(ZwQueryKey);
		GET_FUNC_INDEX(ZwEnumerateKey);
		GET_FUNC_INDEX(ZwConnectPort);
		
		// 特殊处理
		ULONG ulMajorVersion, ulMinorVersion, ulBuildNumber;
		ulMajorVersion = ulMinorVersion = ulBuildNumber = 0;
		PsGetVersion(&ulMajorVersion, &ulMinorVersion, &ulBuildNumber, NULL);
		g_dwZwSecureConnectPortIndex = 1000;
		if(0 == g_dwZwSecureConnectPortAddr)
		{
			if(5 == ulMajorVersion)
			{
				if(0 == ulMinorVersion)
				{
					g_dwZwSecureConnectPortIndex = 184;
				}
				else if(1 ==  ulMinorVersion)
				{
					g_dwZwSecureConnectPortIndex = 210;
				}
			}
		}
		else
		{
			if(0xb8 == *(BYTE*)g_dwZwSecureConnectPortAddr)
			{
				g_dwZwSecureConnectPortIndex = *(DWORD*)(g_dwZwSecureConnectPortAddr + 1);
			}
			if(g_dwZwSecureConnectPortIndex >= 1000)
			{
				g_dwZwSecureConnectPortIndex = 1000;
			}
		}
		KdPrint(("[InitSSDTData]ZwSecureConnectPort Index: %d.\n", g_dwZwSecureConnectPortIndex));

		g_dwZwAlpcConnectPortIndex = 1000;
		if(g_dwZwAlpcConnectPortAddr != 0)
		{
			GET_FUNC_INDEX(ZwAlpcConnectPort);
		}
		else
		{
			KdPrint(("[InitSSDTData]ZwAlpcConnectPort Index: 1000.\n"));
		}

		GET_FUNC_INDEX(ZwSetTimer);
		GET_FUNC_INDEX(ZwSetInformationProcess);
		GET_FUNC_INDEX(ZwMapViewOfSection);

		// TODO: 其它SSDT Index
		bRet = TRUE;
	} while (0);
	return bRet;
}

//////////////////////////////////////////////////////////////////////////
// AllocateSSDTMemory
BOOL AllocateSSDTMemory(DWORD dwServiceLimit)
{
	BOOL bRet = FALSE;
	g_pvSDTBuffer = (PSDT_PROXY_TABLE)ExAllocatePoolWithTag(NonPagedPool, sizeof(SDT_PROXY_TABLE), TAG);	// TODO: miss 4 bytes yet
	if(g_pvSDTBuffer != NULL)
	{
		memset(g_pvSDTBuffer, 0, sizeof(SDT_PROXY_TABLE));
		g_pvSDTBuffer->ProxyServiceTableArray[REAL_SDT_INDEX].ProxyServiceLimit = dwServiceLimit;
		bRet = TRUE;
	}
	return bRet;
}

//////////////////////////////////////////////////////////////////////////
// HookKiFastCallEntry
NTSTATUS HookKiFastCallEntry()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	do 
	{
		ANSI_STRING astrZwSetEvent;
		DWORD dwZwSetEventAddr, dwZwSetEventRVA;
		dwZwSetEventAddr = dwZwSetEventRVA = 0;
		RtlInitAnsiString(&astrZwSetEvent, "ZwSetEvent");
		dwZwSetEventAddr = GetNtoskrnlExportNameAddress(&astrZwSetEvent, &dwZwSetEventRVA);
		if(0 == dwZwSetEventAddr)
		{
			break;
		}
		g_dwZwSetEventIndex = *(DWORD*)(dwZwSetEventAddr + 1);

		KSPIN_LOCK SpinLock;
		KIRQL OldIrql;
		KeInitializeSpinLock(&SpinLock);
		KeAcquireSpinLock(&SpinLock, &OldIrql);
		PageProtectOff();
		RealZwSetEvent = (ZwSetEventFunc)(((PSERVICE_DESCRIPTOR_TABLE)g_dwSDTAddress)->ServiceTable[g_dwZwSetEventIndex]);
		((PSERVICE_DESCRIPTOR_TABLE)g_dwSDTAddress)->ServiceTable[g_dwZwSetEventIndex] = (DWORD)FakeZwSetEvent;
		PageProtectOn();
		KeReleaseSpinLock(&SpinLock, OldIrql);
		ZwSetEvent((HANDLE)FAKE_EVENT_HANDLE, NULL);

		if(0 == g_dwServiceRetAddr)	// The return address of KiFastCallEntry call ZwSetEvent
		{
			if(g_pProxyJmpCode != NULL)
			{
				ExFreePool(g_pProxyJmpCode);
			}
			break;
		}

		if(g_dwProxyRetAddr != 0)	// TODO: Search
		{
			status = STATUS_SUCCESS;
			break;
		}
	} while (0);
	return status;
}

//////////////////////////////////////////////////////////////////////////
// FakeZwSetEvent
NTSTATUS FakeZwSetEvent(HANDLE EventHandle, PLONG PreviousState)
{
	NTSTATUS status = STATUS_SUCCESS;	// STATUS_SUCCESS is the default return value.
	do 
	{
		if((DWORD)EventHandle != FAKE_EVENT_HANDLE || ExGetPreviousMode() != KernelMode)
		{
			status = RealZwSetEvent(EventHandle, PreviousState);
			break;
		}

		g_pProxyJmpCode = (PBYTE)ExAllocatePoolWithTag(NonPagedPool, 5, TAG);	// HookKiFastCallEntry中释放
		if(NULL == g_pProxyJmpCode)
		{
			break;
		}

		g_pProxyJmpCode[0] = 0xe9;
		DWORD dwProxyJmpAddr = (DWORD)ProxyKiFastCallEntryVista;
		if((USHORT)NtBuildNumber < 6000)
		{
			// Before Vista
			dwProxyJmpAddr = (DWORD)ProxyKiFastCallEntry;
		}
		*(DWORD*)(g_pProxyJmpCode + 1) = dwProxyJmpAddr - 5 - (DWORD)(g_pProxyJmpCode);

		KSPIN_LOCK SpinLock;
		KIRQL OldIrql;
		KeInitializeSpinLock(&SpinLock);
		KeAcquireSpinLock(&SpinLock, &OldIrql);
		PageProtectOff();

		((PSERVICE_DESCRIPTOR_TABLE)g_dwSDTAddress)->ServiceTable[g_dwZwSetEventIndex] = (DWORD)RealZwSetEvent;
		_asm
		{
			mov eax, dword ptr[ebp+4]
			mov g_dwServiceRetAddr, eax
		}

		// 搜索Hook的地址
		DWORD dwSearch = g_dwServiceRetAddr;
		do 
		{
			PBYTE pCode = (PBYTE)dwSearch;
			int i = 0;
			for(; i < sizeof(g_KiFastCallEntryOrgCode); ++i)
			{
				if(pCode[i] != g_KiFastCallEntryOrgCode[i])
				{
					break;
				}
			}
			if(i == sizeof(g_KiFastCallEntryOrgCode))
			{
				g_dwProxyRetAddr = dwSearch + 5;
				*(DWORD*)(g_KiFastCallEntryHookCode + 1) = (DWORD)(g_pProxyJmpCode) - 5 - dwSearch;
				memcpy((void*)dwSearch, g_KiFastCallEntryHookCode, 5);
				break;
			}
			--dwSearch;
		} while (g_dwServiceRetAddr - dwSearch < 100);

		PageProtectOn();
		KeReleaseSpinLock(&SpinLock, OldIrql);
	} while (0);
	return status;
}

//////////////////////////////////////////////////////////////////////////
// ProxyKiFastCallEntry
_declspec(naked) VOID ProxyKiFastCallEntry()
{
	_asm
	{
		mov edi, edi
		pushfd
		pushad
		push edi
		push ebx
		push eax
		call FakeKiFastCallEntry
		mov dword ptr[esp+0x10], eax	; 改变ebx的值, 下面调用系统服务是用的call ebx
		popad
		popfd
		sub esp, ecx
		shr ecx, 2
		push g_dwProxyRetAddr
		ret
	}
}

//////////////////////////////////////////////////////////////////////////
// ProxyKiFastCallEntry
_declspec(naked) VOID ProxyKiFastCallEntryVista()
{
	_asm
	{
		mov edi, edi
		pushfd
		pushad
		push edi
		push ebx
		push eax
		call FakeKiFastCallEntry
		mov dword ptr[esp+0x14], eax	; 改变ebx的值, 下面调用系统服务是用的call ebx
		popad
		popfd
		sub esp, ecx
		shr ecx, 2
		push g_dwProxyRetAddr
		retn
	}
}

extern PSERVICE_DESCRIPTOR_TABLE g_pNewSSDT;

//////////////////////////////////////////////////////////////////////////
// FakeKiFastCallEntry
DWORD FakeKiFastCallEntry(DWORD dwServiceNumber, DWORD dwServiceAddress, DWORD dwSDTBase)
{
	//KdPrint(("[FakeKiFastCallEntry]Service Number: %lu, Address: 0x%08X, SDT Base: 0x%08X.\n", dwServiceNumber, dwServiceAddress, dwSDTBase));
	DWORD dwRetAddr = dwServiceAddress;
	do 
	{
		if(dwSDTBase == (DWORD)g_pvServiceTable && dwServiceNumber <= g_dwServiceLimit)
		{
			//if(g_pvSDTBuffer->ProxyServiceTableArray[FLAG_SDT_INDEX].ProxyServiceTable[dwServiceNumber])
			//{
			//	g_pvSDTBuffer->ProxyServiceTableArray[REAL_SDT_INDEX].ProxyServiceTable[dwServiceNumber] = dwServiceAddress;
			//	dwRetAddr = g_pvSDTBuffer->ProxyServiceTableArray[FAKE_SDT_INDEX].ProxyServiceTable[dwServiceNumber];
			//	break;
			//}
			dwRetAddr = g_pNewSSDT->ServiceTable[dwServiceNumber];
			//KdPrint(("[FakeKiFastCallEntry]Service Number: %lu, Address: 0x%08x -> 0x%08x\n", dwServiceNumber, dwServiceAddress, dwRetAddr));
		}

		// TODO: Win32k

		// Here is dwServiceAddress.
	} while (0);
	return dwRetAddr;
}

//////////////////////////////////////////////////////////////////////////
// Test
typedef NTSTATUS (*ZwCreateFileFunc)(
	  PHANDLE FileHandle,
	  ACCESS_MASK DesiredAccess,
	  POBJECT_ATTRIBUTES ObjectAttributes,
	  PIO_STATUS_BLOCK IoStatusBlock,
	  PLARGE_INTEGER AllocationSize,
	  ULONG FileAttributes,
	  ULONG ShareAccess,
	  ULONG CreateDisposition,
	  ULONG CreateOptions,
	  PVOID EaBuffer,
	  ULONG EaLength);

NTSTATUS FakeZwCreateFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength)
{
	KdPrint(("[FakeZwCreateFile]%wZ\n", ObjectAttributes->ObjectName));
	ZwCreateFileFunc RealZwCreateFile = (ZwCreateFileFunc)(g_pvSDTBuffer->ProxyServiceTableArray[REAL_SDT_INDEX].ProxyServiceTable[g_dwZwCreateFileIndex]);
	return RealZwCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, 
		FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

VOID TestSSDTHook()
{
	g_pvSDTBuffer->ProxyServiceTableArray[FAKE_SDT_INDEX].ProxyServiceTable[g_dwZwCreateFileIndex] = (DWORD)FakeZwCreateFile;
	g_pvSDTBuffer->ProxyServiceTableArray[FLAG_SDT_INDEX].ProxyServiceTable[g_dwZwCreateFileIndex] = TRUE;
}
