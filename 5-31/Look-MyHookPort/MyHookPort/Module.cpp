#include "Module.h"
#include "Common.h"
#include <ntimage.h>

DWORD g_dwNtoskrnlImageBase = 0;
DWORD g_dwNtoskrnlImageSize = 0;

typedef enum _SYSTEM_INFORMATION_CLASS   
{   
	SystemBasicInformation,                 //  0 Y N   
	SystemProcessorInformation,             //  1 Y N   
	SystemPerformanceInformation,           //  2 Y N   
	SystemTimeOfDayInformation,             //  3 Y N   
	SystemNotImplemented1,                  //  4 Y N   
	SystemProcessesAndThreadsInformation,   //  5 Y N   
	SystemCallCounts,                       //  6 Y N   
	SystemConfigurationInformation,         //  7 Y N   
	SystemProcessorTimes,                   //  8 Y N   
	SystemGlobalFlag,                       //  9 Y Y   
	SystemNotImplemented2,                  // 10 Y N   
	SystemModuleInformation,                // 11 Y N   
	SystemLockInformation,                  // 12 Y N   
	SystemNotImplemented3,                  // 13 Y N   
	SystemNotImplemented4,                  // 14 Y N   
	SystemNotImplemented5,                  // 15 Y N   
	SystemHandleInformation,                // 16 Y N   
	SystemObjectInformation,                // 17 Y N   
	SystemPagefileInformation,              // 18 Y N   
	SystemInstructionEmulationCounts,       // 19 Y N   
	SystemInvalidInfoClass1,                // 20   
	SystemCacheInformation,                 // 21 Y Y   
	SystemPoolTagInformation,               // 22 Y N   
	SystemProcessorStatistics,              // 23 Y N   
	SystemDpcInformation,                   // 24 Y Y   
	SystemNotImplemented6,                  // 25 Y N   
	SystemLoadImage,                        // 26 N Y   
	SystemUnloadImage,                      // 27 N Y   
	SystemTimeAdjustment,                   // 28 Y Y   
	SystemNotImplemented7,                  // 29 Y N   
	SystemNotImplemented8,                  // 30 Y N   
	SystemNotImplemented9,                  // 31 Y N   
	SystemCrashDumpInformation,             // 32 Y N   
	SystemExceptionInformation,             // 33 Y N   
	SystemCrashDumpStateInformation,        // 34 Y Y/N   
	SystemKernelDebuggerInformation,        // 35 Y N   
	SystemContextSwitchInformation,         // 36 Y N   
	SystemRegistryQuotaInformation,         // 37 Y Y   
	SystemLoadAndCallImage,                 // 38 N Y   
	SystemPrioritySeparation,               // 39 N Y   
	SystemNotImplemented10,                 // 40 Y N   
	SystemNotImplemented11,                 // 41 Y N   
	SystemInvalidInfoClass2,                // 42   
	SystemInvalidInfoClass3,                // 43   
	SystemTimeZoneInformation,              // 44 Y N   
	SystemLookasideInformation,             // 45 Y N   
	SystemSetTimeSlipEvent,                 // 46 N Y   
	SystemCreateSession,                    // 47 N Y   
	SystemDeleteSession,                    // 48 N Y   
	SystemInvalidInfoClass4,                // 49   
	SystemRangeStartInformation,            // 50 Y N   
	SystemVerifierInformation,              // 51 Y Y   
	SystemAddVerifier,                      // 52 N Y   
	SystemSessionProcessesInformation       // 53 Y N   
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE {
	ULONG Reserved1; 
	ULONG Reserved2; 
	PVOID ImageBaseAddress; 
	ULONG ImageSize; 
	ULONG Flags; 
	WORD Id; 
	WORD Rank; 
	WORD w018; 
	WORD NameOffset; 
	BYTE Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

#pragma warning(push)
#pragma warning(disable:4200)
typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG ModulesCount; 
	SYSTEM_MODULE Modules[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
#pragma warning(pop)

#ifdef __cplusplus
extern "C" {
#endif
NTKERNELAPI NTSTATUS WINAPI ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
PIMAGE_EXPORT_DIRECTORY RtlImageDirectoryEntryToData(ULONG ulImageBase, BOOL bVA, ULONG ulDirectoryIndex, ULONG* pulSize);
#ifdef __cplusplus
}; // extern "C"
#endif

//////////////////////////////////////////////////////////////////////////
// GetModuleInfo
BOOL GetModuleInfo(char* lpModuleName, ULONG* pulImageBaseAddress, ULONG* pulImageSize)
{
	BOOL bRet = FALSE;
	do 
	{
		if(NULL == pulImageBaseAddress || NULL == pulImageSize)	// lpModuleName为NULL时返回第一个模块信息
		{
			break;
		}

		PVOID pBuffer = NULL;
		ULONG ulLength = 0x1000;	// 4k
		ULONG ulReturnLength = 0;
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		do 
		{
			if(pBuffer != NULL)
			{
				// 释放上一次分配的内存
				ExFreePool(pBuffer);
				pBuffer = NULL;
			}

			// 申请新的内存
			pBuffer = ExAllocatePoolWithTag(NonPagedPool, ulLength, TAG);
			if(NULL == pBuffer)
			{
				break;
			}

			status = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, ulLength, &ulReturnLength);
			if(STATUS_INFO_LENGTH_MISMATCH == status)
			{
				ulLength *= 2;	// 双倍内存
			}
			else
			{
				break;	// 成功, 或其它失败原因
			}
		} while (1);
		if(!NT_SUCCESS(status))
		{
			break;	// 其它失败原因
		}

		ULONG ulCount = ((PSYSTEM_MODULE_INFORMATION)pBuffer)->ModulesCount;
		if(0 == ulCount)
		{
			ExFreePool(pBuffer);
			break;
		}

		if(NULL == lpModuleName)
		{
			*pulImageBaseAddress = (ULONG)((PSYSTEM_MODULE_INFORMATION)pBuffer)->Modules[0].ImageBaseAddress;
			*pulImageSize = ((PSYSTEM_MODULE_INFORMATION)pBuffer)->Modules[0].ImageSize;
			bRet = TRUE;
			ExFreePool(pBuffer);
			break;
		}

		for(int i = 0; i < (int)ulCount; ++i)
		{
			BYTE* pName = ((PSYSTEM_MODULE_INFORMATION)pBuffer)->Modules[i].Name;	// Modules[0].Name: \WINDOWS\system32\ntkrnlpa.exe
			char* pModule = strrchr((char*)pName, '\\');
			if(pModule != NULL)
			{
				++pModule;
			}
			else
			{
				pModule = (char*)pName;
			}
			if(_stricmp(pModule, lpModuleName) == 0)
			{
				*pulImageBaseAddress = (ULONG)((PSYSTEM_MODULE_INFORMATION)pBuffer)->Modules[i].ImageBaseAddress;
				*pulImageSize = ((PSYSTEM_MODULE_INFORMATION)pBuffer)->Modules[i].ImageSize;
				bRet = TRUE;
				break;
			}
		}
		ExFreePool(pBuffer);
	} while (0);
	return bRet;
}

//////////////////////////////////////////////////////////////////////////
// EATHook
ULONG EATHook(ULONG ulImageBase, ANSI_STRING* lpastrExportName, ULONG ulHookFunc, ULONG* pulOrgFuncRVA)
{
	ULONG ulRet = 0;
	do 
	{
		if(NULL == lpastrExportName || NULL == pulOrgFuncRVA)
		{
			break;
		}

		KdPrint(("EATHook %s.\n", lpastrExportName->Buffer));

		ULONG ulSize = 0;
		PIMAGE_EXPORT_DIRECTORY pDirectory = RtlImageDirectoryEntryToData(ulImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &ulSize);
		if(NULL == pDirectory)
		{
			break;
		}

		int nHighIndex = pDirectory->NumberOfNames - 1;
		if(nHighIndex < 0)
		{
			break;	// NumberOfNames为0
		}

		int nLowIndex = 0;
		int nMidIndex = 0;
		char* pszExportName = lpastrExportName->Buffer;
		BOOL bMatch = FALSE;
		while(nHighIndex >= nLowIndex)
		{
			nMidIndex = (nLowIndex + nHighIndex) / 2;
			char* pBuffer = (char*)(((ULONG*)(pDirectory->AddressOfNames + ulImageBase))[nMidIndex] + ulImageBase);
			//KdPrint(("nLowIndex: %d, nMidIndex: %d, nHightIndex: %d, ExportName: %s.\n", nLowIndex, nMidIndex, nHighIndex, pBuffer));
			int i = 0;
			for(; pszExportName[i] != 0; ++i)
			{
				if(pszExportName[i] - pBuffer[i] > 0)
				{
					if(nLowIndex == nMidIndex)
					{
						// 特殊情况
						++nLowIndex;
					}
					else
					{
						nLowIndex = nMidIndex;
					}
					break;
				}
				else if(pszExportName[i] - pBuffer[i] < 0)
				{
					if(nHighIndex == nMidIndex)
					{
						// 特殊情况
						--nHighIndex;
					}
					else
					{
						nHighIndex = nMidIndex;
					}
					break;
				}
				else
				{
					// 单个字符匹配
				}
			}
			if(0 == pszExportName[i])
			{
				// 完全匹配
				bMatch = TRUE;
				break;
			}
		}
		if(!bMatch)
		{
			break;
		}

		WORD wOrdinal = ((WORD*)(pDirectory->AddressOfNameOrdinals + ulImageBase))[nMidIndex];
		KdPrint(("Ordinal: %d, NumberOfFunctions: %d.\n", wOrdinal, pDirectory->NumberOfFunctions));
		if(wOrdinal >= pDirectory->NumberOfFunctions)
		{
			break;
		}

		ULONG ulAddressOfFunctions = pDirectory->AddressOfFunctions + ulImageBase;
		*pulOrgFuncRVA = ((ULONG*)ulAddressOfFunctions)[wOrdinal];
		ulRet = *pulOrgFuncRVA + ulImageBase;

		if(ulHookFunc != 0)
		{
			PageProtectOff();
			InterlockedExchange(&((LONG*)ulAddressOfFunctions)[wOrdinal], ulHookFunc - ulImageBase);
			PageProtectOn();
		}
	} while (0);
	return ulRet;
}

//////////////////////////////////////////////////////////////////////////
// GetNtoskrnlExportNameAddress
DWORD GetNtoskrnlExportNameAddress(ANSI_STRING* pastrExportName, DWORD* pdwRVA)
{
	DWORD dwAddr = 0;
	if(g_dwNtoskrnlImageBase != 0 || GetModuleInfo(NULL, &g_dwNtoskrnlImageBase, &g_dwNtoskrnlImageSize))
	{
		dwAddr = EATHook(g_dwNtoskrnlImageBase, pastrExportName, 0, pdwRVA);
	}
	return dwAddr;
}
