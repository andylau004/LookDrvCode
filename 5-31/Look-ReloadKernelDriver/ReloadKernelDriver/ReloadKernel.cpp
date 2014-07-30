#include "ReloadKernel.h"
#include "KernelInternal.h"
#include <ntimage.h>

#define INVALID_HANDLE_VALUE ((HANDLE)-1)

PSERVICE_DESCRIPTOR_TABLE g_pNewSSDT = NULL;

// 获取kernel模块的信息
NTSTATUS GetKernelModuleInfo(PSYSTEM_MODULE_INFORMATION pSysModInfo)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PSYSTEM_MODULE_INFO_LIST pSysModInfoList = NULL;
	ULONG ulLength = 0;

	if(NULL == pSysModInfo)
	{
		return STATUS_INVALID_PARAMETER;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, pSysModInfoList, ulLength, &ulLength);
	if(status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return STATUS_UNSUCCESSFUL;
	}

	pSysModInfoList = (PSYSTEM_MODULE_INFO_LIST)ExAllocatePool(NonPagedPool, ulLength);
	if(NULL == pSysModInfoList)
	{
		return STATUS_UNSUCCESSFUL;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, pSysModInfoList, ulLength, &ulLength);
	if(!NT_SUCCESS(status))
	{
		ExFreePool(pSysModInfoList);
		return STATUS_UNSUCCESSFUL;
	}

	RtlCopyMemory(pSysModInfo, &(pSysModInfoList->smi[0]), sizeof(SYSTEM_MODULE_INFORMATION));	// ntoskrnl.exe/ntkrnlpa.exe等为系统加载的第一个模块
	ExFreePool(pSysModInfoList);
	KdPrint(("GetKernelModuleInfo ImageName: %s, Base: 0x%08x, Size: 0x%08x\n", pSysModInfo->ImageName, pSysModInfo->Base, pSysModInfo->Size));
	// ImageName: \WINDOWS\system32\ntkrnlpa.exe
	return STATUS_SUCCESS;
}

NTSTATUS LoadPe(const CHAR* pFilePath, PBYTE* ImageBase, DWORD* ImageSize)
{
	ANSI_STRING asFilePath = {0};
	UNICODE_STRING usFilePath = {0};
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES attrs = {0};
	HANDLE hFile = INVALID_HANDLE_VALUE;
	IO_STATUS_BLOCK isb = {0};
	LARGE_INTEGER liFileOffset = {0};
	IMAGE_DOS_HEADER DosHeader = {0};
	IMAGE_NT_HEADERS NtHeaders = {0};
	PBYTE pImageBuffer = NULL;
	PIMAGE_SECTION_HEADER pSectionHeaders = NULL;

	if(NULL == pFilePath || NULL == ImageBase || NULL == ImageSize)
	{
		return STATUS_INVALID_PARAMETER;
	}

	RtlInitAnsiString(&asFilePath, pFilePath);
	status = RtlAnsiStringToUnicodeString(&usFilePath, &asFilePath, TRUE);
	if(!NT_SUCCESS(status))
	{
		return STATUS_UNSUCCESSFUL;
	}

	InitializeObjectAttributes(&attrs, &usFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, NULL);
	status = ZwCreateFile(
		&hFile, 
		FILE_READ_DATA, 
		&attrs, 
		&isb, 
		NULL, 
		FILE_ATTRIBUTE_NORMAL, 
		FILE_SHARE_READ, 
		FILE_OPEN, 
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 
		NULL, 
		0);
	if(!NT_SUCCESS(status))
	{
		RtlFreeUnicodeString(&usFilePath);
		return STATUS_UNSUCCESSFUL;
	}

	status = ZwReadFile(
		hFile, 
		NULL, 
		NULL, 
		NULL, 
		&isb, 
		(PVOID)&DosHeader, 
		sizeof(DosHeader), 
		&liFileOffset, 
		NULL);
	if(!NT_SUCCESS(status) || DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		ZwClose(hFile);
		RtlFreeUnicodeString(&usFilePath);
		return STATUS_UNSUCCESSFUL;
	}

	liFileOffset.LowPart = DosHeader.e_lfanew;
	status = ZwReadFile(
		hFile, 
		NULL, 
		NULL, 
		NULL, 
		&isb, 
		(PVOID)&NtHeaders, 
		sizeof(NtHeaders), 
		&liFileOffset, 
		NULL);
	if(!NT_SUCCESS(status) || NtHeaders.Signature != IMAGE_NT_SIGNATURE)
	{
		ZwClose(hFile);
		RtlFreeUnicodeString(&usFilePath);
		return STATUS_UNSUCCESSFUL;
	}

	pSectionHeaders = (PIMAGE_SECTION_HEADER)ExAllocatePool(NonPagedPool, NtHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
	pImageBuffer = (PBYTE)ExAllocatePool(NonPagedPool, NtHeaders.OptionalHeader.SizeOfImage);	// 可选头中的SizeOfImage是内存对齐后的镜像大小
	if(NULL == pSectionHeaders || NULL == pImageBuffer)
	{
		if(pSectionHeaders != NULL)
		{
			ExFreePool(pSectionHeaders);
		}
		if(pImageBuffer != NULL)
		{
			ExFreePool(pImageBuffer);
		}
		ZwClose(hFile);
		RtlFreeUnicodeString(&usFilePath);
		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(pImageBuffer, NtHeaders.OptionalHeader.SizeOfImage);
	liFileOffset.LowPart = DosHeader.e_lfanew + sizeof(NtHeaders);
	status = ZwReadFile(
		hFile, 
		NULL, 
		NULL, 
		NULL, 
		&isb, 
		(PVOID)pSectionHeaders, 
		NtHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), 
		&liFileOffset, 
		NULL);
	if(!NT_SUCCESS(status))
	{
		ExFreePool(pSectionHeaders);
		ExFreePool(pImageBuffer);
		ZwClose(hFile);
		RtlFreeUnicodeString(&usFilePath);
		return STATUS_UNSUCCESSFUL;
	}

	for(int i = 0; i < NtHeaders.FileHeader.NumberOfSections; ++ i)
	{
		KdPrint(("LoadPe pImageBuffer=0x%08x, VirtualAddress=0x%08x, PointerToRawData=0x%08x, SizeOfRawData=0x%08x\n", 
			pImageBuffer, pSectionHeaders[i].VirtualAddress, pSectionHeaders[i].PointerToRawData, pSectionHeaders[i].SizeOfRawData));
		liFileOffset.LowPart = pSectionHeaders[i].PointerToRawData;		// 该节在文件中的偏移
		status = ZwReadFile(
			hFile, 
			NULL, 
			NULL, 
			NULL, 
			&isb, 
			(PVOID)(pImageBuffer + pSectionHeaders[i].VirtualAddress),	// 根据RVA计算出VA 
			pSectionHeaders[i].SizeOfRawData,							// 以文件对齐大小512字节对齐后的节大小 
			&liFileOffset, 
			NULL);
		if(!NT_SUCCESS(status))
		{
			ExFreePool(pSectionHeaders);
			ExFreePool(pImageBuffer);
			ZwClose(hFile);
			RtlFreeUnicodeString(&usFilePath);
			return STATUS_UNSUCCESSFUL;
		}
	}

	liFileOffset.LowPart = 0;
	status = ZwReadFile(
		hFile, 
		NULL, 
		NULL, 
		NULL, 
		&isb, 
		(PVOID)pImageBuffer,
		NtHeaders.OptionalHeader.SizeOfHeaders,
		&liFileOffset, 
		NULL);
	if(!NT_SUCCESS(status))
	{
		ExFreePool(pSectionHeaders);
		ExFreePool(pImageBuffer);
		ZwClose(hFile);
		RtlFreeUnicodeString(&usFilePath);
		return STATUS_UNSUCCESSFUL;
	}

	*ImageBase = pImageBuffer;
	*ImageSize = NtHeaders.OptionalHeader.SizeOfImage;
	ExFreePool(pSectionHeaders);
	ZwClose(hFile);
	RtlFreeUnicodeString(&usFilePath);
	return STATUS_SUCCESS;
}

NTSTATUS FixBaseRelocation(PBYTE NewImageBase, PBYTE OldImageBase)
{
	if(NULL == NewImageBase || NULL == OldImageBase)
	{
		return STATUS_INVALID_PARAMETER;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)NewImageBase;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(NewImageBase + pDosHeader->e_lfanew);
	int nDiff = (DWORD)OldImageBase - pNtHeaders->OptionalHeader.ImageBase;											// 计算出原来的模块基址与编译时预设的模块基址的差, 
																													// 后面通过它将新的模块中的重定位项定位到原来的模块中去
	PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)(NewImageBase + 
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD dwBaseRelocSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	while(dwBaseRelocSize > 0)
	{
		DWORD TypeOffsetNumber = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);		// TypeOffset在IMAGE_BASE_RELOCATION之后
		if(TypeOffsetNumber > 0)
		{
			USHORT* pTypeOffset = (USHORT*)((DWORD)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));
			for(int i = 0; i < TypeOffsetNumber; ++i)
			{
				if(pTypeOffset[i] && (pTypeOffset[i] >> 12) == IMAGE_REL_BASED_HIGHLOW)								// 基址重定位项中高4位为3才需要重定位
				{
					DWORD dwAddress = (DWORD)NewImageBase + pBaseReloc->VirtualAddress + (pTypeOffset[i] & 0x0fff);	// 该项的VA
					DWORD dwValue = *(DWORD*)dwAddress;																// 该项的值
					*(DWORD*)dwAddress = dwValue + nDiff;															// 重定向到原来模块中对应的位置
				}
			}
		}
		dwBaseRelocSize -= pBaseReloc->SizeOfBlock;	// 先要减掉才能调整pBaseReloc的位置
		pBaseReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseReloc + pBaseReloc->SizeOfBlock);
	}
	return STATUS_SUCCESS;
}

NTSTATUS FixSSDT(PBYTE NewImageBase, PBYTE OldImageBase, PSERVICE_DESCRIPTOR_TABLE* NewSSDT)
{
	if(NULL == NewImageBase || NULL == OldImageBase || NULL == NewSSDT)
	{
		return STATUS_INVALID_PARAMETER;
	}

	int nDiff = (int)(NewImageBase - OldImageBase);	// 新老模块基址的差值
	PSERVICE_DESCRIPTOR_TABLE pNewSSDT = (PSERVICE_DESCRIPTOR_TABLE)((DWORD)KeServiceDescriptorTable + nDiff);	// 新模块中的SSDT
	pNewSSDT->Ntoskrnl.Limit = KeServiceDescriptorTable->Ntoskrnl.Limit;
	pNewSSDT->Ntoskrnl.Base = (PULONG)((DWORD)(KeServiceDescriptorTable->Ntoskrnl.Base) + nDiff);
	for(int i = 0; i < pNewSSDT->Ntoskrnl.Limit; ++i)
	{
		(DWORD)(pNewSSDT->Ntoskrnl.Base[i]) += nDiff;
	}
	pNewSSDT->Ntoskrnl.Count = (PULONG)((DWORD)(KeServiceDescriptorTable->Ntoskrnl.Count) + nDiff);
	pNewSSDT->Ntoskrnl.Number = (PUCHAR)((DWORD)(KeServiceDescriptorTable->Ntoskrnl.Number) + nDiff);
	RtlCopyMemory(pNewSSDT->Ntoskrnl.Number, KeServiceDescriptorTable->Ntoskrnl.Number, pNewSSDT->Ntoskrnl.Limit);

	*NewSSDT = pNewSSDT;
	return STATUS_SUCCESS;
}

NTSTATUS ReloadKernel()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	SYSTEM_MODULE_INFORMATION SysModInfo = {0};
	PBYTE pImageBase = NULL;
	DWORD dwImageSize = 0;

	KdPrint(("0"));
	status = GetKernelModuleInfo(&SysModInfo);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("1"));
		return STATUS_UNSUCCESSFUL;
	}

	// TODO: 这里省略了获取系统路径的方法, 可以采用如下方法:
	// \KnownDlls目录下的KnownDllPath符号链接其链接目标即为C:\Windows\system32
	CHAR szKernelPath[260] = "\\??\\C:";
	strcat(szKernelPath, SysModInfo.ImageName);	// 使用strcat_s会导致加载驱动失败, 返回STATUS_DRIVER_ENTRYPOINT_NOT_FOUND
	status = LoadPe(szKernelPath, &pImageBase, &dwImageSize);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("2"));
		return STATUS_UNSUCCESSFUL;
	}

	
	status = FixBaseRelocation(pImageBase, SysModInfo.Base);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("3"));
		ExFreePool(pImageBase);
		return STATUS_UNSUCCESSFUL;
	}

	status = FixSSDT(pImageBase, SysModInfo.Base, &g_pNewSSDT);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("4"));
		ExFreePool(pImageBase);
		return STATUS_UNSUCCESSFUL;
	}

	// TODO: 可以抹掉PE头加大检测难度, 节表不能抹掉

	return STATUS_SUCCESS;
}
