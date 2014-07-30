///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2013 - <company name here>
///
/// Original filename: MyHookPort.cpp
/// Project          : MyHookPort
/// Date of creation : 2013-04-12
/// Author(s)        : <author name(s)>
///
/// Purpose          : <description>
///
/// Revisions:
///  0000 [2013-04-12] Initial revision.
///
///////////////////////////////////////////////////////////////////////////////

// $Id$

#ifdef __cplusplus
extern "C" {
#endif
#include <ntddk.h>
#include <string.h>
#include <WinDef.h>
#include <ntimage.h>
#ifdef __cplusplus
}; // extern "C"
#endif

#include "MyHookPort.h"
#include "Module.h"
#include "SSDT.h"

#ifdef __cplusplus
namespace { // anonymous namespace to limit the scope of this global variable!
#endif
PDRIVER_OBJECT pdoGlobalDrvObj = 0;
#ifdef __cplusplus
}; // anonymous namespace
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern NTKERNELAPI ULONG InitSafeBootMode;
#ifdef __cplusplus
}; // extern "C"
#endif

//////////////////////////////////////////////////////////////////////////
// InitHookFrame
NTSTATUS InitHookFrame()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DWORD dwWin32kImageBase, dwWin32kImageSize;
	dwWin32kImageBase = dwWin32kImageSize = 0;
	BOOL bRet = GetModuleInfo(WIN32K_MODULE_NAME, &dwWin32kImageBase, &dwWin32kImageSize);
	KdPrint(("[InitHookFrame][GetModuleInfo]Return: %d, Win32k ImageBase: 0x%08X, ImageSize: 0x%08X.\n", bRet, dwWin32kImageBase, dwWin32kImageSize));
	//if(!bRet)
	if(TRUE)
	{
		ANSI_STRING astrSDT;
		RtlInitAnsiString(&astrSDT, SDT_NAME);
		DWORD dwSDT_RVA = 0;
		g_dwSDTAddress = GetNtoskrnlExportNameAddress(&astrSDT, &dwSDT_RVA);
		KdPrint(("[InitHookFrame][GetNtoskrnlExportNameAddress]SDT Address: 0x%08X, RVA: 0x%08X.\n", g_dwSDTAddress, dwSDT_RVA));
		if(g_dwSDTAddress != 0 && 
			MmIsAddressValid((PVOID)g_dwSDTAddress) && 
			InitSSDTData() && 
			(g_dwServiceLimit = ((SERVICE_DESCRIPTOR_TABLE*)g_dwSDTAddress)->ServiceLimit) != 0 && 
			(g_pvServiceTable = ((SERVICE_DESCRIPTOR_TABLE*)g_dwSDTAddress)->ServiceTable) != NULL && 
			AllocateSSDTMemory(g_dwServiceLimit))
		{
			// TODO: 设置g_pvSDTBuffer中的FakeFunction
			HookKiFastCallEntry();
			TestSSDTHook();
			status = STATUS_SUCCESS;
		}
	}
	else
	{

	}
	return status;
}

NTSTATUS MYHOOKPORT_DispatchCreateClose(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PIRP					Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS MYHOOKPORT_DispatchDeviceControl(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PIRP					Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    switch(irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_MYHOOKPORT_OPERATION:
        // status = SomeHandlerFunction(irpSp);
        break;
    default:
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        break;
    }

    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID MYHOOKPORT_DriverUnload(
    IN PDRIVER_OBJECT		DriverObject
    )
{
    PDEVICE_OBJECT pdoNextDeviceObj = pdoGlobalDrvObj->DeviceObject;
    IoDeleteSymbolicLink(&usSymlinkName);

    // Delete all the device objects
    while(pdoNextDeviceObj)
    {
        PDEVICE_OBJECT pdoThisDeviceObj = pdoNextDeviceObj;
        pdoNextDeviceObj = pdoThisDeviceObj->NextDevice;
        IoDeleteDevice(pdoThisDeviceObj);
    }
}

//////////////////////////////////////////////////////////////////////////
// InitDriverOnWin2kOrXP
// Win2k: 5.0
// WinXP: 5.1
NTSTATUS InitDriverOnWin2kOrXP(PDRIVER_OBJECT pDrvObj)
{
	PDEVICE_OBJECT pDevObj = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	do 
	{
		if(NULL == pDrvObj)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		/*
		if(InitSafeBootMode > 0)
		{
			// 安全模式
			break;
		}
		*/

		// Create the device object.
		if(!NT_SUCCESS(status = IoCreateDevice(
			pDrvObj,
			0x10,
			&usDeviceName,
			FILE_DEVICE_UNKNOWN,
			FILE_DEVICE_SECURE_OPEN,
			FALSE,
			&pDevObj
			)))
		{
			// Bail out (implicitly forces the driver to unload).
			break;
		}

		// Now create the respective symbolic link object
		if(!NT_SUCCESS(status = IoCreateSymbolicLink(
			&usSymlinkName,
			&usDeviceName
			)))
		{
			IoDeleteDevice(pDevObj);
			break;
		}

		// NOTE: You need not provide your own implementation for any major function that
		//       you do not want to handle. I have seen code using DDKWizard that left the
		//       *empty* dispatch routines intact. This is not necessary at all!
		pDrvObj->MajorFunction[IRP_MJ_CREATE] =
		pDrvObj->MajorFunction[IRP_MJ_CLOSE] = MYHOOKPORT_DispatchCreateClose;
		pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MYHOOKPORT_DispatchDeviceControl;
		pDrvObj->DriverUnload = MYHOOKPORT_DriverUnload;

		status = InitHookFrame();
	} while (0);
	return status;
}

#ifdef __cplusplus
extern "C" {
#endif
NTSTATUS DriverEntry(
    IN OUT PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING      RegistryPath
    )
{
    PDEVICE_OBJECT pdoDeviceObj = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    pdoGlobalDrvObj = DriverObject;

	ULONG ulMajorVersion, ulMinorVersion, ulBuildNumber;
	ulMajorVersion = ulMinorVersion = ulBuildNumber = 0;
	PsGetVersion(&ulMajorVersion, &ulMinorVersion, &ulBuildNumber, NULL);
	KdPrint(("[DriverEntry][PsGetVersion]MajorVersion=%lu, MinorVersion=%lu, BuildNumber=%lu.\n", ulMajorVersion, ulMinorVersion, ulBuildNumber));

	if(5 == ulMajorVersion)
	{
		if(0 == ulMinorVersion || 1 == ulMinorVersion)
		{
			return InitDriverOnWin2kOrXP(DriverObject);
		}
	}

    // Create the device object.
    if(!NT_SUCCESS(status = IoCreateDevice(
        DriverObject,
        0,
        &usDeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &pdoDeviceObj
        )))
    {
        // Bail out (implicitly forces the driver to unload).
        return status;
    }

    // Now create the respective symbolic link object
    if(!NT_SUCCESS(status = IoCreateSymbolicLink(
        &usSymlinkName,
        &usDeviceName
        )))
    {
        IoDeleteDevice(pdoDeviceObj);
        return status;
    }

    // NOTE: You need not provide your own implementation for any major function that
    //       you do not want to handle. I have seen code using DDKWizard that left the
    //       *empty* dispatch routines intact. This is not necessary at all!
    DriverObject->MajorFunction[IRP_MJ_CREATE] =
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = MYHOOKPORT_DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MYHOOKPORT_DispatchDeviceControl;
    DriverObject->DriverUnload = MYHOOKPORT_DriverUnload;

	/*
	ULONG ulImageBaseAddress = 0;
	ULONG ulImageSize = 0;
	GetModuleInfo("win32k.sys", &ulImageBaseAddress, &ulImageSize);
	KdPrint(("win32k.sys ImageBaseAddress: 0x%08X, ImageSize: 0x%08X.\n", ulImageBaseAddress, ulImageSize));
	ulImageBaseAddress = ulImageSize = 0;
	GetModuleInfo(NULL, &ulImageBaseAddress, &ulImageSize);
	KdPrint(("NULL ImageBaseAddress: 0x%08X, ImageSize: 0x%08X.\n", ulImageBaseAddress, ulImageSize));

	ANSI_STRING astrSDT = {0};
	RtlInitAnsiString(&astrSDT, "KeServiceDescriptorTable");
	ULONG ulOrgFuncRVA = 0;
	ULONG ulOrgFunc = EATHook(ulImageBaseAddress, &astrSDT, 0, &ulOrgFuncRVA);
	KdPrint(("KeServiceDescriptorTable ulOrgFunc: 0x%08X, ulOrgFuncRVA: 0x%08X.\n", ulOrgFunc, ulOrgFuncRVA));
	ANSI_STRING astrZwCreateKey = {0};
	RtlInitAnsiString(&astrZwCreateKey, "ZwCreateKey");
	ulOrgFuncRVA = 0;
	ulOrgFunc = EATHook(ulImageBaseAddress, &astrZwCreateKey, 0, &ulOrgFuncRVA);
	KdPrint(("ZwCreateKey ulOrgFunc: 0x%08X, ulOrgFuncRVA: 0x%08X.\n", ulOrgFunc, ulOrgFuncRVA));
	*/

    return STATUS_SUCCESS;
}
#ifdef __cplusplus
}; // extern "C"
#endif
