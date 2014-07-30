///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2013 - <company name here>
///
/// Original filename: ReloadKernelDriver.cpp
/// Project          : ReloadKernelDriver
/// Date of creation : 2013-09-24
/// Author(s)        : <author name(s)>
///
/// Purpose          : <description>
///
/// Revisions:
///  0000 [2013-09-24] Initial revision.
///
///////////////////////////////////////////////////////////////////////////////

// $Id$

#ifdef __cplusplus
extern "C" {
#endif
#include <ntifs.h>
#include <string.h>
#ifdef __cplusplus
}; // extern "C"
#endif

#include "ReloadKernelDriver.h"
#include "ReloadKernel.h"
#include "Module.h"
#include "SSDT.h"

#ifdef __cplusplus
namespace { // anonymous namespace to limit the scope of this global variable!
#endif
PDRIVER_OBJECT pdoGlobalDrvObj = 0;
#ifdef __cplusplus
}; // anonymous namespace
#endif

NTSTATUS RELOADKERNELDRIVER_DispatchCreateClose(
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

NTSTATUS RELOADKERNELDRIVER_DispatchDeviceControl(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PIRP					Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    switch(irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_RELOADKERNELDRIVER_OPERATION:
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

VOID RELOADKERNELDRIVER_DriverUnload(
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

//http://bbs.pediy.com/showthread.php?t=179255

#define SDT_NAME ("KeServiceDescriptorTable")

#ifdef __cplusplus
extern "C" {
#endif
NTSTATUS DriverEntry(
    IN OUT PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING      RegistryPath
    )
{
	/*
    PDEVICE_OBJECT pdoDeviceObj = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    pdoGlobalDrvObj = DriverObject;

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
    };

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
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = RELOADKERNELDRIVER_DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RELOADKERNELDRIVER_DispatchDeviceControl;
    DriverObject->DriverUnload = RELOADKERNELDRIVER_DriverUnload;

    return STATUS_SUCCESS;
	*/

	KdPrint(("DriverEntry\n"));
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	pdoGlobalDrvObj = DriverObject;
	DriverObject->DriverUnload = RELOADKERNELDRIVER_DriverUnload;
	status = ReloadKernel();
	if(NT_SUCCESS(status))
	{
		ANSI_STRING astrSDT;
		RtlInitAnsiString(&astrSDT, SDT_NAME);
		DWORD dwSDT_RVA = 0;
		g_dwSDTAddress = GetNtoskrnlExportNameAddress(&astrSDT, &dwSDT_RVA);
		if(g_dwSDTAddress != 0 && 
			(g_dwServiceLimit = ((SERVICE_DESCRIPTOR_TABLE*)g_dwSDTAddress)->ServiceLimit) != 0 && 
			(g_pvServiceTable = ((SERVICE_DESCRIPTOR_TABLE*)g_dwSDTAddress)->ServiceTable) != NULL)
		{
			HookKiFastCallEntry();
		}
	}
	return status;
}
#ifdef __cplusplus
}; // extern "C"
#endif
