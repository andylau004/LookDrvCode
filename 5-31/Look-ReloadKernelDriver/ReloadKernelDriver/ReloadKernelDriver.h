///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2013 - <company name here>
///
/// Original filename: ReloadKernelDriver.h
/// Project          : ReloadKernelDriver
/// Date of creation : <see ReloadKernelDriver.cpp>
/// Author(s)        : <see ReloadKernelDriver.cpp>
///
/// Purpose          : <see ReloadKernelDriver.cpp>
///
/// Revisions:         <see ReloadKernelDriver.cpp>
///
///////////////////////////////////////////////////////////////////////////////

// $Id$

#ifndef __RELOADKERNELDRIVER_H_VERSION__
#define __RELOADKERNELDRIVER_H_VERSION__ 100

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif


#include "drvcommon.h"
#include "drvversion.h"

#define DEVICE_NAME			"\\Device\\RELOADKERNELDRIVER_DeviceName"
#define SYMLINK_NAME		"\\DosDevices\\RELOADKERNELDRIVER_DeviceName"
PRESET_UNICODE_STRING(usDeviceName, DEVICE_NAME);
PRESET_UNICODE_STRING(usSymlinkName, SYMLINK_NAME);

#ifndef FILE_DEVICE_RELOADKERNELDRIVER
#define FILE_DEVICE_RELOADKERNELDRIVER 0x8000
#endif

// Values defined for "Method"
// METHOD_BUFFERED
// METHOD_IN_DIRECT
// METHOD_OUT_DIRECT
// METHOD_NEITHER
// 
// Values defined for "Access"
// FILE_ANY_ACCESS
// FILE_READ_ACCESS
// FILE_WRITE_ACCESS

const ULONG IOCTL_RELOADKERNELDRIVER_OPERATION = CTL_CODE(FILE_DEVICE_RELOADKERNELDRIVER, 0x01, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA);

#endif // __RELOADKERNELDRIVER_H_VERSION__
