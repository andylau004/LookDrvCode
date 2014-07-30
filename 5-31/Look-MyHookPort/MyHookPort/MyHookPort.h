///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2013 - <company name here>
///
/// Original filename: MyHookPort.h
/// Project          : MyHookPort
/// Date of creation : <see MyHookPort.cpp>
/// Author(s)        : <see MyHookPort.cpp>
///
/// Purpose          : <see MyHookPort.cpp>
///
/// Revisions:         <see MyHookPort.cpp>
///
///////////////////////////////////////////////////////////////////////////////

// $Id$

#ifndef __MYHOOKPORT_H_VERSION__
#define __MYHOOKPORT_H_VERSION__ 100

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif


#include "drvcommon.h"
#include "drvversion.h"

#define DEVICE_NAME			"\\Device\\MYHOOKPORT_DeviceName"
#define SYMLINK_NAME		"\\DosDevices\\MYHOOKPORT_DeviceName"
PRESET_UNICODE_STRING(usDeviceName, DEVICE_NAME);
PRESET_UNICODE_STRING(usSymlinkName, SYMLINK_NAME);

#ifndef FILE_DEVICE_MYHOOKPORT
#define FILE_DEVICE_MYHOOKPORT 0x8000
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

const ULONG IOCTL_MYHOOKPORT_OPERATION = CTL_CODE(FILE_DEVICE_MYHOOKPORT, 0x01, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA);

#define WIN32K_MODULE_NAME ("win32k.sys")
#define SDT_NAME ("KeServiceDescriptorTable")

#endif // __MYHOOKPORT_H_VERSION__
