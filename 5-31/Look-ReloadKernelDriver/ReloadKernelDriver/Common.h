#pragma once

#include <ntddk.h>
#include <WinDef.h>

#define TAG 'Ddk '

#ifdef __cplusplus
extern "C" {
#endif
extern NTKERNELAPI ULONG NtBuildNumber;
#ifdef __cplusplus
}; // extern "C"
#endif

//////////////////////////////////////////////////////////////////////////
// PageProtectOn
VOID PageProtectOn();

//////////////////////////////////////////////////////////////////////////
// PageProtectOff
VOID PageProtectOff();
