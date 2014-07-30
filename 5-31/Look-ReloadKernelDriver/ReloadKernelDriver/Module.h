#pragma once

#include <ntddk.h>
#include <WinDef.h>

extern DWORD g_dwNtoskrnlImageBase;
extern DWORD g_dwNtoskrnlImageSize;

//////////////////////////////////////////////////////////////////////////
// GetModuleInfo
// lpModuleName        [IN OPTION]: 模块名, 为NULL时为ntoskrnl.exe
// pulImageBaseAddress [OUT]:       模块基址
// pulImageSize        [OUT]:       模块大小
// Return:                          是否获取模块信息成功
BOOL GetModuleInfo(char* lpModuleName, ULONG* pulImageBaseAddress, ULONG* pulImageSize);

//////////////////////////////////////////////////////////////////////////
// EATHook
// ulImageBase      [IN]:        镜像基址
// lpastrExportName [IN]:        导出名
// ulHookFunc       [IN OPTION]: 代理地址
// pulOrgFuncRVA    [OUT]:       导出名相对地址
// Return:                       导出名绝对地址
ULONG EATHook(ULONG ulImageBase, ANSI_STRING* lpastrExportName, ULONG ulHookFunc, ULONG* pulOrgFuncRVA);

//////////////////////////////////////////////////////////////////////////
// GetNtoskrnlExportNameAddress
// pastrExportName [IN]:  导出名
// pdwRVA          [OUT]: 导出名相对地址
// Return:                导出名绝对地址
DWORD GetNtoskrnlExportNameAddress(ANSI_STRING* pastrExportName, DWORD* pdwRVA);
