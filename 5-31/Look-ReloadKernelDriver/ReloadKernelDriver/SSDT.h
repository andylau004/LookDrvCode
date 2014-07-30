#pragma once

#include <ntddk.h>
#include <WinDef.h>

#define SDT_ENTRY_MAX_NUM		1000
#define SDT_MAX_NUM				6
#define REAL_SDT_INDEX			0
#define FAKE_SDT_INDEX			1
#define REAL_SHADOW_SDT_INDEX	2
#define FAKE_SHADOW_SDT_INDEX	3
#define FLAG_SDT_INDEX			4
#define FLAG_SHADOW_SDT_INDEX	5

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
	PDWORD ServiceTable;
	PVOID ServiceCounterTable;
	DWORD ServiceLimit;
	PVOID ServiceParamTable;
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

typedef struct _SDT_PROXY_TABLE_ENTRY
{
	DWORD ProxyServiceLimit;
	DWORD ProxyServiceTable[SDT_ENTRY_MAX_NUM];
} SDT_PROXY_TABLE_ENTRY, *PSDT_PROXY_TABLE_ENTRY;

typedef struct _SDT_PROXY_TABLE
{
	SDT_PROXY_TABLE_ENTRY ProxyServiceTableArray[SDT_MAX_NUM];
} SDT_PROXY_TABLE, *PSDT_PROXY_TABLE;

extern DWORD g_dwSDTAddress;
extern PVOID g_pvServiceTable;
extern DWORD g_dwServiceLimit;
extern PSDT_PROXY_TABLE g_pvSDTBuffer;

//////////////////////////////////////////////////////////////////////////
// GetSSDTFunctions
BOOL GetSSDTFunctions();

//////////////////////////////////////////////////////////////////////////
// InitSSDTData
BOOL InitSSDTData();

//////////////////////////////////////////////////////////////////////////
// AllocateSSDTMemory
BOOL AllocateSSDTMemory(DWORD dwServiceLimit);

//////////////////////////////////////////////////////////////////////////
// HookKiFastCallEntry
NTSTATUS HookKiFastCallEntry();

//////////////////////////////////////////////////////////////////////////
// FakeZwSetEvent
NTSTATUS FakeZwSetEvent(HANDLE EventHandle, PLONG PreviousState);

//////////////////////////////////////////////////////////////////////////
// ProxyKiFastCallEntry
VOID ProxyKiFastCallEntry();

//////////////////////////////////////////////////////////////////////////
// ProxyKiFastCallEntryVista
VOID ProxyKiFastCallEntryVista();

//////////////////////////////////////////////////////////////////////////
// FakeKiFastCallEntry
DWORD _stdcall FakeKiFastCallEntry(DWORD dwServiceNumber, DWORD dwServiceAddress, DWORD dwSDTBase);

VOID TestSSDTHook();
