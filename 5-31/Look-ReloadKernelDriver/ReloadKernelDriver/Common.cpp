#include "Common.h"

//////////////////////////////////////////////////////////////////////////
// PageProtectOn
VOID PageProtectOn()
{
	_asm
	{
		sti
		mov eax, cr0
		or  eax, 0x10000
		mov cr0, eax
	}
}

//////////////////////////////////////////////////////////////////////////
// PageProtectOff
VOID PageProtectOff()
{
	_asm
	{
		mov eax, cr0
		and eax, not 0x10000
		mov cr0, eax
		cli
	}
}
