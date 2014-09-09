#include <fltKernel.h>
#include <wdm.h>
#include <ntddk.h>
#include <ntifs.h>
#include <ntstrsafe.h>
#include <Ntddk.h>

/*
	Steps:

	1. Collect information
	2. Attach to the process
	3. Allocate enough memory for our function
	4. Write our function in the allocated memory
	5. Hook a commonly used function
	6. Unload
*/

// Structures
typedef struct
{
	char DllPathway [250];
	WCHAR wDllPathway [250];
	DWORD dllEntrypoint;
	SIZE_T dllSize;
} DLLSTRUCT;
//

// Library Structures
DLLSTRUCT MainLibrary;
DLLSTRUCT InjecTORLib;

// Debugging functions
NTSTATUS ntStatus;
int Check = 0;

// Type definitions
typedef BOOLEAN BOOL;

// Definitions
#define true 1
#define false 0

// Target
HANDLE hTarget;
CLIENT_ID clientId;
OBJECT_ATTRIBUTES objAttributes;

// Sleep
LARGE_INTEGER SleepVal;

// Lengths of specific strings in the settings.
SIZE_T szFile;
SIZE_T szMainDir;
SIZE_T dirLength;

// Handles to files.
HANDLE hCurrentDir = NULL;
HANDLE hGreenlight = NULL;
HANDLE hSettings = NULL;
HANDLE hInjecTOR = NULL;

// Library name and pathway.
char MainDir [250];

// 'MainLibrary' Variables.
char DllName [250];
char DllPathway [250];

// 'InjecTORLib' Variables.
char InjecTOR [] = "InjecTOR.dll";
char InjecTORPath [250];

// 'PsSetLoadImageNotifyRoutine' Variables.
char moddedPath [250];
char moddedDll [250];
WCHAR wDllPathway [250];
WCHAR wInjecTOR [250];

// Dll Memory
DWORD dllEntrypoint;
SIZE_T dllLength;

// Signature
BOOL FoundFirst = FALSE;
BOOL Signatures = FALSE;

// Variables for attaching
PEPROCESS  targetProcess;
KAPC_STATE apcState;

// Allocation size variable
SIZE_T szAllocation = 5;

// Variables for allocation (void*)
PVOID funcEntrypoint;
PVOID pOriginalBytes;
PVOID pDllPath;
PVOID lpProtect;
PVOID lpLoadLib;
PVOID lpCreateThread;
PVOID lpVirtualProtect;
PVOID lpTargetFunc;
PVOID OldProtect;
PVOID lpDllPath;
PVOID Dummy;

// Variables for allocation (dword)
DWORD pLoadLibraryA;
DWORD pCreateThread;
DWORD pSleep;
DWORD pVirtualProtect;
DWORD dwProcessId;
DWORD DllSize;

// Memory protection
ULONG OldProtection;

// User processor information
BOOL Go8;		 // Windows 8 32 Bit 
BOOL processor;

// Multibyte to Unicode size
ULONG UnicodeToWrite;

// UNICODE_STRING Variables
UNICODE_STRING uTestFunc;  

// Addresses to kernel-mode functions
VOID* lpTestFunc;
VOID* lpTestFunc2;

// Settings information
char Characters [250];
char cProcessID [10];
char cCreateThread [10];
char cLoadLibrary  [10];
char cSleep        [10];
char cVirtualProtect [10];
char cDllSize [10];
char greenlight [10];
char injector [8];

// Variables for memory comparisons
unsigned char comparison [5];
unsigned char entrypoint [3];
unsigned char hook       [5];
unsigned char FuncBytes  [150];

// ZwProtectVirtualMemory
typedef NTSTATUS (__stdcall *ZWPROTECTMEM ) ( IN HANDLE ProcessHandle, IN PVOID * BaseAddress, IN SIZE_T * NumberOfBytesToProtect, 
											  IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection ); 

ZWPROTECTMEM ZwProtectVirtualMemory = NULL;

// Loop variables
SIZE_T loopNum;
int powNum;

// Other
LARGE_INTEGER largeInt;
IO_STATUS_BLOCK status;

// Locate ZwProtectVirtualMemory 
VOID* LocateProtect32 ( VOID* ZwPulseEvent )
{
	// Make a copy of lea edx, [esp+04]
	memcpy ( &comparison, (void*) ( (unsigned int) ZwPulseEvent + 0x05 ), 5 );

	if ( !Go8 )
	{
		// Locate the previous lea edx, [esp+04]
		for ( loopNum = 0; loopNum < 40; loopNum ++ )
			if ( !memcmp ( (void*) ( (unsigned int) ZwPulseEvent - loopNum ), &comparison, 5 ) )
				break;

		return ( (void*) ( (unsigned int) ZwPulseEvent - loopNum - 0x05 ) );
	}
	else
	{
		// Locate the next lea edx, [esp+04]
		for ( loopNum = 0; loopNum < 40; loopNum ++ )
			if ( !memcmp ( (void*) ( (unsigned int) ZwPulseEvent + 0x9 + loopNum ), &comparison, 5 ) )
				break;

		return ( (void*) ( (unsigned int) ZwPulseEvent + 0x9 + loopNum - 0x05 ) );
	}
}
VOID* LocateProtect64 ( VOID* ZwQuerySection )
{
	// Make a copy of ZwQuerySection
	memcpy ( &entrypoint, (void*) ZwQuerySection, 3 );

	// Scan for previous instance
	for ( loopNum = 0; loopNum < 40; loopNum ++ )
		if ( !memcmp ( &entrypoint, (void*) ( (unsigned __int64) ZwQuerySection - loopNum - 0x03 ), 3 ) )
			break;

	// Return
	return (void*) ( (unsigned __int64) ZwQuerySection - loopNum - 0x03 );
}
//

// Memory Functions
int  cmpMemory ( void* blockOne, void* blockTwo, size_t szComparison )
{
	__try
	{
		return memcmp ( blockOne, blockTwo, szComparison );
	}
	__except ( true )
	{
		return 1;
	}
}
void cpyMemory ( void* destination, void* source, size_t szCopy )
{
	__try
	{
		memcpy ( destination, source, szCopy );
	}
	__except ( true )
	{
		return;
	}
}
//

// Misc
UNICODE_STRING InitializeText ( PCWSTR Text )
{
	UNICODE_STRING uString;
	RtlInitUnicodeString ( &uString, Text );
	return uString;
}
DWORD          Power           ( DWORD Value, int Exponent )
{
	DWORD dwNewVal = 1;

	for ( powNum = 0; powNum < Exponent; powNum ++ )
	{
		dwNewVal *= Value;
	}

	return dwNewVal;
}
DWORD          ToDwordFromChar ( char* Text )
{
	int   number  = 0;
	DWORD decimal = 0;

	for ( loopNum = 0; loopNum < strlen ( Text ); loopNum ++ )
	{
		if ( ( Text [loopNum] - 48 ) >= 0 && 
			 ( Text [loopNum] - 48 ) <= 9 )
			number = Text [loopNum] - 48;
		else
		{
			if ( Text [loopNum] == 'A' )
				number = 10;
			else if ( Text [loopNum] == 'B' )
				number = 11;
			else if ( Text [loopNum] == 'C' )
				number = 12;
			else if ( Text [loopNum] == 'D' )
				number = 13;
			else if ( Text [loopNum] == 'E' )
				number = 14;
			else if ( Text [loopNum] == 'F' )
				number = 15;
		}
		
		decimal += number * Power ( 16, strlen (Text) - 1 - loopNum );
	}

	return decimal;
}
//

// Open/Read/Write Files
HANDLE OpenFile ( PCWSTR FilePath )
{
	HANDLE hFile;
	IO_STATUS_BLOCK status;
	OBJECT_ATTRIBUTES obj;
	UNICODE_STRING pText;

	// Define object-attributes
	RtlInitUnicodeString ( &pText, FilePath );

	// Initialize the object
	InitializeObjectAttributes ( &obj, &pText, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	// Open the file
	ntStatus = ZwOpenFile ( &hFile, GENERIC_READ | GENERIC_WRITE, &obj, &status, 0, FILE_SYNCHRONOUS_IO_NONALERT );

	if ( ntStatus != STATUS_SUCCESS )
		return 0;

	return hFile;
}
BOOL   ReadFile ( HANDLE hFile, void* Buffer, ULONG Length )
{
	largeInt.HighPart = 0;
	largeInt.LowPart = 0;

	ntStatus = ZwReadFile ( hFile, NULL, NULL, NULL, &status, Buffer, Length, &largeInt, NULL );

	if ( ntStatus != STATUS_SUCCESS )
		return FALSE;
	else
		return TRUE;
}
//

// 'PsSetLoadImageNotifyRoutine' Callback
VOID ViewMappedMemory ( PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo )
{
	if ( ImageInfo->SystemModeImage == 0 )
	{
		if ( wcsstr ( FullImageName->Buffer, MainLibrary.wDllPathway ) != NULL )
		{
			// Grab information
			MainLibrary.dllEntrypoint = (DWORD) ImageInfo->ImageBase;
			MainLibrary.dllSize       = ImageInfo->ImageSize;
		}

		if ( wcsstr ( FullImageName->Buffer, InjecTORLib.wDllPathway ) != NULL )
		{
			// Grab information
			InjecTORLib.dllEntrypoint = (DWORD) ImageInfo->ImageBase;
			InjecTORLib.dllSize       = ImageInfo->ImageSize;
		}
	}
}
//

// Inject
VOID Inject ( DLLSTRUCT* dllStruct )
{
	// Reset information
	dllStruct->dllEntrypoint = 0;
	dllStruct->dllSize = 0;

	// Allocate memory
	szAllocation = 144;
	ZwAllocateVirtualMemory ( NtCurrentProcess (), &funcEntrypoint, 0, &szAllocation, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	szAllocation = 4;
	ZwAllocateVirtualMemory ( NtCurrentProcess (), &lpLoadLib, 0, &szAllocation, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	ZwAllocateVirtualMemory ( NtCurrentProcess (), &lpCreateThread, 0, &szAllocation, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	ZwAllocateVirtualMemory ( NtCurrentProcess (), &lpVirtualProtect, 0, &szAllocation, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	ZwAllocateVirtualMemory ( NtCurrentProcess (), &lpTargetFunc, 0, &szAllocation, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	ZwAllocateVirtualMemory ( NtCurrentProcess (), &OldProtect, 0, &szAllocation, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	ZwAllocateVirtualMemory ( NtCurrentProcess (), &Dummy, 0, &szAllocation, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	szAllocation = strlen ( dllStruct->DllPathway );
	ZwAllocateVirtualMemory ( NtCurrentProcess (), &lpDllPath, 0, &szAllocation, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	// Setup Variables
	memcpy ( lpTargetFunc, &pSleep, 4 );
	memcpy ( lpLoadLib, &pLoadLibraryA, 4 );
	memcpy ( lpCreateThread, &pCreateThread, 4 );
	memcpy ( lpVirtualProtect, &pVirtualProtect, 4 );
	memcpy ( lpDllPath, &dllStruct->DllPathway, strlen ( dllStruct->DllPathway ) );

	// Write the function
	memcpy ( &FuncBytes [0], (void*) "\x55\x53\x52\x54\x51\x50\x54\x56\x57\x6A\x00\x6A\x00", 13 );
	FuncBytes [13] = 0x68;
	*(DWORD*) &FuncBytes [14] = (DWORD) lpDllPath;
	FuncBytes [18] = 0xA1;
	*(DWORD*) &FuncBytes [19] = (DWORD) lpLoadLib;
	memcpy ( &FuncBytes [23], (void*) "\x50\x6A\x00\x6A\x00", 5 ); 
	FuncBytes [28] = 0xFF;
	FuncBytes [29] = 0x15;
	*(DWORD*) &FuncBytes [30] = (DWORD) lpCreateThread;
	FuncBytes [34] = 0x68;
	*(DWORD*) &FuncBytes [35] = (DWORD) OldProtect;
	memcpy ( &FuncBytes [39], (void*) "\x6A\x40\x6A\x05", 4 ); 
	memcpy ( &FuncBytes [43], (void*) "\x8B\x0D", 2 );
	*(DWORD*) &FuncBytes [45] = (DWORD) lpTargetFunc;
	FuncBytes [49] = 0x51;
	FuncBytes [50] = 0xFF;
	FuncBytes [51] = 0x15;
	*(DWORD*) &FuncBytes [52] = (DWORD) lpVirtualProtect;
	FuncBytes [56] = 0x8B;
	FuncBytes [57] = 0x15;
	*(DWORD*) &FuncBytes [58] = (DWORD) lpTargetFunc; 
	memcpy ( &FuncBytes [62], (void*) "\xC6\x02\x8B", 3 ); 
	FuncBytes [65] = 0xA1;
	*(DWORD*) &FuncBytes [66] = (DWORD) lpTargetFunc; 
	memcpy ( &FuncBytes [70], (void*) "\xC6\x40\x01\xFF", 4 ); 
	FuncBytes [74] = 0x8B;
	FuncBytes [75] = 0x0D;
	*(DWORD*) &FuncBytes [76] = (DWORD) lpTargetFunc; 
	memcpy ( &FuncBytes [80], (void*) "\xC6\x40\x02\x55", 4 ); 
	FuncBytes [84] = 0x8B;
	FuncBytes [85] = 0x15;
	*(DWORD*) &FuncBytes [86] = (DWORD) lpTargetFunc;
	memcpy ( &FuncBytes [90], (void*) "\xC6\x42\x03\x8B", 4 ); 
	FuncBytes [94] = 0xA1;
	*(DWORD*) &FuncBytes [95] = (DWORD) lpTargetFunc;
	memcpy ( &FuncBytes [99], (void*) "\xC6\x40\x04\xEC", 4 );	
	FuncBytes [103] = 0x68;
	*(DWORD*) &FuncBytes [104] = (DWORD) Dummy;	
	memcpy ( &FuncBytes [108], (void*) "\x6A\x40\x6A\x05", 4 );
	FuncBytes [112] = 0x8B;
	FuncBytes [113] = 0x0D;
	*(DWORD*) &FuncBytes [114] = (DWORD) lpTargetFunc;
	FuncBytes [118] = 0x51;
	FuncBytes [119] = 0xFF;
	FuncBytes [120] = 0x15;
	*(DWORD*) &FuncBytes [121] = (DWORD) lpVirtualProtect; 
	memcpy ( &FuncBytes [125], (void*) "\x5F\x5E\x5C\x58\x59\x5C\x5A\x5B\x5D", 9 ); 
	FuncBytes [134] = 0xFF;
	FuncBytes [135] = 0x25;
	*(DWORD*) &FuncBytes [136] = (DWORD) lpTargetFunc;
	memcpy ( &FuncBytes [140], "\xCC\xCC\xCC\xCC", 4 );

	// Set the function
	memcpy ( funcEntrypoint, &FuncBytes, 144 );	

	// Write the hook
	hook [0] = 0xE9;
	*(DWORD*) &hook [1] = (DWORD) funcEntrypoint - ( (DWORD) pSleep + 0x05 );
	szAllocation = 5;

	// Set the hook
	__try
	{
		lpProtect = (void*) pSleep;

		// Protect memory
		ntStatus = ZwProtectVirtualMemory ( NtCurrentProcess (), &lpProtect, &szAllocation, PAGE_EXECUTE_READWRITE, &OldProtection );

		// Attempt to write hook
		if ( ntStatus == STATUS_SUCCESS )
			memcpy ( (void*) pSleep, &hook, 5 );
	}
	__except ( 1 )
	{
		DbgPrint ( "Failed to use ZwProtectVirtualMemory ()" );
	}

	// Wait for the DLL to Inject
	SleepVal.QuadPart = -1;

	while ( !dllStruct->dllEntrypoint )
		KeDelayExecutionThread ( KernelMode, FALSE, &SleepVal );

	// Free the allocations
	szAllocation = 144;
	ntStatus = ZwFreeVirtualMemory ( NtCurrentProcess (), &funcEntrypoint, &szAllocation, MEM_RELEASE );
	szAllocation = 4;
	ZwFreeVirtualMemory ( NtCurrentProcess (), &lpLoadLib, &szAllocation, MEM_RELEASE );
	ZwFreeVirtualMemory ( NtCurrentProcess (), &lpCreateThread, &szAllocation, MEM_RELEASE );
	ZwFreeVirtualMemory ( NtCurrentProcess (), &lpVirtualProtect, &szAllocation, MEM_RELEASE );
	ZwFreeVirtualMemory ( NtCurrentProcess (), &lpTargetFunc, &szAllocation, MEM_RELEASE );
	ZwFreeVirtualMemory ( NtCurrentProcess (), &OldProtect, &szAllocation, MEM_RELEASE );
	ZwFreeVirtualMemory ( NtCurrentProcess (), &Dummy, &szAllocation, MEM_RELEASE );
	szAllocation = strlen ( dllStruct->DllPathway );
	ZwFreeVirtualMemory ( NtCurrentProcess (), &lpDllPath, &szAllocation, MEM_RELEASE );

	// Reset variables
	funcEntrypoint = NULL;
	lpLoadLib = NULL;
	lpCreateThread = NULL;
	lpVirtualProtect = NULL;
	lpTargetFunc = NULL;
	OldProtect = NULL;
	Dummy = NULL;
	lpDllPath = NULL;

	return;
}
//

// Wait for the result of InjecTOR.dll
BOOL Wait ()
{
	// Edit 'SleepVal'
	SleepVal.QuadPart = -3;

	// Open the file
	hInjecTOR = OpenFile ( L"\\DosDevices\\C:\\injector.txt" );

	// Check to see if the file exists
	while ( !hInjecTOR )
	{
		hInjecTOR = OpenFile ( L"\\DosDevices\\C:\\injector.txt" );
		KeDelayExecutionThread ( KernelMode, FALSE, &SleepVal );
	}

	if ( !hInjecTOR )
		return FALSE;
	else
	{
		// Empty and read
		RtlZeroMemory ( &injector, 8 );
		ReadFile ( hInjecTOR, injector, 8 );

		// Close the file
		ZwClose ( hInjecTOR );

		// Output
		if ( strstr ( injector, "injector" ) != 0 )
			return TRUE;
		else
			return FALSE;
	}

	return FALSE;
}
//

// Collect information from Usermode Application
BOOL CollectInformation ()
{	
	// Check to see if the file exists
	hGreenlight = OpenFile ( L"\\DosDevices\\C:\\Windows\\greenlight.txt" );

	if ( hGreenlight != 0 )
	{
		// Empty and read
		RtlZeroMemory ( &greenlight, 10 );
		ReadFile ( hGreenlight, greenlight, 10 );

		// Close the file
		ZwClose ( hGreenlight );

		// Check for greenlight
		if ( !strcmp ( greenlight, "greenlight" ) )
		{
			hSettings = OpenFile ( L"\\DosDevices\\C:\\Settings.ini" );

			if ( hSettings != 0 )
			{
				// Empty and read
				RtlZeroMemory ( &Characters, 250 );
				ReadFile ( hSettings, Characters, 250 );

				// Close the file
				ZwClose ( hSettings );

				// Determine the length of the directory
				for ( loopNum = 56; loopNum < 250; loopNum ++ )
					if ( Characters [loopNum] == '\n' )
						break;

				dirLength = loopNum - 56 - 1;

				// Determine the length of the DLL
				for ( loopNum = ( 56 + dirLength + 2 ); loopNum < 250; loopNum ++ )
					if ( Characters [loopNum] == '\n' )
						break;

				dllLength = loopNum - 56 - dirLength - 3;

				// Determine the size of the file
				for ( loopNum = 0; loopNum < 250; loopNum ++ )
					if ( Characters [loopNum] == 'e' )
						if ( Characters [loopNum+1] == 'n' )
							if ( Characters [loopNum+2] == 'd' )
								break;

				szFile = loopNum - 2;

				// Pass out information
				if ( Characters [0] == '1' )
					processor = TRUE;
				else
					processor = FALSE;

				if ( Characters [3] == '1' )
					if ( !processor )
						Go8 = TRUE;
			
				for ( loopNum = 0; loopNum < 8; loopNum ++ )
					cProcessID [loopNum] = Characters [6 + loopNum];

				for ( loopNum = 0; loopNum < 8; loopNum ++ )
					cCreateThread [loopNum] = Characters [16 + loopNum];

				for ( loopNum = 0; loopNum < 8; loopNum ++ )
					cLoadLibrary [loopNum] = Characters [26 + loopNum];

				for ( loopNum = 0; loopNum < 8; loopNum ++ )
					cSleep [loopNum] = Characters [36 + loopNum];

				for ( loopNum = 0; loopNum < 8; loopNum ++ )
					cVirtualProtect [loopNum] = Characters [46 + loopNum];

				for ( loopNum = 56; loopNum < ( 56 + dirLength ); loopNum ++ )
					MainDir [loopNum - 56] = Characters [loopNum];

				for ( loopNum = ( 56 + dirLength + 2 ); loopNum < ( 56 + dirLength + 2 + dllLength ); loopNum ++ )
					DllName [ loopNum - ( 56 + dirLength + 2 ) ] = Characters [ loopNum ];

				for ( loopNum = ( 56 + dirLength + 2 + dllLength + 2 ); loopNum < szFile; loopNum ++ )
					cDllSize [ loopNum - ( 56 + dirLength + 2 + dllLength + 2 ) ] = Characters [ loopNum ];

				szMainDir = strlen ( MainDir );

				// Setup variables
				pLoadLibraryA = ToDwordFromChar ( cLoadLibrary );
				pCreateThread = ToDwordFromChar ( cCreateThread );
				pSleep        = ToDwordFromChar ( cSleep );
				dwProcessId   = ToDwordFromChar ( cProcessID );
				pVirtualProtect = ToDwordFromChar ( cVirtualProtect );
				DllSize		  = ToDwordFromChar ( cDllSize );

				// Setup dll pathway
				memcpy ( &DllPathway, &MainDir, szMainDir );
				memcpy ( &InjecTORPath, &MainDir, szMainDir );
				memcpy ( &DllPathway [szMainDir], &DllName, strlen ( DllName ) );
				memcpy ( &InjecTORPath [szMainDir], &InjecTOR, strlen ( InjecTOR ) );
				memcpy ( &moddedPath, &DllName, strlen ( DllName ) );
				memcpy ( &moddedDll, &InjecTOR, strlen ( InjecTOR ) );

				// Convert multi-byte to unicode
				if ( RtlMultiByteToUnicodeSize ( &UnicodeToWrite, moddedPath, (ULONG) strlen ( moddedPath ) ) == STATUS_SUCCESS )
				{
					if ( RtlMultiByteToUnicodeN ( wDllPathway, UnicodeToWrite, NULL, moddedPath, (ULONG) strlen ( moddedPath ) ) != STATUS_SUCCESS )
						return FALSE;
				}
				else
					return FALSE;

				if ( RtlMultiByteToUnicodeSize ( &UnicodeToWrite, moddedDll, (ULONG) strlen ( moddedDll ) ) == STATUS_SUCCESS )
				{
					if ( RtlMultiByteToUnicodeN ( wInjecTOR, UnicodeToWrite, NULL, moddedDll, (ULONG) strlen ( moddedDll ) ) != STATUS_SUCCESS )
						return FALSE;
				}
				else
					return FALSE;

				// Debug variables
				/*DbgPrint ( "%s", "Printing.." );
				DbgPrint ( "%x", (void*) processor );
				DbgPrint ( "%x", (void*) Go8 );
				DbgPrint ( "%x", (void*) pLoadLibraryA );
				DbgPrint ( "%x", (void*) pCreateThread );
				DbgPrint ( "%x", (void*) pSleep );
				DbgPrint ( "%x", (void*) dwProcessId );
				DbgPrint ( "%x", (void*) pVirtualProtect );
				DbgPrint ( "%d", DllSize );
				DbgPrint ( "%s", MainDir );
				DbgPrint ( "%ws", wDllPathway );
				DbgPrint ( "%ws", wInjecTOR );*/

				return TRUE;
			}
			else
				return FALSE;
		}
		else
			return FALSE;
	}

	return FALSE;
}
//

// Driver Unload
NTSTATUS DriverUnload ( struct _DRIVER_OBJECT *DriverObject )
{
	// Message
	DbgPrint ( "Successfully unloaded!" );

	// Return
	return STATUS_SUCCESS;
}
//

// Driver Entry
NTSTATUS DriverEntry (PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) 
{	
	// Setup 'DriverUnload'
	pDriverObject->DriverUnload = DriverUnload;

	// Collect information from settings
	if ( CollectInformation () )
	{
		// Setup target function based off processor
		if ( processor == TRUE )
			uTestFunc = InitializeText ( L"ZwQuerySection" );
		else
			uTestFunc = InitializeText ( L"ZwPulseEvent" );

		// Locate the kernel mode function
		lpTestFunc = MmGetSystemRoutineAddress ( &uTestFunc );

		if ( processor == TRUE )
			lpTestFunc2 = LocateProtect64 ( lpTestFunc );
		else
			lpTestFunc2 = LocateProtect32 ( lpTestFunc );

		// Set 'ZwProtectVirtualMemory'
		ZwProtectVirtualMemory = (ZWPROTECTMEM) lpTestFunc2;
		
		// Attach to the process
		ntStatus = PsLookupProcessByProcessId ( (HANDLE) dwProcessId, &targetProcess );

		if ( ntStatus != STATUS_SUCCESS )
			DbgPrint ( "%s%x%s", "Error: ", ntStatus, " target." );
		else
		{
			// Open the handle
			ntStatus = ObOpenObjectByPointer ( targetProcess, 0, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hTarget );

			if ( ( hTarget != NULL ) &&
				 ( ntStatus == STATUS_SUCCESS ) )
			{
				// Add the callback
				PsSetLoadImageNotifyRoutine ( ViewMappedMemory );

				// Attach to the process
				KeStackAttachProcess ( targetProcess, &apcState );

				// Setup 'InjecTORLib'
				memcpy ( &InjecTORLib.DllPathway, &InjecTORPath, strlen ( InjecTORPath ) );
				memcpy ( &InjecTORLib.wDllPathway, &wInjecTOR, 250 );

				// Setup 'MainLibrary'
				memcpy ( &MainLibrary.DllPathway, &DllPathway, strlen ( DllPathway ) );
				memcpy ( &MainLibrary.wDllPathway, &wDllPathway, 250 );

				// Inject 'InjecTOR.dll'
				Inject ( &InjecTORLib );
				
				// Inject the main library
				Inject ( &MainLibrary );

				// Wait for the file
				Signatures = Wait ();

				// Unattach from the process
				KeUnstackDetachProcess ( &apcState );

				// Remove the callback
				PsRemoveLoadImageNotifyRoutine ( ViewMappedMemory );

				// Terminate
				__try
				{
					if ( !Signatures )
						ZwTerminateProcess ( hTarget, STATUS_SUCCESS );
				}
				__except ( true )
				{
					DbgPrint ( "%s", "ZwTerminateProcess () Failed." );
				}

				// Close the handle
				ZwClose ( hTarget );
			}
			else
				DbgPrint ( "%s", "Bad handle." );
		}
	}

	DbgPrint ( "%s", "The driver has finished loading." );

	return STATUS_SUCCESS;
}
//