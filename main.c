#include <Windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <psapi.h>
#include <string.h>

#define SUCCESS 0
#define MEMFL 1	// memory allocation failed
#define SNAPFL 2 // snapshot capturing failed
#define SRCHFL 3 // search failed
int err_code = SUCCESS;

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

int validateInput(TCHAR *, int *);
int PrintModules(DWORD);
int retrieveHandleCount(HANDLE);

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
		ULONG SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength);

typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
		HANDLE SourceProcessHandle,
		HANDLE SourceHandle,
		HANDLE TargetProcessHandle,
		PHANDLE TargetHandle,
		ACCESS_MASK DesiredAccess,
		ULONG Attributes,
		ULONG Options);

typedef NTSTATUS(NTAPI *_NtQueryObject)(
		HANDLE ObjectHandle,
		ULONG ObjectInformationClass,
		PVOID ObjectInformation,
		ULONG ObjectInformationLength,
		PULONG ReturnLength);

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE,
		*PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

PVOID GetLibraryProcAddress(LPCSTR LibraryName, LPCSTR ProcName)
{
	HMODULE LibHandle = GetModuleHandleA(LibraryName);
	if (!LibHandle)
	{
		printf("Error getting library.");
		exit(SRCHFL);
	}
	return GetProcAddress(LibHandle, ProcName);
}

int main(void)
{
	// Initialise Buffer to get file path + name
	TCHAR *buffer = (TCHAR *)malloc(MAX_PATH * sizeof(TCHAR));
	if (!buffer || !*buffer)
	{
		printf("Something went wrong. Are you nearing your RAM limit?");
		return MEMFL;
	}

	// Get user input
	printf("Drag and drop a file to this window to get a list of the active processes . . .\n");
	_getts_s(buffer, MAX_PATH);

	unsigned int fNameLen = 0;
	// Faulty input check
	while (!buffer || !validateInput(buffer, &fNameLen))
	{
		printf("Please enter a valid path.\n");
		_getts_s(buffer, MAX_PATH);
	}

	// Get the name of the file
	TCHAR *pStrStart = _tcsrchr(buffer, '\\') + 1;
	if (!pStrStart)
	{
		printf("Something went wrong. Filename retrieval failed.");
		return SRCHFL;
	}

	// Copy the name of the file into a dedicated variable
	TCHAR *pFileName = (TCHAR *)malloc(fNameLen * sizeof(TCHAR) + 1);
	if (pFileName == NULL)
	{
		printf("Something went wrong. Are you nearing your RAM limit?");
		return MEMFL;
	}
	_tcsncpy_s(pFileName, fNameLen + 1, pStrStart, fNameLen);
	pFileName[fNameLen + 1] = '\0';

	// Free the buffer memory
	if (buffer)
	{
		free(buffer);
		buffer = pStrStart = NULL;
	}

	// Take a snapshot of currently executing processes in the system
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("Something went wrong. There was an error in capturing system porcesses.");
		return (SNAPFL);
	}

	// Define the process entries
	PROCESSENTRY32 pe32;

	// Set the size of the structure before use
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap); // clean the snapshot handle
		return SNAPFL;
	}

	DWORD pid = 0;
	// Cycle through Process List
	do
	{
		// Get the appropriate Process PID
		if (_tcsicmp(pe32.szExeFile, pFileName) == 0)
		{
			pid = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	// Clean the snapshot object to prevent resource leakage
	CloseHandle(hProcessSnap);

	if (!pid)
	{
		_tprintf(TEXT("Process '%s' not found. Exiting..."), pFileName);
		return SRCHFL;
	}

	_tprintf(TEXT("List of all modules used by %s (PID %u):\n"), pFileName, pid);
	PrintModules(pid);

	// Retrieve the count of handles used by the process
	int handleCount = retrieveHandleCount(OpenProcess(PROCESS_QUERY_INFORMATION |
																												PROCESS_VM_READ,
																										FALSE, pid));
	if (!handleCount)
		return err_code;
	printf("The number of handles used is: %d.", handleCount);

	// NT function imports
	_NtQuerySystemInformation NtQuerySystemInformation =
			(_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject =
			(_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
	_NtQueryObject NtQueryObject =
			(_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");

	// Stop halt
	//while ('\n' != getchar());
	printf("\nPress any key to close this window . . .\n");
	if (getchar())
		return SUCCESS;
	printf("Program timeout.");
	return SUCCESS;
}

// Validates if the input contains a path and extension
int validateInput(TCHAR *input, int *len)
{
	int dotExists = 0;
	int indexSlash = 0;
	for (int i = _tcslen(input); i > 0; --i)
	{
		if (input[i] == '.')
			dotExists = 1;
		else if (input[i] == '\\')
			indexSlash = i + dotExists;
		if (indexSlash && dotExists)
		{
			*len = _tcslen(input) - indexSlash;
			return 1; // input valid: bool true
		}
	}
	return 0; // input invalid: bool false
}

// Display process modules
int PrintModules(DWORD processID)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	// Get a handle to the process
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
														 PROCESS_VM_READ,
												 FALSE, processID);

	if (NULL == hProcess)
		return 1;

	// Get a list of all modules in the process
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file
			if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				// Print the module name
				_tprintf(TEXT("\t%s (0x%08p)\n"), szModName, hMods[i]);
			}
		}
	}

	// Release the handle to the process
	CloseHandle(hProcess);

	return 0;
}

int retrieveHandleCount(HANDLE hProcess)
{
	PDWORD count = (PDWORD)malloc(sizeof(PDWORD));
	if (!count)
	{
		err_code = MEMFL;
		return 0;
	}
	BOOL opStatus = GetProcessHandleCount(hProcess, count);
	return opStatus ? *count : 0;
}