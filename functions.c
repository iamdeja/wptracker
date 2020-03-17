#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "extern.h"

// Link external libraries
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

// Retreive the amount of spawned handles by the PID
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

// Print the process name from a PID
void printProcessName(DWORD processID)
{
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

	// Get a handle to the process.

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);

	// Get the process name.

	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
			&cbNeeded))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName,
				sizeof(szProcessName) / sizeof(TCHAR));
		}
	}

	// Print the process name and identifier.

	_tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);

	// Release the handle to the process.
	if (!hProcess)
	{
		printf("Something went wrong.");
		err_code = NULLPTR;
		return;
	}

	CloseHandle(hProcess);
}

// Validates if the input contains a path and extension
int validateInput(TCHAR* input, int* len)
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

void queryHandles(DWORD processID)
{
	// NT function imports
	_NtQuerySystemInformation NtQuerySystemInformation =
		(_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle;

	// Check for system processes
	if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_VM_READ, FALSE, processID))) return;

	/*
	If the process isn't a system process, its handle is retrieved.
	After usage, or upon return, this handle will need to be closed
	in order to avoid memory leaks.
	*/

	// Sets up the unit storing handle information.
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

	// If space couldn't be allocated for the info unit.
	if (!handleInfo)
	{
		CloseHandle(processHandle);
		return;
	}

	// NtQuerySystemInformation won't give us the correct buffer size,
	//  so we guess by doubling the buffer size
	while ((status = NtQuerySystemInformation(
		SystemHandleInformation,
		handleInfo,
		handleInfoSize,
		NULL
	)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		PSYSTEM_HANDLE_INFORMATION tempHandle = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
		// If space couldn't be reallocated for the info unit.
		if (!tempHandle)
		{
			CloseHandle(processHandle);
			return;
		}
		handleInfo = tempHandle;
	}

	// NtQuerySystemInformation workaround for STATUS_INFO_LENGTH_MISMATCH
	if (!NT_SUCCESS(status)) {
		printf("NtQuerySystemInformation failed!\n");
		free(handleInfo);
		CloseHandle(processHandle);
		return;
	}

	iterateOverHandles(processHandle, handleInfo, processID);

	free(handleInfo);
	CloseHandle(processHandle);
}

void iterateOverHandles(HANDLE processHandle, PSYSTEM_HANDLE_INFORMATION handleInfo, DWORD processID)
{
	_NtDuplicateObject NtDuplicateObject =
		(_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
	_NtQueryObject NtQueryObject =
		(_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");

	unsigned int i;
	for (i = 0; i < handleInfo->HandleCount; i++) {
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength = 0;

		// Check handle against PID
		if (handle.ProcessId != processID)
			continue;

		/* Skip handles with the following access codes as the next call
		   to NtDuplicateObject() or NtQueryObject() might hang forever. */
		if ((handle.GrantedAccess == 0x0012019f)
			|| (handle.GrantedAccess == 0x001a019f)
			|| (handle.GrantedAccess == 0x00120189)
			|| (handle.GrantedAccess == 0x00100000)) {
			continue;
		}

		// Duplicate the handle to allow for querying
		if (!DuplicateHandle(
			processHandle,
			(HANDLE)handle.Handle,
			GetCurrentProcess(),
			&dupHandle,
			0,
			0,
			0
		)) continue;

		// Break on pipe handles
		if (GetFileType(dupHandle) == FILE_TYPE_PIPE)
		{
			CloseHandle(dupHandle);
			return;
		}

		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);

		// If the memory allocation fails.
		if (!objectTypeInfo)
		{
			CloseHandle(dupHandle);
			return;
		}

		// Query the object type.
		PWSTR fileType = TEXT("File");
		NTSTATUS tempObjState = NtQueryObject(
			dupHandle,
			ObjectTypeInformation,
			objectTypeInfo,
			0x1000,
			NULL
		);
		if (!NT_SUCCESS(tempObjState)) {
			printf("[%#x] Error!\n", handle.Handle);
			free(objectTypeInfo);
			CloseHandle(dupHandle);
			continue;
		}
		else if (_tcsicmp(objectTypeInfo->Name.Buffer, fileType) != 0)
		{
			free(objectTypeInfo);
			CloseHandle(dupHandle);
			continue;
		}

		objectNameInfo = malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(
			dupHandle,
			ObjectNameInformation,
			objectNameInfo,
			0x1000,
			&returnLength
		))) {
			// Reallocate the buffer and try again.
			PVOID tempNameInfo = realloc(objectNameInfo, returnLength);
			if (!tempNameInfo)
			{
				free(objectTypeInfo);
				CloseHandle(dupHandle);
				printf("Memory allocation failed.");
				err_code = MEMFL;
				return;
			}
			objectNameInfo = tempNameInfo;
			if (!NT_SUCCESS(NtQueryObject(
				dupHandle,
				ObjectNameInformation,
				objectNameInfo,
				returnLength,
				NULL
			))) {
				// We have the type name, so just display that.
				printf(
					"[%#x] %.*S: (could not get name)\n",
					handle.Handle,
					objectTypeInfo->Name.Length / 2,
					objectTypeInfo->Name.Buffer
				);

				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
				continue;
			}
		}
		if (!objectNameInfo)
		{
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			err_code = NULLPTR;
			return;
		}

		// Cast our buffer into an UNICODE_STRING.
		objectName = *(PUNICODE_STRING)objectNameInfo;

		PWSTR tocheck = TEXT("\\Device\\HarddiskVolume3\\Program Files (x86)\\Gyazo\\Gyazo.Messaging.dll");
		if (_tcsicmp(objectName.Buffer, tocheck) == 0)
		{
			printProcessName(processID);
		}
		//// Print the information!
		//if (objectName.Length)
		//{
		//	// The object has a name.
		//	printf(
		//		"[%#x]: %.*S\n",
		//		handle.Handle,
		//		objectName.Length / 2,
		//		objectName.Buffer
		//	);
		//}
		//else {
		//	// Print something else.
		//	printf(
		//		"[%#x] %.*S: (unnamed)\n",
		//		handle.Handle,
		//		objectTypeInfo->Name.Length / 2,
		//		objectTypeInfo->Name.Buffer
		//	);
		//}

		free(objectTypeInfo);
		free(objectNameInfo);
		CloseHandle(dupHandle);
	}
}