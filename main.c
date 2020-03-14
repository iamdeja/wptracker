#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "extern.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(x) ((x) >= 0)
#endif
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

err_code = SUCCESS;

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

int main(void) {
	// Initialise Buffer to get file path + name
	TCHAR* buffer = (TCHAR*)malloc(MAX_PATH * sizeof(TCHAR));
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
	TCHAR* pStrStart = _tcsrchr(buffer, '\\') + 1;
	if (!pStrStart)
	{
		printf("Something went wrong. Filename retrieval failed.");
		return SRCHFL;
	}

	// Copy the name of the file into a dedicated variable
	TCHAR* pFileName = (TCHAR*)malloc(fNameLen * sizeof(TCHAR) + 1);
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
		return(SNAPFL);
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
	do {
		// Get the appropriate Process PID
		if (_tcsicmp(pe32.szExeFile, pFileName) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	// Clean the snapshot object to prevent resource leakage
	CloseHandle(hProcessSnap);

	if (!pid) {
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
	printf("The number of handles used is: %d. The following file handles are in use:\n", handleCount);
	printProcessName(pid);

	// NT function imports
	_NtQuerySystemInformation NtQuerySystemInformation =
		(_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject =
		(_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
	_NtQueryObject NtQueryObject =
		(_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle;
	unsigned int i;

	if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid))) {
		printf("Could not open PID %d! (Don't try to open a system process.)\n", pid);
		return 1;
	}

	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	if (!handleInfo)
	{
		printf("Memory allocation failed.");
		return MEMFL;
	}

	// NtQuerySystemInformation won't give us the correct buffer size,
	//  so we guess by doubling the buffer size.
	while ((status = NtQuerySystemInformation(
		SystemHandleInformation,
		handleInfo,
		handleInfoSize,
		NULL
	)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		PSYSTEM_HANDLE_INFORMATION tempHandle = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
		if (!tempHandle)
		{
			printf("Memory allocation failed.");
			return MEMFL;
		}
		handleInfo = tempHandle;
	}

	// NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
	if (!NT_SUCCESS(status)) {
		printf("NtQuerySystemInformation failed!\n");
		free(handleInfo);
		return 1;
	}

	for (i = 0; i < handleInfo->HandleCount; i++) {
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;

		// Check if this handle belongs to the PID the user specified.
		if (handle.ProcessId != pid)
			continue;

		/* Skip handles with the following access codes as the next call
		   to NtDuplicateObject() or NtQueryObject() might hang forever. */
		if ((handle.GrantedAccess == 0x0012019f)
			|| (handle.GrantedAccess == 0x001a019f)
			|| (handle.GrantedAccess == 0x00120189)
			|| (handle.GrantedAccess == 0x00100000)) {
			continue;
		}

		// Duplicate the handle so we can query it.
		if (!NT_SUCCESS(NtDuplicateObject(
			processHandle,
			(void*)handle.Handle,
			GetCurrentProcess(),
			&dupHandle,
			0,
			0,
			0
		))) {
			//printf("[%#x] Error!\n", handle.Handle);
			continue;
		}

		PWSTR fileType = TEXT("File");
		// Query the object type.
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		NTSTATUS tempObjState = NtQueryObject(
			dupHandle,
			ObjectTypeInformation,
			objectTypeInfo,
			0x1000,
			NULL
		);
		if (!objectTypeInfo) return NULLPTR;
		if (!NT_SUCCESS(tempObjState)) {
			printf("[%#x] Error!\n", handle.Handle);
			CloseHandle(dupHandle);
			continue;
		}
		else if (_tcsicmp(objectTypeInfo->Name.Buffer, fileType) != 0)
		{
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
				printf("Memory allocation failed.");
				return MEMFL;
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
		if (!objectNameInfo) return NULLPTR;

		// Cast our buffer into an UNICODE_STRING.
		objectName = *(PUNICODE_STRING)objectNameInfo;

		// Print the information!
		if (objectName.Length)
		{
			// The object has a name.
			printf(
				"[%#x]: %.*S\n",
				handle.Handle,
				objectName.Length / 2,
				objectName.Buffer
			);
		}
		else {
			// Print something else.
			printf(
				"[%#x] %.*S: (unnamed)\n",
				handle.Handle,
				objectTypeInfo->Name.Length / 2,
				objectTypeInfo->Name.Buffer
			);
		}

		free(objectTypeInfo);
		free(objectNameInfo);
		CloseHandle(dupHandle);
	}

	free(handleInfo);
	CloseHandle(processHandle);

	// Stop halt
	//while ('\n' != getchar());
	printf("\nPress any key to close this window . . .\n");
	if (getchar())
		return err_code;
	printf("Program timeout.");
	return err_code;
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