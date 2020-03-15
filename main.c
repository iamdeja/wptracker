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
	//// Initialise Buffer to get file path + name
	//TCHAR* buffer = (TCHAR*)malloc(MAX_PATH * sizeof(TCHAR));
	//if (!buffer || !*buffer)
	//{
	//	printf("Something went wrong. Are you nearing your RAM limit?");
	//	return MEMFL;
	//}

	//// Get user input
	//printf("Drag and drop a file to this window to get a list of the active processes . . .\n");
	//_getts_s(buffer, MAX_PATH);

	//unsigned int fNameLen = 0;
	//// Faulty input check
	//while (!buffer || !validateInput(buffer, &fNameLen))
	//{
	//	printf("Please enter a valid path.\n");
	//	_getts_s(buffer, MAX_PATH);
	//}

	//// Get the name of the file
	//TCHAR* pStrStart = _tcsrchr(buffer, '\\') + 1;
	//if (!pStrStart)
	//{
	//	printf("Something went wrong. Filename retrieval failed.");
	//	return SRCHFL;
	//}

	//// Copy the name of the file into a dedicated variable
	//TCHAR* pFileName = (TCHAR*)malloc(fNameLen * sizeof(TCHAR) + 1);
	//if (pFileName == NULL)
	//{
	//	printf("Something went wrong. Are you nearing your RAM limit?");
	//	return MEMFL;
	//}
	//_tcsncpy_s(pFileName, fNameLen + 1, pStrStart, fNameLen);
	//pFileName[fNameLen + 1] = '\0';

	//// Free the buffer memory
	//if (buffer)
	//{
	//	free(buffer);
	//	buffer = pStrStart = NULL;
	//}

	//// Take a snapshot of currently executing processes in the system
	//HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	//if (hProcessSnap == INVALID_HANDLE_VALUE)
	//{
	//	printf("Something went wrong. There was an error in capturing system porcesses.");
	//	return(SNAPFL);
	//}

	//// Define the process entries
	//PROCESSENTRY32 pe32;

	//// Set the size of the structure before use
	//pe32.dwSize = sizeof(PROCESSENTRY32);

	//// Retrieve information about the first process,
	//// and exit if unsuccessful
	//if (!Process32First(hProcessSnap, &pe32))
	//{
	//	CloseHandle(hProcessSnap); // clean the snapshot handle
	//	return SNAPFL;
	//}

	//DWORD pid = 0;
	//// Cycle through Process List
	//do {
	//	// Get the appropriate Process PID
	//	if (_tcsicmp(pe32.szExeFile, pFileName) == 0) {
	//		pid = pe32.th32ProcessID;
	//		queryHandles(pid);
	//		break;
	//	}
	//} while (Process32Next(hProcessSnap, &pe32));
	//// Clean the snapshot object to prevent resource leakage
	//CloseHandle(hProcessSnap);

	//if (!pid) {
	//	_tprintf(TEXT("Process '%s' not found. Exiting..."), pFileName);
	//	return SRCHFL;
	//}

	//_tprintf(TEXT("List of all modules used by %s (PID %u):\n"), pFileName, pid);
	//PrintModules(pid);

	//// Retrieve the count of handles used by the process
	//int handleCount = retrieveHandleCount(OpenProcess(PROCESS_QUERY_INFORMATION |
	//	PROCESS_VM_READ,
	//	FALSE, pid));
	//if (!handleCount)
	//	return err_code;
	//printf("The number of handles used is: %d. The following file handles are in use:\n", handleCount);
	//printProcessName(pid);

	// Get the list of process identifiers.
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 1;
	}

	// Calculate how many process identifiers were returned.

	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process.

	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			printProcessName(aProcesses[i]);
			queryHandles(aProcesses[i]);
		}
	}

	// Stop halt
	//while ('\n' != getchar());
	printf("\nPress any key to close this window . . .\n");
	if (getchar())
		return err_code;
	printf("Program timeout.");
	return err_code;
}

void queryHandles(DWORD processID)
{
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

	for (i = 0; i < handleInfo->HandleCount; i++) {
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;

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

		// Break on pipe handles
		if (GetFileType(handle.Handle) == FILE_TYPE_PIPE)
		{
			free(handleInfo);
			CloseHandle(processHandle);
			return;
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

		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);

		// If the memory allocation fails.
		if (!objectTypeInfo)
		{
			CloseHandle(dupHandle);
			free(handleInfo);
			CloseHandle(processHandle);
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
				free(handleInfo);
				CloseHandle(processHandle);
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
			free(handleInfo);
			CloseHandle(processHandle);
			err_code = NULLPTR;
			return;
		}

		// Cast our buffer into an UNICODE_STRING.
		objectName = *(PUNICODE_STRING)objectNameInfo;

		LPSTR filePath[MAX_PATH];
		//DWORD kek = GetFinalPathNameByHandleA(
		//	dupHandle,
		//	lpszFilePath,
		//	MAX_PATH,
		//	0
		//);
		GetModuleFileNameExA(
			dupHandle,
			NULL,
			filePath,
			MAX_PATH
		);

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
}