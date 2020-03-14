#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "extern.h"
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