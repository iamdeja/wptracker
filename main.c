#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "extern.h"

err_code = SUCCESS;

int main(void) {
	// Initialise Buffer to get file path + name
	TCHAR* buffer = (TCHAR*)malloc(MAX_PATH * sizeof(TCHAR));
	if (!buffer || !*buffer)
	{
		printf("Something went wrong. Are you nearing your RAM limit?");
		return MEMFL;
	}

	// Get user input
	printf("Drag and drop a file to this window to get a list of locking processes . . .\n");
	_getts_s(buffer, MAX_PATH);

	unsigned int fNameLen = 0;
	// Faulty input check
	while (!buffer || !validateInput(buffer, &fNameLen))
	{
		printf("Please the full path.\n");
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

	// Get the list of process identifiers.
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 1;
	}

	// Calculate how many process identifiers were returned.

	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name of the locking process:
	printf("The specified file is currently being targeted by the following process(es):\n");

	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
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