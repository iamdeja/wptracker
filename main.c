#include "stdlib.h"
#include "stdio.h"
#include "windows.h"
#include "tchar.h"
#include "psapi.h"
#include "string.h"

void PrintProcessNameAndID(DWORD processID)
{
    // Initialise unknown processes to <unknown>
    // Changes literal to wide literal for the unicode flag
    TCHAR szProcessName[MAX_PATH] = TEXT("<unkown>");


    // In Win32, the HANDLE type is either a pointer in kernel memory
    // or an index into some kernel - internal array.

    // Gets a handle to the process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

    // Get process name
    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
        {
            GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
        }
    }

    // Print process name and identifier
    _tprintf(TEXT("%-30s %5u "), szProcessName, processID);

    //if (CloseHandle(hProcess) != 0)
    if (hProcess == 0)
        printf("\n");
    else
        printf("Process's handle closed succesffuly.\n");
}


void main(void) {
    // Initialise Buffer to get file path + name
    char* buffer = NULL;
    buffer = (char*) calloc(MAX_PATH, sizeof(char));
    if (buffer == NULL)
    {
        printf("Something went wrong. Are you nearing your RAM limit?");
        return;
    }

    // Get user input
    printf("Drag and drop a file to this window to get a list of the active processes...\n");
    gets_s(buffer, MAX_PATH);

    // Empty input check
    while (!buffer)
    {
        printf("Please enter a filename\n");
        gets_s(buffer, MAX_PATH);
    }

    // Get the name of the file
    buffer = strrchr(buffer, '\\') + 1;
    char* pFileExtension = strchr(buffer, '.');
    unsigned int fileNameLength = strlen(buffer) - strlen(pFileExtension);

    // Copy the name of the file into a dedicated variable
    char* pFileName = (char*)calloc(fileNameLength + 1, sizeof(char));
    if (pFileName == NULL)
    {
        printf("Something went wrong. The filename couldn't be retrieved.");
        return;
    }
    strncpy_s(pFileName, fileNameLength + 1, buffer, fileNameLength);

    // Free the buffer memory
    //if (buffer)
    //{
    //    free(buffer);
    //    buffer = NULL;
    //}

    printf("%s\n", pFileName);

    // Get a list of process identifiers
    DWORD aProcesses[1024], cbNeeded, cProcesses;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) return;

    // Calculate the number of returned process identifiers
    cProcesses = cbNeeded / sizeof(DWORD);

    // Print the name and process identifier for each process
    printf("\n");
    printf("Process Name Process ID\n");
    printf("============ ==========\n");
    for (unsigned int i = 0; i < cProcesses; ++i)
    {
        PrintProcessNameAndID(aProcesses[i]);
    }
}