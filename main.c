#include <Windows.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string.h>

#define SUCCESS 0
#define MEMFL 1  // memory allocation failed
#define SNAPFL 2 // snapshot capturing failed
int err_code = SUCCESS;

int validateInput(char *, int *);
int PrintModules(DWORD);
HANDLE takeSnapShot();

int main(void)
{
    // Initialise Buffer to get file path + name
    char *buffer = (char *)malloc(MAX_PATH);
    if (!buffer || !*buffer)
    {
        printf("Something went wrong. Are you nearing your RAM limit?");
        return MEMFL;
    }

    // Get user input
    printf("Drag and drop a file to this window to get a list of the active processes . . .\n");
    gets_s(buffer, MAX_PATH);

    unsigned int fNameLen = 0;
    // Faulty input check
    while (!buffer || !validateInput(buffer, &fNameLen))
    {
        printf("Please enter a valid path.\n");
        gets_s(buffer, MAX_PATH);
    }

    // Get the name of the file
    char *pStrStart = strrchr(buffer, '\\') + 1;

    // Copy the name of the file into a dedicated variable
    char *pFileName = (char *)malloc(fNameLen + 1);
    if (pFileName == NULL)
    {
        printf("Something went wrong. Filename retrieval failed.");
        return MEMFL;
    }
    strncpy_s(pFileName, fNameLen + 1, pStrStart, fNameLen);
    pFileName[fNameLen + 1] = '\0';

    // Free the buffer memory
    if (buffer)
    {
        free(buffer);
        buffer = pStrStart = NULL;
    }

    printf("%s\n", pFileName);

    HANDLE snap = takeSnapShot();
    if (!snap)
        return SNAPFL;

    // Get the current process
    PROCESSENTRY32W entry; //current process
    entry.dwSize = sizeof(PROCESSENTRY32W);

    // Retrieve process info + handle error
    if (!Process32First(snap, &entry))
    {
        printf("%s", GetLastError());
        // Clean the snapshot object to prevent resource leakage
        CloseHandle(snap);
    }

    int pid = 0;
    printf("%s\n", pFileName);
    // Cycle through Process List
    do
    {
        // ERROR: only lists first char??
        printf("%s\t\t\t%d\n", entry.szExeFile, entry.th32ProcessID);
        if (strcmp(entry.szExeFile, pFileName) == 0)
        {
            pid = entry.th32ProcessID;
        }
    } while (Process32Next(snap, &entry));
    // Clean the snapshot object to prevent resource leakage
    CloseHandle(snap);

    if (pid != 0)
    {
        printf("The process ID of process %s is %d", pFileName, pid);
    }
    else
    {
        printf("Process '%s' not found. Exiting...", pFileName);
    }

    //DWORD aProcesses[1024];
    //DWORD cbNeeded;
    //DWORD cProcesses;
    //unsigned int i;

    //// Get the list of process identifiers

    //if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    //	return 1;

    //// Calculate the number of returned process identifiers
    //cProcesses = cbNeeded / sizeof(DWORD);

    //// Print the names of the modules for each process
    //printf("Process Name Process ID\n");
    //for (i = 0; i < cProcesses; i++)
    //{
    //	PrintModules(aProcesses[i]);
    //}

    // Stop halt
    //while ('\n' != getchar());
    printf("\nPress any key to close this window . . .\n");
    if (getchar())
        return SUCCESS;
    printf("Program timeout.");
    return SUCCESS;
}

// Validates if the input contains a path and extension
int validateInput(char *input, int *len)
{
    int dotExists = 0;
    int indexSlash = 0;
    for (int i = strlen(input); i > 0; --i)
    {
        if (input[i] == '.')
            dotExists = 1;
        else if (input[i] == '\\')
            indexSlash = i + dotExists;
        if (indexSlash && dotExists)
        {
            *len = strlen(input) - indexSlash;
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

    // Print the process identifier
    printf("\nProcess ID: %u\n", processID);

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
                _tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
            }
        }
    }

    // Release the handle to the process
    CloseHandle(hProcess);

    return 0;
}

// Create a snapshot of the currently running processes
HANDLE takeSnapShot(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        printf("%s", GetLastError());
        return NULL;
    }
    return snap;
}