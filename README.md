# wptracker

Attempt at CLI tool to list, track and manipulate processes used by a file.

Interfacing with the processes is based on Microsoft's Process Status API on [MS DOCS](https://docs.microsoft.com/en-us/windows/win32/psapi/process-status-helper).

The structures used are based on the invaluable list of _NtQuerySystemInformation_ structures documented in exploit-monday's [blog post](http://www.exploit-monday.com/2013/06/undocumented-ntquerysysteminformation.html). More information can be found in Microsoft's documentation on [NtQuerySystemInformation](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation) and [ZwQuerySystemInformation](https://docs.microsoft.com/en-us/windows/win32/sysinfo/zwquerysysteminformation).

Geoff Chappell has resources concerning Kernel level functions on his [website](https://www.geoffchappell.com/studies/windows/km/index.htm). For deeper research, some undocumented functions can be found [here](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FSystem%20Information%2FStructures%2FSYSTEM_PROCESS_INFORMATION.html).

Enumeration logic based on the psutil [source](https://github.com/tamentis/psutil/blob/master/psutil/arch/mswindows/process_handles.c).
