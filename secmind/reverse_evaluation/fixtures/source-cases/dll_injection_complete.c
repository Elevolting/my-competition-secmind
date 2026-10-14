OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
VirtualAllocEx(process, 0, size, MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(process, remote, dll_path, size, 0);
CreateRemoteThread(process, 0, 0, LoadLibraryA, remote, 0, 0);
