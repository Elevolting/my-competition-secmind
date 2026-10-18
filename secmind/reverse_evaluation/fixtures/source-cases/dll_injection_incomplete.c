VirtualAllocEx(process, 0, size, MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(process, remote, data, size, 0);
