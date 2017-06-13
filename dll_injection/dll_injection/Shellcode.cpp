#include "Shellcode.h"
#include "ExecutionRemoteThread.h"


__declspec(noinline)
int myLoadLibrary(for_shellcode_t *info) {
	HMODULE hModule = info->LoadLibrary(info->path_to_my_dll);
	return info->GetLastError();
}

unsigned char byte_code_myLoadLibrary[] = {
	0x53,						// push        rbx
	0x48, 0x83, 0xEC, 0x20,		// sub         rsp,20h
	0x48, 0x89, 0xCB,			// mov         rbx,rcx
	0x48, 0x83, 0xC1, 0x10,		// add         rcx,10h
	0xFF, 0x13,					// call        qword ptr [rbx] 
	0x48, 0x8B, 0x43, 0x08,		// mov         rax,qword ptr [rbx+8] 
	0x48, 0x83, 0xC4, 0x20,		// add         rsp,20h 
	0x5B,						// pop         rbx
	0xFF, 0xE0					// jmp         rax 
};

int executionShellcode(PROCESS_INFORMATION pi, void * baseKernel32) {

	// load my lib
	HMODULE hKernel32 = GetModuleHandle(KERNEL32DLL_NAME);
	if (!hKernel32)
		error_exit("GetModuleHandle", 1);

	printf("kernel32 loc = %p\n", hKernel32);
	printf("kernel32 rem = %p\n", baseKernel32);

	// calculate remote LoadLibrary
	INT64 rvaLoadLibraryA = (unsigned char *)LoadLibraryA - (unsigned char *)hKernel32;
	LoadLibrary_t remoteLoadLibraryA = (LoadLibrary_t)((unsigned char *)baseKernel32 + rvaLoadLibraryA);

	// calculate remote GetLastError
	INT64 rvaGetLastError = (unsigned char *)GetLastError - (unsigned char *)hKernel32;
	GetLastError_t remoteGetLastError = (GetLastError_t)((unsigned char *)baseKernel32 + rvaGetLastError);

	for_shellcode_t info;
	info.GetLastError = remoteGetLastError;
	info.LoadLibrary = remoteLoadLibraryA;
	strncpy(info.path_to_my_dll, DLL_PATH, sizeof(DLL_PATH));

	ThreadInfo thread_info;
	thread_info.code = byte_code_myLoadLibrary;
	thread_info.size_code = sizeof(byte_code_myLoadLibrary);
	thread_info.arg = (unsigned char *)&info;
	thread_info.size_arg = sizeof(info);

	if (executionRemoteThread(pi, &thread_info))
		error_exit("executionRemoteThread", 1);

	if (thread_info.ret_val) {
		printf("LoadLibraryA return error: %d\n", thread_info.ret_val);
		return 1;
	}

	return 0;
}
