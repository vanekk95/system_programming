#pragma once

#include "for_main.h"
#include "ManagerProcMemory.h"

int waitGetExitCodeAndCloseHandle(HANDLE hThread, LPDWORD pRetVal) {
	DWORD ret;
	if (pRetVal == NULL)
		pRetVal = &ret;
	if (WaitForSingleObject(hThread, INFINITE) == 0xFFFFFFFF)
		error_exit("WaitForSingleObject[mem_for_simple_code]", 1);

	if (!GetExitCodeThread(hThread, pRetVal))
		error_exit("GetExitCodeThread[LoadLibraryA]", 1);

	if (!CloseHandle(hThread))
		error_exit("CloseHandle[LoadLibraryA]", 1);

	return 0;
}

void * executionRemoteThread(PROCESS_INFORMATION pi, unsigned char *byte_code, SIZE_T size_byte_code) {
	ManagerProcMemory procMemory(pi.hProcess);

	void *remote_byte_code = procMemory.alloc(size_byte_code);
	if (!remote_byte_code)
		error_exit("VirtualAllocEx", NULL);

	if (procMemory.write(remote_byte_code, byte_code, size_byte_code))
		error_exit("WriteProcessMemory", NULL);

	void *for_ret_val = procMemory.alloc(sizeof(void *));
	if (!for_ret_val)
		error_exit("VirualAllocEx", NULL);

	HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_byte_code, for_ret_val, 0, NULL);
	if (!hThread)
		error_exit("CreateRemoteThread", NULL);

	void *ret_val = NULL;

	if (waitGetExitCodeAndCloseHandle(hThread, NULL))
		error_exit("waitGetExitCodeAndCloseHandle", NULL);

	if (procMemory.read(for_ret_val, &ret_val, sizeof(void *)))
		error_exit("readProcessMemory", NULL);

	return ret_val;
}
