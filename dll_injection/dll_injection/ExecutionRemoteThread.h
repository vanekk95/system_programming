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

struct ThreadInfo {
	unsigned char *code;
	SIZE_T size_code;
	unsigned char *arg;
	SIZE_T size_arg;
	DWORD ret_val;
};


int executionRemoteThread(PROCESS_INFORMATION pi, ThreadInfo *info) {
	ManagerProcMemory procMemory(pi.hProcess);

	void *remote_byte_code = procMemory.alloc(info->size_code);
	if (!remote_byte_code)
		error_exit("VirtualAllocEx", 1);

	if (procMemory.write(remote_byte_code, info->code, info->size_code))
		error_exit("WriteProcessMemory", 1);

	void *remote_arg = procMemory.alloc(info->size_arg);
	if (!remote_arg)
		error_exit("VirualAllocEx", 1);

	if (procMemory.write(remote_arg, info->arg, info->size_arg))
		error_exit("WriteProcessMemory", 1);

	HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_byte_code, remote_arg, 0, NULL);
	if (!hThread)
		error_exit("CreateRemoteThread", 1);

	if (waitGetExitCodeAndCloseHandle(hThread, &info->ret_val))
		error_exit("waitGetExitCodeAndCloseHandle", 1);

	if (procMemory.read(remote_arg, info->arg, info->size_arg))
		error_exit("readProcessMemory", 1);

	if (procMemory.free_mem(remote_byte_code))
		error_exit("VirtualFreeEx", 1);

	if (procMemory.free_mem(remote_arg))
		error_exit("VirtualFreeEx", 1);

	return 0;
}
