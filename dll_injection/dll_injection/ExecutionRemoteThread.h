#pragma once

#include "main_header.h"
#include "ManagerProcMemory.h"


struct ThreadInfo {
	unsigned char *code;
	SIZE_T size_code;
	unsigned char *arg;
	SIZE_T size_arg;
	DWORD ret_val;
};


int executionRemoteThread(PROCESS_INFORMATION pi, ThreadInfo *info);
int waitGetExitCodeAndCloseHandle(HANDLE hThread, LPDWORD pRetVal);
