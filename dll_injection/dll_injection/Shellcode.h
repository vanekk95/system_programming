#pragma once

#include "main_header.h"


typedef HMODULE(*LoadLibrary_t)(
	_In_ LPCSTR lpLibFileName
	);

typedef DWORD(*GetLastError_t)(VOID);

struct for_shellcode_t {
	LoadLibrary_t LoadLibrary;
	GetLastError_t GetLastError;
	char path_to_my_dll[SIZE_PATH];
};

int executionShellcode(PROCESS_INFORMATION pi, void *baseKernel32);