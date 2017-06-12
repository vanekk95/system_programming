#pragma once
#include "main_header.h"

// return 0 if success and 1 when fail
class ManagerProcMemory {
public:
	ManagerProcMemory(HANDLE hProcess);
	int read(LPCVOID baseAddress, LPVOID buffer, SIZE_T size);
	int write(LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  size);
	void * alloc(SIZE_T size);
	int free_mem(LPVOID lpAddress);

private:
	HANDLE hProcess;
};
