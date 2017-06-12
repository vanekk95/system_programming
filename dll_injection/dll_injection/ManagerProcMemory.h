#pragma once
#include "for_main.h"

class ManagerProcMemory {
public:
	ManagerProcMemory(HANDLE hProcess) {
		this->hProcess = hProcess;
	}
	int read(LPCVOID baseAddress, LPVOID buffer, SIZE_T size) {
		SIZE_T retSize = 0;
		ReadProcessMemory(hProcess, baseAddress, buffer, size, &retSize);
		//		printf("size = %d\tretSize = %d\n", size, retSize);
		return (size == retSize) ? 0 : 1;
	}

	int write(LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  size) {
		SIZE_T retSize = 0;
		WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, size, &retSize);
		return (size == retSize) ? 0 : 1;
	}
	void * alloc(SIZE_T size) {
		return VirtualAllocEx(hProcess, NULL, size,
			MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	}

	int free_mem(LPVOID lpAddress) {
		return !VirtualFreeEx(hProcess, lpAddress, 0, MEM_RELEASE);
	}
private:
	HANDLE hProcess;
};
