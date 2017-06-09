#pragma once

#include "for_main.h"
#include "ManagerProcMemory.h"


#define SIZE_FUNC_NAME 128
#define SIZE_DLL_NAME 64

typedef struct LDR_DATA_ENTRY {
	LIST_ENTRY              InMemoryOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_DATA_ENTRY, *PLDR_DATA_ENTRY;


wchar_t *getShortDllName(wchar_t *fullName) {
	if (!fullName)
		return NULL;
	int i = 0, k = 0;
	for (i = 0; fullName[i] != '\0'; i++)
		if (fullName[i] == '\\')
			k = i;
	return (!k) ? fullName : &fullName[k + 1];
}


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

unsigned char get_ldr_byte_code_x32[] = {
	0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,	//  mov eax, fs:[0x30]  // PEB
	0x8B, 0x40, 0x0C,					//  mov eax, [eax + 0x0C] // PEB_LDR_DATA
	0x8B, 0x40, 0x1C,					//  mov eax, [eax + 0x1C] // InInitializationOrderModuleList
	0xC3 };								//  ret	

unsigned char get_base_adr_x64[] = { 
	0x65, 0x4C, 0x8B, 0x24, 0x25, 0x60, 0x00, 0x00, 0x00, // mov r12, gs:[0x60]		;peb
	0x4D, 0x8B, 0x64, 0x24, 0x18,						  // mov r12, [r12 + 0x18]	;Peb --> LDR 
	0x4D, 0x8B, 0x64, 0x24, 0x20,						  // mov r12, [r12 + 0x20]	;Peb.Ldr.InMemoryOrderModuleList
	0x4D, 0x8B, 0x24, 0x24,								  // mov r12, [r12]			;2st entry
	0x4D, 0x8B, 0x24, 0x24,								  // mov r12, [r12]			;3nd entry
	0x4D, 0x8B, 0x64, 0x24, 0x20,						  // mov r12, [r12 + 0x20]	;kernel32.dll base address!
	0x4C, 0x89, 0x21,									  // mov [rcx], r12			;save in mem
	0xC3 };												  // ret

void* FindKernel32Address_x64(PROCESS_INFORMATION pi)
{
	void *adrKernel32 = NULL;
	ManagerProcMemory procMemory(pi.hProcess);

	void *byte_code = procMemory.alloc(sizeof(get_base_adr_x64));
	if (!byte_code)
		error_exit("VirtualAllocEx", NULL);

	if (procMemory.write(byte_code, get_base_adr_x64, sizeof(get_base_adr_x64)))
		error_exit("WriteProcessMemory", NULL);

	void *for_ret_val = procMemory.alloc(sizeof(void *));
	if (!for_ret_val)
		error_exit("VirualAllocEx", NULL);

	HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)byte_code, for_ret_val, 0, NULL);
	if (!hThread)
		error_exit("CreateRemoteThread", NULL);

	void *baseKernel32 = NULL;

	if (waitGetExitCodeAndCloseHandle(hThread, NULL))
		error_exit("waitGetExitCodeAndCloseHandle", NULL);

	if (procMemory.read(for_ret_val, &baseKernel32, sizeof(void *)))
		error_exit("readProcessMemory", NULL);

	return baseKernel32;
}
