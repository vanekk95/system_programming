#pragma once

#include "for_main.h"
#include "ManagerProcMemory.h"
#include "ExecutionRemoteThread.h"
extern  "C" {
	#include <DbgHelp.h>
}

#define SIZE_FUNC_NAME 128
#define SIZE_DLL_NAME 64

/*
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

BOOL ProcessMemorReader(
	HANDLE hProcess, 
	DWORD64 qwBaseAddress, 
	PVOID lpBuffer, 
	DWORD nSize, 
	LPDWORD lpNumberOfBytesRead
) {
	return ReadProcessMemory(hProcess, (LPCVOID)qwBaseAddress, lpBuffer, nSize, (SIZE_T *)lpNumberOfBytesRead);
}

int stackTrace(PROCESS_INFORMATION pi) {
	STACKFRAME64 stack = { 0 };

	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &context);

	stack.AddrPC.Offset = context.Rip;
	stack.AddrPC.Mode = AddrModeFlat;
	stack.AddrFrame.Offset = context.Rbp;
	stack.AddrFrame.Mode = AddrModeFlat;
	stack.AddrStack.Offset = context.Rsp;
	stack.AddrStack.Mode = AddrModeFlat;

	BOOL ret = StackWalk(IMAGE_FILE_MACHINE_AMD64, pi.hProcess, pi.hThread, &stack, &context,
		ProcessMemorReader, SymFunctionTableAccess64, SymGetModuleBase64, 0);
	if (!ret) {
		printf("error in StackWalk64\n");
		return 1;
	}
	else {
		printf("Stack_frame:\n\tAddrRetenr = %p\n", stack.AddrReturn);
	}
	return 0;
}


wchar_t *getShortDllName(wchar_t *fullName) {
	if (!fullName)
		return NULL;
	int i = 0, k = 0;
	for (i = 0; fullName[i] != '\0'; i++)
		if (fullName[i] == '\\')
			k = i;
	return (!k) ? fullName : &fullName[k + 1];
}
*/



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
	return executionRemoteThread(pi,get_base_adr_x64, sizeof(get_base_adr_x64));
}

