#pragma once

#include "for_main.h"
#include "ManagerProcMemory.h"
#include "ExecutionRemoteThread.h"


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
	void *baseKernel32;
	ThreadInfo info;
	info.code = get_base_adr_x64;
	info.size_code = sizeof(get_base_adr_x64);
	info.arg = (unsigned char *)&baseKernel32;
	info.size_arg = sizeof(baseKernel32);

	if (executionRemoteThread(pi, &info))
		error_exit("executionRemoteThread", NULL);

	return baseKernel32;
}

