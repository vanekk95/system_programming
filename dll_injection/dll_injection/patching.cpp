#include "patching.h"


unsigned char loop[] = {
	0x90,		// loop:	nop
	0x90,		//			nop
	0x90,		//			nop
	0x90,		//			nop
	0x90,		//			nop
	0xEB, 0xF9 	//			jmp loop
};

unsigned char get_base_image[] = {
	0x65, 0x4C, 0x8B, 0x24, 0x25, 0x60, 0x00, 0x00, 0x00, // mov r12, gs:[0x60]		;peb
	0x4D, 0x8B, 0x64, 0x24, 0x10, 						  // mov r12, [r12 + 0x10]	;Peb --> ImageBaseAddress 
	0x4C, 0x89, 0x21,									  // mov [rcx], r12			;save in mem
	0xC3 };


void printPEandOptionalHeaders(IMAGE_NT_HEADERS PeHeader) {

	printf("PE HEADER = #%c%c%x%x# machine: 0x%x sizeof=%s \n",
		PeHeader.Signature & 0xFF,
		(PeHeader.Signature >> 8) & 0xFF,
		(PeHeader.Signature >> 16) & 0xFF,
		(PeHeader.Signature >> 24) & 0xFF,
		PeHeader.FileHeader.Machine,
		PeHeader.FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER) ? "OK" : "BAD");

	printf("pOptionalHeader\n");
	printf("\tAddressOfEntryPoint = %u\n", PeHeader.OptionalHeader.AddressOfEntryPoint);
	printf("\tBaseOfCode = %u\n", PeHeader.OptionalHeader.BaseOfCode);
	printf("\tFileAlignment = %u\n", PeHeader.OptionalHeader.FileAlignment);
	printf("\tSizeOfImage = %u\n", PeHeader.OptionalHeader.SizeOfImage);

}


int make_patch_x64(PROCESS_INFORMATION pi, PatchInfo *info) {

	BUILD_BUG_ON(SIZE_PATCH < sizeof(loop));
	
	unsigned char *base;
	ThreadInfo thread_info;

	thread_info.code = get_base_image;
	thread_info.size_code = sizeof(get_base_image);
	thread_info.arg = (unsigned char *)&base;
	thread_info.size_arg = sizeof(base);

	if (executionRemoteThread(pi, &thread_info))
		error_exit("executionRemoteThread", 1);

	ManagerProcMemory procMemory(pi.hProcess);
	IMAGE_DOS_HEADER dosHeader;

	if (procMemory.read(base, &dosHeader, sizeof(IMAGE_DOS_HEADER)))
		error_exit("readProcessMemory", NULL);

	printf("DOS HEADER = %c%c 0x%x \n", dosHeader.e_magic & 0xFF, (dosHeader.e_magic >> 8) & 0xFF, dosHeader.e_lfanew);

	unsigned char *pPeHeader = base + dosHeader.e_lfanew;
	info->pPeHeader = pPeHeader;
	info->base = base;
	IMAGE_NT_HEADERS PeHeader;
	if (procMemory.read(pPeHeader, &PeHeader, sizeof(IMAGE_NT_HEADERS)))
		error_exit("ReadProcessMemory", 1);

	printPEandOptionalHeaders(PeHeader);

	void *addrOfEntryPoint = base + PeHeader.OptionalHeader.AddressOfEntryPoint;
	printf("addrOfEntryPoint = %p\n", addrOfEntryPoint);
	if (procMemory.read(addrOfEntryPoint, info->origin_instr, sizeof(loop)))
		error_exit("ReadProcessMemory", 1);

	printf("fist instructions\n");
	for (int i = 0; i < sizeof(loop); i++)
		printf("0x%x ", info->origin_instr[i]);
	printf("\n");

	if (procMemory.write(addrOfEntryPoint, loop, sizeof(loop)))
		error_exit("WriteProcessMemory", 1);

	info->entryPoint = addrOfEntryPoint;
	info->context.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(pi.hThread, &info->context))
		error_exit("GetThreadContext", 1);
	printf("make patch:\t context->rip = %p\n", info->context.Rip);

	return 0;
}


int unmake_patch_x64(PROCESS_INFORMATION pi, PatchInfo info) {
	ManagerProcMemory procMemory(pi.hProcess);

	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(pi.hThread, &context))
		error_exit("WriteProcessMemory", 1);
	printf("unmake patch:\t context->rip = %p\n", context.Rip);

	context.ContextFlags = CONTEXT_FULL;
	context.Rip = (DWORD64)(info.entryPoint);
	if (!SetThreadContext(pi.hThread, &context))
		error_exit("SetThreadContext", 1);

	if (procMemory.write(info.entryPoint, info.origin_instr, sizeof(loop)))
		error_exit("WriteProcessMemory", 1);

	return 0;
}
