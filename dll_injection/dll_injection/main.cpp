#include "for_main.h"
#include "find_kernel32.h"
#include "time.h"
#include "patching.h"



#define APP_PATH	       "D:\\For_programm\\system prog 8 sem\\lab_2\\simple_program\\x64\\Debug\\simple_program.exe"
#define DLL_PATH	       "D:\\For_programm\\system prog 8 sem\\lab_2\\MyFirstDLL\\x64\\Debug\\myFirstDLL.dll"
#define KERNEL32DLL_NAME   "kernel32.dll"
// x32 app
#define WARCRAFT_PATH      "D:\\Game\\Warcraft III\\Frozen Throne.exe"
#define WARCRAFT_DIR_PATH  "D:\\Game\\Warcraft III"
#define MOST_WANT_PATH     "D:\\Game\\NFS Most Wanted\\directory\\Need For Speed - Most Wanted\\speed.exe"
#define MOST_WANT_DIR_PATH "D:\\Game\\NFS Most Wanted\\directory\\Need For Speed - Most Wanted"
// x64 app
#define TASK_MGR           "C:\\Windows\\System32\\Taskmgr.exe"
#define TASK_DIR_MGR       "C:\\Windows\\System32"

#define SIZE_PATH 512
#define GetCurrentDir _getcwd

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))


typedef HMODULE  (*LoadLibrary_t)(
	_In_ LPCSTR lpLibFileName
);
typedef DWORD (*GetLastError_t)(VOID);

struct for_shellcode_t {
	LoadLibrary_t LoadLibrary;
	GetLastError_t GetLastError;
	char path_to_my_dll[SIZE_PATH];
};
__declspec(noinline)
int myLoadLibrary(for_shellcode_t *info) {
	HMODULE hModule = info->LoadLibrary(info->path_to_my_dll);
	return info->GetLastError();
}
unsigned char byte_code_myLoadLibrary[] = { 
	0x53,						// push        rbx
	0x48, 0x83, 0xEC, 0x20,		// sub         rsp,20h
	0x48, 0x89, 0xCB,			// mov         rbx,rcx
	0x48, 0x83, 0xC1, 0x10,		// add         rcx,10h
	0xFF, 0x13,					// call        qword ptr [rbx] 
	0x48, 0x8B, 0x43, 0x08,		// mov         rax,qword ptr [rbx+8] 
	0x48, 0x83, 0xC4, 0x20,		// add         rsp,20h 
	0x5B,						// pop         rbx
	0xFF, 0xE0					// jmp         rax 
};


int main()
{
	BUILD_BUG_ON(SIZE_PATH < sizeof(DLL_PATH));

	STARTUPINFO cif;
	ZeroMemory(&cif, sizeof(STARTUPINFO));

	PROCESS_INFORMATION pi;
	if (!CreateProcess(TASK_MGR, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, TASK_DIR_MGR, &cif, &pi))
	//if (!CreateProcess(APP_PATH, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &cif, &pi))
		error_exit("CreateProcess", 1);

	PatchInfo patch_info;

	if (make_patch_x64(pi, &patch_info))
		error_exit("make_patch_x64", 1);

	if (ResumeThread(pi.hThread) == -1)
		error_exit("ResumeThread", 1);
	
	Sleep(200);

	void *remoteKernel32 = FindKernel32Address_x64(pi);
	if (remoteKernel32 == NULL)
		error_exit("FindKernel32AddressX86", 1);

	if (SuspendThread(pi.hThread) == -1)
		error_exit("ResumeThread", 1);

	if (unmake_patch_x64(pi, patch_info))
		error_exit("unmakePatch_x86", 1);

	// load my lib
	HMODULE hKernel32 = GetModuleHandle(KERNEL32DLL_NAME);
	if (!hKernel32)
		error_exit("GetModuleHandle", 1);

	printf("kernel32 loc = %p\n", hKernel32);
	printf("kernel32 rem = %p\n", remoteKernel32);

	// calculate remote LoadLibrary
	INT64 rvaLoadLibraryA = (unsigned char *)LoadLibraryA - (unsigned char *)hKernel32;
	LoadLibrary_t remoteLoadLibraryA = (LoadLibrary_t)((unsigned char *)remoteKernel32 + rvaLoadLibraryA);

	// calculate remote GetLastError
	INT64 rvaGetLastError = (unsigned char *)GetLastError - (unsigned char *)hKernel32;
	GetLastError_t remoteGetLastError = (GetLastError_t)((unsigned char *)remoteKernel32 + rvaGetLastError);

	for_shellcode_t info;
	info.GetLastError = remoteGetLastError;
	info.LoadLibrary = remoteLoadLibraryA;
	strncpy(info.path_to_my_dll, DLL_PATH, sizeof(DLL_PATH));

	ThreadInfo thread_info;
	thread_info.code = byte_code_myLoadLibrary;
	thread_info.size_code = sizeof(byte_code_myLoadLibrary);
	thread_info.arg = (unsigned char *)&info;
	thread_info.size_arg = sizeof(info);

	if (executionRemoteThread(pi, &thread_info))
		error_exit("executionRemoteThread", 1);

	printf("error_code = 0x%x\n", thread_info.ret_val);

	if (ResumeThread(pi.hThread) == -1)
		error_exit("ResumeThread", 1);

	if (waitGetExitCodeAndCloseHandle(pi.hThread, NULL))
		error_exit("waitGetExitCodeAndCloseThread", 1);

	printf("Program succesfully finished.\n");
	
	return 0;
}
