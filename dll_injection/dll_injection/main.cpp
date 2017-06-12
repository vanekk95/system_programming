#define _CRTDBG_MAP_ALLOC  
#include <stdlib.h>  
#include <crtdbg.h> 

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


int check_file_path(char *path) {
	OFSTRUCT file_struct;
	HFILE hFile = OpenFile(DLL_PATH, &file_struct, 0);
	if (hFile == HFILE_ERROR)
		error_exit("OpenFile", 1);
	//CloseFile(hFile);
	return 0;
}

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
//	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

	//printf("myLoadLibrary %s\n", myLoadLibrary(&info) ? "Error" : "OK");

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
	strcpy(info.path_to_my_dll, DLL_PATH);

	// put arg for shellcode
	ManagerProcMemory procMemory(pi.hProcess);
	void *info_for_shellcode;
	if (!(info_for_shellcode = procMemory.alloc(sizeof(for_shellcode_t))))
		error_exit("AllocProcessMemory", 1);
	if (procMemory.write(info_for_shellcode, &info, sizeof(for_shellcode_t)))
		error_exit("WriteProcessMemory", 1);

	// put code for shellcode
	void *remote_shellcode;
	if (!(remote_shellcode = procMemory.alloc(sizeof(byte_code_myLoadLibrary))))
		error_exit("AllocProcessMemory", 1);
	if (procMemory.write(remote_shellcode, byte_code_myLoadLibrary, sizeof(byte_code_myLoadLibrary)))
		error_exit("WriteProcessMemory", 1);

	// create remote thread for LoadLibrary
	HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_shellcode, info_for_shellcode, 0, NULL);
	if (!hThread)
		error_exit("CreateRemoteThread[LoadLibrary]", 1);

	DWORD error_code;
	if (waitGetExitCodeAndCloseHandle(hThread, (LPDWORD)(&error_code)))
		error_exit("waitGetExitCodeAndCloseHandle", 1);

	printf("error_code = 0x%x\n", error_code);

	if (ResumeThread(pi.hThread) == -1)
		error_exit("ResumeThread", 1);

	if (waitGetExitCodeAndCloseHandle(pi.hThread, NULL))
		error_exit("waitGetExitCodeAndCloseThread", 1);

	printf("Program succesfully finished.\n");

//	_CrtDumpMemoryLeaks();
	return 0;
}
