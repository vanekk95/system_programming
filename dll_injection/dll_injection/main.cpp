#include "main_header.h"
#include "find_kernel32.h"
#include "patching.h"
#include "Shellcode.h"


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

	if (executionShellcode(pi, remoteKernel32))
		error_exit("executionShellcode", 1);

	if (ResumeThread(pi.hThread) == -1)
		error_exit("ResumeThread", 1);

	if (waitGetExitCodeAndCloseHandle(pi.hThread, NULL))
		error_exit("waitGetExitCodeAndCloseThread", 1);

	printf("Program succesfully finished.\n");
	
	return 0;
}
