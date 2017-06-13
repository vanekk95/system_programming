#pragma once

#include <stdio.h>
#include <tchar.h>
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <Winternl.h>
#include <direct.h>
#include <stdlib.h>



#define error_exit(msg, ret) do {																			\
								printf("%s doesn't work correctly, error: %d\n", msg, GetLastError());		\
								Sleep(2000);																\
								return ret;																	\
							} while(0)

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



