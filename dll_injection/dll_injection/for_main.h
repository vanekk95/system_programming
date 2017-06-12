#pragma once

//#include "targetver.h"

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




