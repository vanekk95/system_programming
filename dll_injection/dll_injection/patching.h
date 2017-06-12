#pragma once

#include "main_header.h"
#include "ManagerProcMemory.h"
#include "ExecutionRemoteThread.h"

#define SIZE_PATCH 16

struct PatchInfo {
	void *entryPoint;
	unsigned char origin_instr[SIZE_PATCH];
	CONTEXT context;
	unsigned char * pPeHeader;
	unsigned char * base;
};

void printPEandOptionalHeaders(IMAGE_NT_HEADERS PeHeader);
int make_patch_x64(PROCESS_INFORMATION pi, PatchInfo *info);
int unmake_patch_x64(PROCESS_INFORMATION pi, PatchInfo info);

