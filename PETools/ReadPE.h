#pragma once

#include <minwindef.h>
#include <winnt.h>
#include <Windows.h>

class ReadPE
{
public:
	DWORD ReadPEFile(LPSTR lpszFile, LPVOID& pFileBuffer);
};

