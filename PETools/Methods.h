#pragma once

#include <minwindef.h>
#include <winnt.h>
#include <Windows.h>

class Methods
{
	public:
		PIMAGE_DOS_HEADER pDosHeader;
		PIMAGE_NT_HEADERS pNTHeader;
		PIMAGE_FILE_HEADER pPEHeader;
		PIMAGE_OPTIONAL_HEADER32 pOptionHeader;
		PIMAGE_SECTION_HEADER pSectionHeader;
		DWORD minRange, maxRange;
		BOOL memery2File(LPVOID pMemBuffer, DWORD size, LPSTR lpszFile);
		DWORD RvaToFileOffset(LPVOID pFileBuffer, DWORD dwRva);
};

