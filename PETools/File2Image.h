#pragma once

#include <minwindef.h>
#include <winnt.h>
#include <Windows.h>

class File2Image
{
	public:
		PIMAGE_DOS_HEADER pDosHeader;
		PIMAGE_NT_HEADERS pNTHeader;
		PIMAGE_FILE_HEADER pPEHeader;
		PIMAGE_OPTIONAL_HEADER32 pOptionHeader;
		PIMAGE_SECTION_HEADER pSectionHeader;
		DWORD readFile2Image(LPVOID pFileBuffer,LPVOID& pImageBuffer);
};

