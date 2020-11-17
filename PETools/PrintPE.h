#pragma once

#include <minwindef.h>
#include <winnt.h>
#include <Windows.h>

class PrintPE
{
	public:
		PIMAGE_DOS_HEADER pDosHeader;
		PIMAGE_NT_HEADERS pNTHeader;
		PIMAGE_FILE_HEADER pPEHeader;
		PIMAGE_OPTIONAL_HEADER32 pOptionHeader;
		PIMAGE_SECTION_HEADER pSectionHeader;
		void printPEHeaders(LPVOID pFileBuffer);
};

