#pragma once

#include <minwindef.h>
#include <winnt.h>
#include <Windows.h>

class AddCode
{
	public:
		PIMAGE_DOS_HEADER pDosHeader;
		PIMAGE_NT_HEADERS pNTHeader;
		PIMAGE_FILE_HEADER pPEHeader;
		PIMAGE_OPTIONAL_HEADER32 pOptionHeader;
		PIMAGE_SECTION_HEADER pSectionHeader;
		BOOL AddCodeToCodeSec(LPSTR lpszFile, LPSTR lpszOutFile);
		DWORD AddSection(LPVOID pFileBuffer, LPVOID& pNewFileBuffer, DWORD dwFileBufferSize, DWORD dwNewSectionSize);
		DWORD ExpandLastSection(LPVOID pFileBuffer, LPVOID& pNewFileBuffer, DWORD dwOldSize, DWORD dwExpandSize);
		BOOL MergeSection(LPVOID pImageBuffer, LPVOID& pNewImageBuffer, DWORD dwImageSize);
};

