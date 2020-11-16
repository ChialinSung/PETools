#include "File2Image.h"
#include "PrintPE.h"
#include "ReadPE.h"

#include <minwindef.h>
#include <iostream>
#include <winnt.h>
#include <Windows.h>
#include <fstream>

DWORD File2Image::readFile2Image(char* lpszFile) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID pFileBuffer = NULL;
	
	ReadPE rpe;
	pFileBuffer = rpe.ReadPEFile(lpszFile);

	if (!pFileBuffer)
	{
		printf("文件读取失败\n");
		return NULL;
	}

	//判断是否是有效的MZ标志	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		free(pFileBuffer);
		return NULL;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	LPVOID pImageBuffer = NULL;
	pImageBuffer = malloc((pOptionHeader->SizeOfImage));

	if (!pFileBuffer)
	{
		printf(" 分配Image空间失败! ");
		return NULL;
	}

	//fwrite(*pImageBuffer,sizeof(headersSize),1,pFile);
	memcpy(pImageBuffer,pFileBuffer,pOptionHeader->SizeOfHeaders);
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		memcpy((LPVOID)((DWORD)(pImageBuffer) + pSectionHeader[i].VirtualAddress), (LPVOID)((DWORD)pFileBuffer + pSectionHeader[i].PointerToRawData), pSectionHeader[i].SizeOfRawData);
	}

	printf("ImageBuffer生成成功！");
	return pOptionHeader->SizeOfImage;
}
