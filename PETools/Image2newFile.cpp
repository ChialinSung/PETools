
/*

coding by Song Jialin (Chialin)
2020年11月17日20:52:51

类作用：由ImageBuffer转为newBuffer，为下一步存贮为文件做准备
*/



#include "Image2newFile.h"

#include <minwindef.h>
#include <winnt.h>
#include <Windows.h>
#include <iostream>
#include <fstream>

DWORD Image2newFile::copyImageBufferToNewBuffer(LPVOID pImageBuffer, LPVOID& pNewBuffer) {

	pDosHeader = NULL;
	pNTHeader = NULL;
	pPEHeader = NULL;
	pOptionHeader = NULL;
	pSectionHeader = NULL;

	if (!pImageBuffer)
	{
		printf("文件读取失败\n");
		return NULL;
	}

	//判断是否是有效的MZ标志	
	if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		free(pImageBuffer);
		return NULL;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader+pPEHeader->SizeOfOptionalHeader);

	new_buffer_size = pOptionHeader->SizeOfHeaders;
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		new_buffer_size += pSectionHeader[i].SizeOfRawData;  // pSectionHeader[i]另一种加法
	}

	pNewBuffer = malloc(new_buffer_size);
	if (!pNewBuffer)
	{
		printf(" 分配NewBuffer空间失败! ");
		return NULL;
	}

	memcpy(pNewBuffer, pImageBuffer, pOptionHeader->SizeOfHeaders);
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		memcpy((LPVOID)((DWORD)(pNewBuffer) + pSectionHeader[i].PointerToRawData), (LPVOID)((DWORD)pImageBuffer + pSectionHeader[i].VirtualAddress), pSectionHeader[i].SizeOfRawData);
	}
	printf("NewBuffer生成成功\n");
	return new_buffer_size;
}