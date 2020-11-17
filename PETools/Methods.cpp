

/*

coding by Song Jialin (Chialin)
2020年11月17日20:54:57

类作用：一些方法
*/

#pragma warning(disable : 4996)

#include "Methods.h"

#include <minwindef.h>
#include <winnt.h>
#include <Windows.h>
#include <fstream>
#include <iostream>

//保存文件
BOOL Methods::memery2File(LPVOID pMemBuffer, DWORD size, LPSTR lpszFile) {
	FILE* fp;
	fp = fopen(lpszFile, "wb");
	if (fp != NULL)
	{
		fwrite(pMemBuffer, size, 1, fp);
	}
	fclose(fp);
	return true;
}

//计算偏移
DWORD Methods::RvaToFileOffset(LPVOID pFileBuffer, DWORD dwRva) {
	pDosHeader = NULL;
	pNTHeader = NULL;
	pPEHeader = NULL;
	pOptionHeader = NULL;
	pSectionHeader = NULL;
	minRange = NULL;
	maxRange = NULL;

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

	// RVA在文件头中或者文件对齐==内存对齐时，RVA==FOA  错！第一句是对的，第二句是错的
	if (dwRva < pOptionHeader->SizeOfHeaders)
	{
		return dwRva;
	}

	// 遍历节表，确定偏移属于哪一个节	
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		if (dwRva >= pSectionHeader[i].VirtualAddress && dwRva < pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize)
		{
			int offset = dwRva - pSectionHeader[i].VirtualAddress;
			return pSectionHeader[i].PointerToRawData + offset;
		}
	}
	printf("找不到RVA %x 对应的 FOA，转换失败\n", dwRva);
	return 0;
}


