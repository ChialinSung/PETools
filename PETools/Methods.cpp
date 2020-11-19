

/*

coding by Song Jialin (Chialin)
2020年11月18日17:24:21

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

// 移动NT头和节表到DOS STUB，该函数在新增节时节表空间不足的情况下调用；返回地址减小值
DWORD Methods::MoveNTHeaderAndSectionHeadersToDosStub(LPVOID pFileBuffer) {
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	LPVOID pDst = (LPVOID)((DWORD)pDosHeader + sizeof(IMAGE_DOS_HEADER)); // NT头插入点
	DWORD dwRet = (DWORD)pNTHeader - (DWORD)pDst; // 返回地址减小的值
	DWORD dwSize = 4 + sizeof(IMAGE_FILE_HEADER) + pPEHeader->SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * pPEHeader->NumberOfSections; // 移动的字节数
	LPVOID pSrc = malloc(dwSize);
	if (pSrc == NULL)
	{
		printf("分配内存失败\n");
		return 0;
	}
	memcpy(pSrc, (LPVOID)pNTHeader, dwSize); // 保存要复制的数据
	memset((LPVOID)pNTHeader, 0, dwSize); // 清空原数据
	memcpy(pDst, pSrc, dwSize); // 移动数据
	free(pSrc);
	pDosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER); // 更新 e_lfanew，因为直接跟在了dos头的后面

	return dwRet;
}

DWORD Methods::Align(DWORD dwOffset, DWORD dwAlign)
{
	// 如果偏移小于对齐，向上取整
	if (dwOffset <= dwAlign) return dwAlign;
	// 如果偏移大于对齐且不能除尽，向上取整
	if (dwOffset % dwAlign)
	{
		return (dwOffset / dwAlign + 1) * dwAlign;
	}
	// 如果能除尽，直接返回offset
	return dwOffset;
}


