

/*

coding by Song Jialin (Chialin)
2020��11��17��20:54:57

�����ã�һЩ����
*/

#pragma warning(disable : 4996)

#include "Methods.h"

#include <minwindef.h>
#include <winnt.h>
#include <Windows.h>
#include <fstream>
#include <iostream>

//�����ļ�
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

//����ƫ��
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
		printf("�ļ���ȡʧ��\n");
		return NULL;
	}

	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		free(pFileBuffer);
		return NULL;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	// RVA���ļ�ͷ�л����ļ�����==�ڴ����ʱ��RVA==FOA  ����һ���ǶԵģ��ڶ����Ǵ��
	if (dwRva < pOptionHeader->SizeOfHeaders)
	{
		return dwRva;
	}

	// �����ڱ�ȷ��ƫ��������һ����	
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		if (dwRva >= pSectionHeader[i].VirtualAddress && dwRva < pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize)
		{
			int offset = dwRva - pSectionHeader[i].VirtualAddress;
			return pSectionHeader[i].PointerToRawData + offset;
		}
	}
	printf("�Ҳ���RVA %x ��Ӧ�� FOA��ת��ʧ��\n", dwRva);
	return 0;
}


