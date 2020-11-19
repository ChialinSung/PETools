

/*

coding by Song Jialin (Chialin)
2020��11��18��17:24:21

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

// �ƶ�NTͷ�ͽڱ�DOS STUB���ú�����������ʱ�ڱ�ռ䲻�������µ��ã����ص�ַ��Сֵ
DWORD Methods::MoveNTHeaderAndSectionHeadersToDosStub(LPVOID pFileBuffer) {
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	LPVOID pDst = (LPVOID)((DWORD)pDosHeader + sizeof(IMAGE_DOS_HEADER)); // NTͷ�����
	DWORD dwRet = (DWORD)pNTHeader - (DWORD)pDst; // ���ص�ַ��С��ֵ
	DWORD dwSize = 4 + sizeof(IMAGE_FILE_HEADER) + pPEHeader->SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * pPEHeader->NumberOfSections; // �ƶ����ֽ���
	LPVOID pSrc = malloc(dwSize);
	if (pSrc == NULL)
	{
		printf("�����ڴ�ʧ��\n");
		return 0;
	}
	memcpy(pSrc, (LPVOID)pNTHeader, dwSize); // ����Ҫ���Ƶ�����
	memset((LPVOID)pNTHeader, 0, dwSize); // ���ԭ����
	memcpy(pDst, pSrc, dwSize); // �ƶ�����
	free(pSrc);
	pDosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER); // ���� e_lfanew����Ϊֱ�Ӹ�����dosͷ�ĺ���

	return dwRet;
}

DWORD Methods::Align(DWORD dwOffset, DWORD dwAlign)
{
	// ���ƫ��С�ڶ��룬����ȡ��
	if (dwOffset <= dwAlign) return dwAlign;
	// ���ƫ�ƴ��ڶ����Ҳ��ܳ���������ȡ��
	if (dwOffset % dwAlign)
	{
		return (dwOffset / dwAlign + 1) * dwAlign;
	}
	// ����ܳ�����ֱ�ӷ���offset
	return dwOffset;
}


