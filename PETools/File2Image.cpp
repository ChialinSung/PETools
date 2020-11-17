
/*

coding by Song Jialin (Chialin)
2020��11��17��20:52:28

�����ã���FilebufferתΪImageBuffer
*/


#include "File2Image.h"

#include <minwindef.h>
#include <iostream>
#include <winnt.h>
#include <Windows.h>
#include <fstream>

DWORD File2Image::readFile2Image(LPVOID pFileBuffer, LPVOID& pImageBuffer) {
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

	pImageBuffer = malloc((pOptionHeader->SizeOfImage));

	if (!pImageBuffer)
	{
		printf(" ����Image�ռ�ʧ��! ");
		return NULL;
	}

	//fwrite(*pImageBuffer,sizeof(headersSize),1,pFile);
	memcpy(pImageBuffer,pFileBuffer,pOptionHeader->SizeOfHeaders);
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		memcpy((LPVOID)((DWORD)(pImageBuffer) + pSectionHeader[i].VirtualAddress), (LPVOID)((DWORD)pFileBuffer + pSectionHeader[i].PointerToRawData), pSectionHeader[i].SizeOfRawData);
	}

	printf("ImageBuffer���ɳɹ���\n");
	return pOptionHeader->SizeOfImage;
}
