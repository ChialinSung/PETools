
/*

coding by Song Jialin (Chialin)
2020��11��17��20:52:51

�����ã���ImageBufferתΪnewBuffer��Ϊ��һ������Ϊ�ļ���׼��
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
		printf("�ļ���ȡʧ��\n");
		return NULL;
	}

	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
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
		new_buffer_size += pSectionHeader[i].SizeOfRawData;  // pSectionHeader[i]��һ�ּӷ�
	}

	pNewBuffer = malloc(new_buffer_size);
	if (!pNewBuffer)
	{
		printf(" ����NewBuffer�ռ�ʧ��! ");
		return NULL;
	}

	memcpy(pNewBuffer, pImageBuffer, pOptionHeader->SizeOfHeaders);
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		memcpy((LPVOID)((DWORD)(pNewBuffer) + pSectionHeader[i].PointerToRawData), (LPVOID)((DWORD)pImageBuffer + pSectionHeader[i].VirtualAddress), pSectionHeader[i].SizeOfRawData);
	}
	printf("NewBuffer���ɳɹ�\n");
	return new_buffer_size;
}