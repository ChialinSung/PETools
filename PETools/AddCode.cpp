#include "AddCode.h"
#include "ReadPE.h"
#include "File2Image.h"
#include "Image2newFile.h"
#include "Methods.h"

#include <minwindef.h>
#include <winnt.h>
#include <Windows.h>
#include <fstream>
#include <iostream>

// ���������MessageBox����
// ��������Ӵ��벻��Ҫ�����ڴ������С�����仯
// Ĭ�ϵ�һ�����Ǵ���ڣ����������жϲ�һ��׼ȷ��Ӧ�ñ����ڱ����������Ҵ����
BOOL AddCode::AddCodeToCodeSec(LPSTR lpszFile, LPSTR lpszOutFile) {
	BYTE shellcode[] = {
		0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, // push 0 push 0 push 0 push 0
		0xE8, 0x00, 0x00, 0x00, 0x00,					// call MessageBoxA
		0xE9, 0x00, 0x00, 0x00, 0x00					// jmp OEP
	};
	DWORD dwShellCodeSize = 18;
	DWORD dwCodeRva = 0; // �����λ��RVA
	LPVOID pFileBuffer = NULL;
	LPVOID pImageBuffer = NULL;
	LPVOID pNewBuffer = NULL;

	DWORD dwFileBufferSize = 0;
	DWORD dwImageBufferSize = 0;
	DWORD dwNewBufferSize = 0;

	ReadPE rpe;
	dwFileBufferSize = rpe.ReadPEFile(lpszFile, pFileBuffer);
	//printf("ԭ�ļ���С��%x",dwFileBufferSize);
	File2Image f2i;
	f2i.readFile2Image(pFileBuffer,pImageBuffer);
	Image2newFile i2f;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	DWORD dwCodeSecIndex = -1;
	// �����ڱ��ҵ������
	//�жϴ����Ƿ���ִ��Ȩ��
	for (int i = 0; i <pPEHeader->NumberOfSections; i++)
	{
		if ((pSectionHeader[i].Characteristics & 0x60000020) == 0x60000020)
		{
			dwCodeSecIndex = i;
			break;
		}
	}
	if (dwCodeSecIndex == -1)
	{
		printf("�Ҳ��������\n");
		free(pFileBuffer);
		free(pImageBuffer);
		return FALSE;
	}

	dwCodeRva = pSectionHeader[dwCodeSecIndex].VirtualAddress + pSectionHeader[dwCodeSecIndex].Misc.VirtualSize;
	DWORD dwUnuseSize;

	if (dwCodeSecIndex + 1 == pPEHeader->NumberOfSections)
	{
		if (dwCodeRva + dwShellCodeSize > pOptionHeader->SizeOfImage) {
			printf("�����û���㹻�Ŀռ�������\n");
			free(pFileBuffer);
			free(pImageBuffer);
			return FALSE;
		}
	}	else{
		dwUnuseSize = pSectionHeader[dwCodeSecIndex + 1].VirtualAddress - pSectionHeader[dwCodeSecIndex].VirtualAddress - pSectionHeader[dwCodeSecIndex].Misc.VirtualSize;
		if (dwUnuseSize < dwShellCodeSize)
		{
			printf("�����û���㹻�Ŀռ�������\n");
			free(pFileBuffer);
			free(pImageBuffer);
			return FALSE;
		}
	}

	memcpy((LPVOID)((DWORD)pImageBuffer + dwCodeRva), shellcode, dwShellCodeSize);
	DWORD MsgBoxAddr = (DWORD)&MessageBoxA; // ��ȡMessageBox�ĵ�ַ
	DWORD hardCodeAddr = MsgBoxAddr - (pOptionHeader->ImageBase + dwCodeRva + 13);
	memcpy((LPVOID)((DWORD)pImageBuffer + dwCodeRva + 9), &hardCodeAddr, 4);
	hardCodeAddr = pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint - (pOptionHeader->ImageBase + dwCodeRva + 18);
	memcpy((LPVOID)((DWORD)pImageBuffer + dwCodeRva + 14), &hardCodeAddr, 4);
	// �޸���ڵ�
	pOptionHeader->AddressOfEntryPoint = dwCodeRva;\

	// ת���ļ�����
	dwNewBufferSize = i2f.copyImageBufferToNewBuffer(pImageBuffer, pNewBuffer);
	//printf("���ļ���С��%x", dwNewBufferSize);
	if (dwNewBufferSize != dwFileBufferSize)
	{
		printf("���ܶ�ʧ����\n");
	}
	Methods mts;
	mts.memery2File(pNewBuffer, dwNewBufferSize, lpszOutFile);
	free(pFileBuffer);
	free(pImageBuffer);
	free(pNewBuffer);
	printf("�������ɹ�\n");
	return TRUE;
}

// ����һ����СΪ newSectionSize �Ĵ����
// dwFileBufferSize ��ԭ�����ļ���С
// �����»������Ĵ�С��ʧ�ܷ���0
DWORD AddCode::AddSection(LPVOID pFileBuffer, LPVOID& pNewFileBuffer, DWORD dwFileBufferSize, DWORD dwNewSectionSize)
{
	// ����һ�� pFileBuffer����Ҫ�޸�ԭ��������
	LPVOID pFileBuffer2 = malloc(dwFileBufferSize);
	memcpy(pFileBuffer2, pFileBuffer, dwFileBufferSize);
	pFileBuffer = pFileBuffer2;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	PWORD pNumberOfSections = &(pPEHeader->NumberOfSections); // �ڵ�����
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + *pNumberOfSections - 1; // ���һ���ڱ�
	PIMAGE_SECTION_HEADER pNewSectionHeader = pSectionHeader + *pNumberOfSections; // �½ڱ�����
	DWORD newFileBufferSize = 0; // ���ļ��Ĵ�С

	Methods mts;

	// �ж����һ���ڱ�����Ƿ��п��е�80�ֽ�
	if (80 > (DWORD)pFileBuffer + pOptionHeader->SizeOfHeaders - (DWORD)pNewSectionHeader)
	{
		printf("û���㹻��80�ֽڲ����½ڱ�\n");
		free(pFileBuffer2);
		return 0;
	}

	// �жϿ��е�80�ֽ��Ƿ�ȫΪ0��������ǣ��������NTͷ����Ų����dos stub�Կճ��ռ����ڱ�
	for (int i = 0; i < 80; i++)
	{
		if (((PBYTE)pNewSectionHeader)[i] != 0)
		{
			DWORD dwRet = mts.MoveNTHeaderAndSectionHeadersToDosStub(pFileBuffer);
			printf("�ڱ�ռ䲻�㣬NTͷ�ͽڱ���͵�ַ�ƶ��� %d �ֽ�\n", dwRet);
			if (dwRet < 80)
			{
				printf("�ƶ�����û���㹻��80�ֽڿռ�����½ڱ�\n");
				free(pFileBuffer2);
				return 0;
			}
			// ����ָ��
			pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
			pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
			pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
			pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
			pNumberOfSections = &(pPEHeader->NumberOfSections); // �ڵ�����
			pLastSectionHeader = pSectionHeader + *pNumberOfSections - 1; // ���һ���ڱ�
			pNewSectionHeader = pSectionHeader + *pNumberOfSections; // �½ڱ�����
			break;
		}
	}

	// ����һ�� IMAGE_SECTION_HEADER �ṹ���������������
	IMAGE_SECTION_HEADER newSectionHeader;
	memcpy(newSectionHeader.Name, ".newsec", 8);
	newSectionHeader.Misc.VirtualSize = mts.Align(dwNewSectionSize, pOptionHeader->SectionAlignment);
	newSectionHeader.VirtualAddress = pLastSectionHeader->VirtualAddress + mts.Align(pLastSectionHeader->Misc.VirtualSize, pOptionHeader->SectionAlignment);
	newSectionHeader.SizeOfRawData = mts.Align(dwNewSectionSize, pOptionHeader->FileAlignment);
	newSectionHeader.PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	newSectionHeader.PointerToRelocations = 0;
	newSectionHeader.PointerToLinenumbers = 0;
	newSectionHeader.NumberOfRelocations = 0;
	newSectionHeader.NumberOfLinenumbers = 0;
	newSectionHeader.Characteristics = 0x60000020;

	// pNewFileBuffer �����ڴ棬�� pFileBuffer ���ƹ�ȥ��������޸Ķ��� pNewFileBuffer ����
	pNewFileBuffer = malloc(dwFileBufferSize + newSectionHeader.SizeOfRawData);
	memcpy(pNewFileBuffer, pFileBuffer, dwFileBufferSize);
	memset((LPVOID)((DWORD)pNewFileBuffer + dwFileBufferSize), 0, newSectionHeader.SizeOfRawData); // ������������0

	// ����ָ�룬ָ�����ڴ�	
	pDosHeader = (PIMAGE_DOS_HEADER)pNewFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pNumberOfSections = &(pPEHeader->NumberOfSections);
	pLastSectionHeader = pSectionHeader + *pNumberOfSections - 1;
	pNewSectionHeader = pSectionHeader + *pNumberOfSections;

	// �ڵ�����+1��SizeOfImage���ڴ��������Ĵ�С
	*pNumberOfSections += 1;
	pOptionHeader->SizeOfImage += mts.Align(newSectionHeader.Misc.VirtualSize, pOptionHeader->SectionAlignment);

	// ���� newSectionHeader
	memcpy(pNewSectionHeader, &newSectionHeader, sizeof(newSectionHeader));

	printf("����ɹ�\n");
	free(pFileBuffer2);
	return dwFileBufferSize + newSectionHeader.SizeOfRawData;
}

// �������һ����
// �������ļ��Ĵ�С��ʧ�ܷ���0
DWORD AddCode::ExpandLastSection(LPVOID pFileBuffer, LPVOID& pNewFileBuffer, DWORD dwOldSize, DWORD dwExpandSize)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	Methods mts;

	DWORD dwVirtualSizeExpand = mts.Align(dwExpandSize, pOptionHeader->SectionAlignment);
	DWORD dwRawDataExpand = mts.Align(dwExpandSize, pOptionHeader->FileAlignment);

	pNewFileBuffer = malloc(dwOldSize + dwRawDataExpand);
	memcpy(pNewFileBuffer, pFileBuffer, dwOldSize);
	memset((LPVOID)((DWORD)(pNewFileBuffer) + dwOldSize), 0, dwRawDataExpand);

	pDosHeader = (PIMAGE_DOS_HEADER)pNewFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (DWORD)pNewFileBuffer);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pNTHeader + 0x18);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	// �޸����ڴ������
	pSectionHeader[pPEHeader->NumberOfSections - 1].Misc.VirtualSize += dwVirtualSizeExpand;
	pSectionHeader[pPEHeader->NumberOfSections - 1].SizeOfRawData += dwRawDataExpand;
	pOptionHeader->SizeOfImage += dwVirtualSizeExpand;

	return dwOldSize + dwRawDataExpand;
}

// �ϲ����н�
BOOL AddCode::MergeSection(LPVOID pImageBuffer, LPVOID& pNewImageBuffer, DWORD dwImageSize)
{
	pNewImageBuffer = malloc(dwImageSize);
	if (pNewImageBuffer == NULL)
	{
		printf("�����ڴ�ʧ��\n");
		return FALSE;
	}
	memcpy(pNewImageBuffer, pImageBuffer, dwImageSize);

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pNewImageBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 1;
	Methods mts;

	// �޸ĵ�һ���ڵķ�Χ�Ը����������н�
	pSectionHeader->SizeOfRawData = pSectionHeader->Misc.VirtualSize = \
		pOptionHeader->SizeOfImage - pSectionHeader->VirtualAddress;
	pSectionHeader->SizeOfRawData = mts.Align(pSectionHeader->SizeOfRawData, pOptionHeader->FileAlignment);

	// ���԰������нڵ�����
	for (int i = 1; i < pPEHeader->NumberOfSections; i++)
	{
		pSectionHeader[0].Characteristics |= pSectionHeader[i].Characteristics;
	}

	// ��������ڱ�����ݣ��ⲽ��Ϊ�˺ϲ��ں������ڷ���
	memset(pSectionHeader + 1, 0, sizeof(IMAGE_SECTION_HEADER) * (pPEHeader->NumberOfSections - 1));

	// �ڵ����� = 1
	pPEHeader->NumberOfSections = 1;

	return TRUE;
}



