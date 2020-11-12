
/*

coding by Song Jialin (Chialin)
2020��11��12��21:28:04

�����ã�����ȡ��PE�ļ���Ϣ��ӡ����
*/




#include "PrintPE.h"
#include "ReadPE.h"

#include <minwindef.h>
#include <iostream>
#include <winnt.h>
#include <Windows.h>

void PrintPE::PrintNTHeaders(char* lpszFile) {
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	ReadPE rpe;
	pFileBuffer = rpe.ReadPEFile(lpszFile);

	if (!pFileBuffer)
	{
		printf("�ļ���ȡʧ��\n");
		return;
	}

	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		free(pFileBuffer);
		return;
	}

	//��ӡDOCͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
		
	printf("********************DOCͷ********************\n");
	printf("MZ��־��%x\n", pDosHeader->e_magic);
	printf("PEƫ�ƣ�%x\n", pDosHeader->e_lfanew);

	//�ж��Ƿ�����Ч��PE��־
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		free(pFileBuffer);
		return;
	}

	//��ӡNTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
		
	printf("********************NTͷ********************\n");
	printf("NT��%x\n", pNTHeader->Signature);

	//��ӡPEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);

	printf("********************PEͷ********************\n");
	printf("�������е�CPU�ͺţ�%x\n", pPEHeader->Machine);
	printf("�ڵ�������%x\n", pPEHeader->NumberOfSections);
	printf("ʱ�����%x\n", pPEHeader->TimeDateStamp);
	printf("��ѡPEͷ�Ĵ�С��%x\n", pPEHeader->SizeOfOptionalHeader);
	printf("��ִ���ļ���ʶ��%x\n", pPEHeader->Characteristics);

	//��ӡ��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	printf("********************OPTIOIN_PEͷ********************\n");
	printf("˵���ļ����ͣ�%x\n", pOptionHeader->Magic);
	printf("������ڣ�%x\n", pOptionHeader->AddressOfEntryPoint);
	printf("�ڴ澵���ַ��%x\n", pOptionHeader->ImageBase);
	printf("�ڴ���룺%x\n", pOptionHeader->SectionAlignment);
	printf("�ļ����룺%x\n", pOptionHeader->FileAlignment);
	printf("�ڴ�������PE�ļ���ӳ��ĳߴ磺%x\n", pOptionHeader->SizeOfImage);
	printf("����ͷ+�ڱ����ļ������Ĵ�С��%x\n", pOptionHeader->SizeOfHeaders);
	printf("У��ͣ�%x\n", pOptionHeader->CheckSum);
	printf("Ŀ¼����Ŀ��%x\n", pOptionHeader->NumberOfRvaAndSizes);

	//��ӡ�ڱ�
	for (int i = 0; i < pPEHeader->NumberOfSections; i++){
		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader + sizeof(_IMAGE_SECTION_HEADER)*i);
		printf("********************�ڱ�%d********************\n",i+1);
		char c[IMAGE_SIZEOF_SHORT_NAME];
		for (int a = 0; a < IMAGE_SIZEOF_SHORT_NAME; a++) {
			c[a] = pSectionHeader->Name[a];
		}
		printf("�ڱ�����%s\n", c);
		printf("δ�������ʵ�ߴ磺%x\n", pSectionHeader->Misc.VirtualSize);
		printf("���ڴ��е�ƫ�Ƶ�ַ�������ڴ��ַ����%x\n", (pSectionHeader->VirtualAddress+pOptionHeader->ImageBase));
		printf("�ļ��ж�����С��%x\n", (pSectionHeader->SizeOfRawData));
		printf("���ļ��е�ƫ�Ƶ�ַ��%x\n", (pSectionHeader->PointerToRawData));
		printf("�ýڱ����ԣ�%x\n", pSectionHeader->Characteristics);
	}
	

	//�ͷ��ڴ�	
	free(pFileBuffer);
}
