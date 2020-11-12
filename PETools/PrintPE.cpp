
/*

coding by Song Jialin (Chialin)
2020年11月12日21:28:04

类作用：将读取的PE文件信息打印出来
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
		printf("文件读取失败\n");
		return;
	}

	//判断是否是有效的MZ标志	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		free(pFileBuffer);
		return;
	}

	//打印DOC头
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
		
	printf("********************DOC头********************\n");
	printf("MZ标志：%x\n", pDosHeader->e_magic);
	printf("PE偏移：%x\n", pDosHeader->e_lfanew);

	//判断是否是有效的PE标志
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		free(pFileBuffer);
		return;
	}

	//打印NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
		
	printf("********************NT头********************\n");
	printf("NT：%x\n", pNTHeader->Signature);

	//打印PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);

	printf("********************PE头********************\n");
	printf("程序运行的CPU型号：%x\n", pPEHeader->Machine);
	printf("节的数量：%x\n", pPEHeader->NumberOfSections);
	printf("时间戳：%x\n", pPEHeader->TimeDateStamp);
	printf("可选PE头的大小：%x\n", pPEHeader->SizeOfOptionalHeader);
	printf("可执行文件标识：%x\n", pPEHeader->Characteristics);

	//打印可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	printf("********************OPTIOIN_PE头********************\n");
	printf("说明文件类型：%x\n", pOptionHeader->Magic);
	printf("程序入口：%x\n", pOptionHeader->AddressOfEntryPoint);
	printf("内存镜像基址：%x\n", pOptionHeader->ImageBase);
	printf("内存对齐：%x\n", pOptionHeader->SectionAlignment);
	printf("文件对齐：%x\n", pOptionHeader->FileAlignment);
	printf("内存中整个PE文件的映射的尺寸：%x\n", pOptionHeader->SizeOfImage);
	printf("所有头+节表按照文件对齐后的大小：%x\n", pOptionHeader->SizeOfHeaders);
	printf("校验和：%x\n", pOptionHeader->CheckSum);
	printf("目录项数目：%x\n", pOptionHeader->NumberOfRvaAndSizes);

	//打印节表
	for (int i = 0; i < pPEHeader->NumberOfSections; i++){
		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader + sizeof(_IMAGE_SECTION_HEADER)*i);
		printf("********************节表%d********************\n",i+1);
		char c[IMAGE_SIZEOF_SHORT_NAME];
		for (int a = 0; a < IMAGE_SIZEOF_SHORT_NAME; a++) {
			c[a] = pSectionHeader->Name[a];
		}
		printf("节表名：%s\n", c);
		printf("未对齐的真实尺寸：%x\n", pSectionHeader->Misc.VirtualSize);
		printf("在内存中的偏移地址（加上内存基址）：%x\n", (pSectionHeader->VirtualAddress+pOptionHeader->ImageBase));
		printf("文件中对齐后大小：%x\n", (pSectionHeader->SizeOfRawData));
		printf("在文件中的偏移地址：%x\n", (pSectionHeader->PointerToRawData));
		printf("该节表属性：%x\n", pSectionHeader->Characteristics);
	}
	

	//释放内存	
	free(pFileBuffer);
}
