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

// 向代码节添加MessageBox代码
// 向代码节添加代码不需要担心内存对齐后大小发生变化
// 默认第一个节是代码节，但是这样判断不一定准确，应该遍历节表，根据属性找代码节
BOOL AddCode::AddCodeToCodeSec(LPSTR lpszFile, LPSTR lpszOutFile) {
	BYTE shellcode[] = {
		0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, // push 0 push 0 push 0 push 0
		0xE8, 0x00, 0x00, 0x00, 0x00,					// call MessageBoxA
		0xE9, 0x00, 0x00, 0x00, 0x00					// jmp OEP
	};
	DWORD dwShellCodeSize = 18;
	DWORD dwCodeRva = 0; // 插入的位置RVA
	LPVOID pFileBuffer = NULL;
	LPVOID pImageBuffer = NULL;
	LPVOID pNewBuffer = NULL;

	DWORD dwFileBufferSize = 0;
	DWORD dwImageBufferSize = 0;
	DWORD dwNewBufferSize = 0;

	ReadPE rpe;
	dwFileBufferSize = rpe.ReadPEFile(lpszFile, pFileBuffer);
	//printf("原文件大小：%x",dwFileBufferSize);
	File2Image f2i;
	f2i.readFile2Image(pFileBuffer,pImageBuffer);
	Image2newFile i2f;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	DWORD dwCodeSecIndex = -1;
	// 遍历节表，找到代码节
	//判断代码是否有执行权限
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
		printf("找不到代码节\n");
		free(pFileBuffer);
		free(pImageBuffer);
		return FALSE;
	}

	dwCodeRva = pSectionHeader[dwCodeSecIndex].VirtualAddress + pSectionHeader[dwCodeSecIndex].Misc.VirtualSize;
	DWORD dwUnuseSize;

	if (dwCodeSecIndex + 1 == pPEHeader->NumberOfSections)
	{
		if (dwCodeRva + dwShellCodeSize > pOptionHeader->SizeOfImage) {
			printf("代码节没有足够的空间插入代码\n");
			free(pFileBuffer);
			free(pImageBuffer);
			return FALSE;
		}
	}	else{
		dwUnuseSize = pSectionHeader[dwCodeSecIndex + 1].VirtualAddress - pSectionHeader[dwCodeSecIndex].VirtualAddress - pSectionHeader[dwCodeSecIndex].Misc.VirtualSize;
		if (dwUnuseSize < dwShellCodeSize)
		{
			printf("代码节没有足够的空间插入代码\n");
			free(pFileBuffer);
			free(pImageBuffer);
			return FALSE;
		}
	}

	memcpy((LPVOID)((DWORD)pImageBuffer + dwCodeRva), shellcode, dwShellCodeSize);
	DWORD MsgBoxAddr = (DWORD)&MessageBoxA; // 获取MessageBox的地址
	DWORD hardCodeAddr = MsgBoxAddr - (pOptionHeader->ImageBase + dwCodeRva + 13);
	memcpy((LPVOID)((DWORD)pImageBuffer + dwCodeRva + 9), &hardCodeAddr, 4);
	hardCodeAddr = pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint - (pOptionHeader->ImageBase + dwCodeRva + 18);
	memcpy((LPVOID)((DWORD)pImageBuffer + dwCodeRva + 14), &hardCodeAddr, 4);
	// 修改入口点
	pOptionHeader->AddressOfEntryPoint = dwCodeRva;\

	// 转成文件对齐
	dwNewBufferSize = i2f.copyImageBufferToNewBuffer(pImageBuffer, pNewBuffer);
	//printf("新文件大小：%x", dwNewBufferSize);
	if (dwNewBufferSize != dwFileBufferSize)
	{
		printf("可能丢失数据\n");
	}
	Methods mts;
	mts.memery2File(pNewBuffer, dwNewBufferSize, lpszOutFile);
	free(pFileBuffer);
	free(pImageBuffer);
	free(pNewBuffer);
	printf("插入代码成功\n");
	return TRUE;
}

// 新增一个大小为 newSectionSize 的代码节
// dwFileBufferSize 是原来的文件大小
// 返回新缓冲区的大小，失败返回0
DWORD AddCode::AddSection(LPVOID pFileBuffer, LPVOID& pNewFileBuffer, DWORD dwFileBufferSize, DWORD dwNewSectionSize)
{
	// 复制一份 pFileBuffer，不要修改原来的数据
	LPVOID pFileBuffer2 = malloc(dwFileBufferSize);
	memcpy(pFileBuffer2, pFileBuffer, dwFileBufferSize);
	pFileBuffer = pFileBuffer2;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	PWORD pNumberOfSections = &(pPEHeader->NumberOfSections); // 节的数量
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + *pNumberOfSections - 1; // 最后一个节表
	PIMAGE_SECTION_HEADER pNewSectionHeader = pSectionHeader + *pNumberOfSections; // 新节表插入点
	DWORD newFileBufferSize = 0; // 新文件的大小

	Methods mts;

	// 判断最后一个节表后面是否有空闲的80字节
	if (80 > (DWORD)pFileBuffer + pOptionHeader->SizeOfHeaders - (DWORD)pNewSectionHeader)
	{
		printf("没有足够的80字节插入新节表\n");
		free(pFileBuffer2);
		return 0;
	}

	// 判断空闲的80字节是否全为0，如果不是，则把整个NT头往上挪覆盖dos stub以空出空间插入节表
	for (int i = 0; i < 80; i++)
	{
		if (((PBYTE)pNewSectionHeader)[i] != 0)
		{
			DWORD dwRet = mts.MoveNTHeaderAndSectionHeadersToDosStub(pFileBuffer);
			printf("节表空间不足，NT头和节表向低地址移动了 %d 字节\n", dwRet);
			if (dwRet < 80)
			{
				printf("移动后仍没有足够的80字节空间插入新节表\n");
				free(pFileBuffer2);
				return 0;
			}
			// 更新指针
			pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
			pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
			pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
			pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
			pNumberOfSections = &(pPEHeader->NumberOfSections); // 节的数量
			pLastSectionHeader = pSectionHeader + *pNumberOfSections - 1; // 最后一个节表
			pNewSectionHeader = pSectionHeader + *pNumberOfSections; // 新节表插入点
			break;
		}
	}

	// 定义一个 IMAGE_SECTION_HEADER 结构，计算里面的属性
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

	// pNewFileBuffer 分配内存，把 pFileBuffer 复制过去，后面的修改都在 pNewFileBuffer 进行
	pNewFileBuffer = malloc(dwFileBufferSize + newSectionHeader.SizeOfRawData);
	memcpy(pNewFileBuffer, pFileBuffer, dwFileBufferSize);
	memset((LPVOID)((DWORD)pNewFileBuffer + dwFileBufferSize), 0, newSectionHeader.SizeOfRawData); // 新增节数据清0

	// 更新指针，指向新内存	
	pDosHeader = (PIMAGE_DOS_HEADER)pNewFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pNumberOfSections = &(pPEHeader->NumberOfSections);
	pLastSectionHeader = pSectionHeader + *pNumberOfSections - 1;
	pNewSectionHeader = pSectionHeader + *pNumberOfSections;

	// 节的数量+1，SizeOfImage是内存中拉伸后的大小
	*pNumberOfSections += 1;
	pOptionHeader->SizeOfImage += mts.Align(newSectionHeader.Misc.VirtualSize, pOptionHeader->SectionAlignment);

	// 拷贝 newSectionHeader
	memcpy(pNewSectionHeader, &newSectionHeader, sizeof(newSectionHeader));

	printf("插入成功\n");
	free(pFileBuffer2);
	return dwFileBufferSize + newSectionHeader.SizeOfRawData;
}

// 扩大最后一个节
// 返回新文件的大小，失败返回0
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
	// 修改新内存的属性
	pSectionHeader[pPEHeader->NumberOfSections - 1].Misc.VirtualSize += dwVirtualSizeExpand;
	pSectionHeader[pPEHeader->NumberOfSections - 1].SizeOfRawData += dwRawDataExpand;
	pOptionHeader->SizeOfImage += dwVirtualSizeExpand;

	return dwOldSize + dwRawDataExpand;
}

// 合并所有节
BOOL AddCode::MergeSection(LPVOID pImageBuffer, LPVOID& pNewImageBuffer, DWORD dwImageSize)
{
	pNewImageBuffer = malloc(dwImageSize);
	if (pNewImageBuffer == NULL)
	{
		printf("分配内存失败\n");
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

	// 修改第一个节的范围以覆盖其他所有节
	pSectionHeader->SizeOfRawData = pSectionHeader->Misc.VirtualSize = \
		pOptionHeader->SizeOfImage - pSectionHeader->VirtualAddress;
	pSectionHeader->SizeOfRawData = mts.Align(pSectionHeader->SizeOfRawData, pOptionHeader->FileAlignment);

	// 属性包含所有节的属性
	for (int i = 1; i < pPEHeader->NumberOfSections; i++)
	{
		pSectionHeader[0].Characteristics |= pSectionHeader[i].Characteristics;
	}

	// 清空其他节表的数据，这步是为了合并节后新增节方便
	memset(pSectionHeader + 1, 0, sizeof(IMAGE_SECTION_HEADER) * (pPEHeader->NumberOfSections - 1));

	// 节的数量 = 1
	pPEHeader->NumberOfSections = 1;

	return TRUE;
}



