

/*

coding by Song Jialin (Chialin)
2020年11月12日21:28:04

类作用：读取PE文件，按照文件格式打开
*/


//忽略本文件的安全警告！
#pragma warning(disable : 4996)

#include "ReadPE.h"
#include <minwindef.h>
#include <winnt.h>
#include <stdio.h>
#include <Windows.h>
#include <fstream>


DWORD ReadPE::ReadPEFile(LPSTR lpszFile,LPVOID& pFileBuffer){
	FILE* pFile = NULL;
	DWORD fileSize = 0;

	//打开文件	
	pFile = fopen(lpszFile, "rb");
	if (!pFile)
	{
		printf(" 无法打开 EXE 文件! ");
		return NULL;
	}
	//读取文件大小		
	fseek(pFile, 0, SEEK_END);
	fileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	//分配缓冲区	
	pFileBuffer = malloc(fileSize);

	if (!pFileBuffer)
	{
		printf(" 分配空间失败! ");
		fclose(pFile);
		return 0;
	}
	//将文件数据读取到缓冲区	
	size_t n = fread(pFileBuffer, 1, fileSize, pFile);
	//printf("读了%x",n);
	if (!n)
	{
		printf(" 读取数据失败! ");
		free(pFileBuffer);
		fclose(pFile);
		return 0;
	}
	//关闭文件	
	fclose(pFile);
	return n;
}



