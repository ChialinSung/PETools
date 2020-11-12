

/*

coding by Song Jialin (Chialin)
2020��11��12��21:28:04

�����ã���ȡPE�ļ��������ļ���ʽ��
*/


//���Ա��ļ��İ�ȫ���棡
#pragma warning(disable : 4996)

#include "ReadPE.h"
#include <minwindef.h>
#include <winnt.h>
#include <stdio.h>
#include <Windows.h>


void* ReadPE::ReadPEFile(char* lpszFile){
	FILE* pFile = NULL;
	DWORD fileSize = 0;
	LPVOID pFileBuffer = NULL;

	//���ļ�	
	pFile = fopen(lpszFile, "rb");
	if (!pFile)
	{
		printf(" �޷��� EXE �ļ�! ");
		return NULL;
	}
	//��ȡ�ļ���С		
	fseek(pFile, 0, SEEK_END);
	fileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	//���仺����	
	pFileBuffer = malloc(fileSize);

	if (!pFileBuffer)
	{
		printf(" ����ռ�ʧ��! ");
		fclose(pFile);
		return NULL;
	}
	//���ļ����ݶ�ȡ��������	
	size_t n = fread(pFileBuffer, fileSize, 1, pFile);
	if (!n)
	{
		printf(" ��ȡ����ʧ��! ");
		free(pFileBuffer);
		fclose(pFile);
		return NULL;
	}
	//�ر��ļ�	
	fclose(pFile);
	return pFileBuffer;
}



