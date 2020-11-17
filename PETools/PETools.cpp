
/*

coding by Song Jialin (Chialin)
最近一次修改时间：
2020年11月17日20:54:48

主程序。
*/

// PETools.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <minwindef.h>
#include <windows.h>
#include <winnt.h>
#include <fstream>

#include "TestClass.h"
#include "ReadPE.h"
#include "PrintPE.h"
#include "File2Image.h"
#include "Image2newFile.h"
#include "Methods.h"


using namespace std;

int main()
{   
    LPVOID pFileBuffer = NULL;
    LPVOID pImageBuffer = NULL;
    LPVOID pNewBuffer = NULL;
    DWORD tempSize = NULL;
    DWORD valueRVA = 0x1001;

    //PE文件路径
    char PEfilepath[] = "C:/Users/chialin/Desktop/notepad.exe";
    //导出文件路径
    char outfilepath[] = "C:/Users/chialin/Desktop/notepad2.exe";

    //读取文件
    ReadPE rpe;
    rpe.ReadPEFile(PEfilepath, pFileBuffer);

    //打印PE文件信息
    PrintPE ppe;
    ppe.printPEHeaders(pFileBuffer);

    //将fileBuffer读到ImageBuffer
    File2Image f2i;
    f2i.readFile2Image(pFileBuffer, pImageBuffer);

    //将ImageBuffer转存为NewBuffer
    Image2newFile i2n;
    tempSize = i2n.copyImageBufferToNewBuffer(pImageBuffer, pNewBuffer);

    //存储为文件
    Methods mts;

    if (mts.memery2File(pNewBuffer, tempSize, outfilepath)) {
        printf("文件输出成功！\n");
    }
    else
    {
        printf("文件输出失败！\n");
    }

    //RVA转foa！偏移换算
    printf("RVA值为%x在文件中的偏移位置foa为%x",valueRVA,mts.RvaToFileOffset(pFileBuffer, valueRVA));

    //测试类文件
    //TestClass tre;
    //tre.testClass();
    //std::cout << "Hello World!\n";
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
