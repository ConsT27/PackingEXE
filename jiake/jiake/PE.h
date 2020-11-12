#include <Windows.h>

typedef struct _StubConf
{
	DWORD srcOep;		//入口点
	DWORD textScnRVA;	//代码段RVA
	DWORD textScnSize;	//代码段的大小
	DWORD key;			//解密密钥
}StubConf;

struct StubInfo
{
	char* dllbase;			//stub.dll的加载基址
	DWORD pfnStart;			//stub.dll(start)导出函数的地址
	StubConf* pStubConf;	//stub.dll(g_conf)导出全局变量的地址
};


//***********************
//PE信息获取函数簇
//time:2020/11/2
//***********************
PIMAGE_DOS_HEADER GetDosHeader(_In_ char* pBase) {
	return PIMAGE_DOS_HEADER(pBase);
}

PIMAGE_NT_HEADERS GetNtHeader(_In_ char* pBase) {
return PIMAGE_NT_HEADERS(GetDosHeader(pBase)->e_lfanew+(SIZE_T)pBase);
}

PIMAGE_FILE_HEADER GetFileHeader(_In_ char* pBase) {
	return &(GetNtHeader(pBase)->FileHeader);
}

PIMAGE_OPTIONAL_HEADER32 GetOptHeader(_In_ char* pBase) {
	return &(GetNtHeader(pBase)->OptionalHeader);
}

PIMAGE_SECTION_HEADER GetLastSec(_In_ char* pBase) {
	DWORD SecNum = GetFileHeader(pBase)->NumberOfSections;
	PIMAGE_SECTION_HEADER FirstSec = IMAGE_FIRST_SECTION(GetNtHeader(pBase));
	PIMAGE_SECTION_HEADER LastSec = FirstSec + SecNum - 1;
	return LastSec;
}

PIMAGE_SECTION_HEADER GetSecByName(_In_ char* pBase,_In_ const char* name) {
	DWORD Secnum = GetFileHeader(pBase)->NumberOfSections;
	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(GetNtHeader(pBase));
	char buf[10] = { 0 };
	for (DWORD i = 0; i < Secnum; i++) {
		memcpy_s(buf, 8, (char*)Section[i].Name, 8);
		if (!strcmp(buf, name)) {
				return Section + i;
		}
	}
	return nullptr;
}

//**********************
//打开文件返回句柄
//time:2020/11/2
//*********************
char* GetFileHmoudle(_In_ const char* path,_Out_opt_ DWORD* nFileSize) {
	//打开一个文件并获得文件句柄
	HANDLE hFile = CreateFileA(path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	//获得文件大小
	DWORD FileSize = GetFileSize(hFile, NULL);
	//返回文件大小到变量nFileSize
	if(nFileSize)
		*nFileSize = FileSize;
	//申请一片大小为FileSize的内存并将指针置于首位
	char* pFileBuf = new CHAR[FileSize]{ 0 };
	//给刚刚申请的内存读入数据
	DWORD dwRead;
	ReadFile(hFile, pFileBuf, FileSize, &dwRead, NULL);
	CloseHandle(hFile);
	return pFileBuf;
}

//****************
//对齐处理
//time:2020/11/5
//****************
int AlignMent(_In_ int size, _In_ int alignment) {
	return (size) % (alignment)==0 ? (size) : ((size) / alignment+1) * (alignment);
}

//*********************
//增添区段
//time:2020/11/6
//*********************
char* AddSec(_In_ char*& hpe, _In_ DWORD& filesize, _In_ const char* secname, _In_ const int secsize) {
	GetFileHeader(hpe)->NumberOfSections++;
	PIMAGE_SECTION_HEADER pesec = GetLastSec(hpe);
	//设置区段表属性
	memcpy(pesec->Name, secname, 8);
	pesec->Misc.VirtualSize = secsize;
	pesec->VirtualAddress = (pesec - 1)->VirtualAddress + AlignMent((pesec - 1)->SizeOfRawData,GetOptHeader(hpe)->SectionAlignment);
	pesec->SizeOfRawData = AlignMent(secsize, GetOptHeader(hpe)->FileAlignment);
	pesec->PointerToRawData = AlignMent(filesize,GetOptHeader(hpe)->FileAlignment);
	pesec->Characteristics = 0xE00000E0;
	//设置OPT头映像大小
	GetOptHeader(hpe)->SizeOfImage = pesec->VirtualAddress + pesec->SizeOfRawData;
	//扩充文件数据
	int newSize = pesec->PointerToRawData + pesec->SizeOfRawData;
	char* nhpe = new char [newSize] {0};
	//向新缓冲区录入数据
	memcpy(nhpe, hpe, filesize);
	//缓存区更替
	delete hpe;
	filesize = newSize;
	return nhpe;
}

//******************
//保存文件
//time:2020/11/6
//******************
void SaveFile(_In_ const char* path, _In_ const char* data, _In_ int FileSize) {
	HANDLE hFile = CreateFileA(
		path,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	DWORD Buf = 0;
	WriteFile(hFile, data, FileSize, &Buf,NULL);
	CloseHandle(hFile);
}

//*******************
//加载stub
//time:
//******************
//void StubLoad (_In_ StubInfo* pStub) {
//
//}


void FixStub(DWORD targetDllbase, DWORD stubDllbase,DWORD targetNewScnRva,DWORD stubTextRva )
{
	//找到stub.dll的重定位表
	DWORD dwRelRva = GetOptHeader((char*)stubDllbase)->DataDirectory[5].VirtualAddress;
	IMAGE_BASE_RELOCATION* pRel = (IMAGE_BASE_RELOCATION*)(dwRelRva + stubDllbase);

	//遍历重定位表
	while (pRel->SizeOfBlock)
	{
		struct TypeOffset
		{
			WORD offset : 12;
			WORD type : 4;

		};
		TypeOffset* pTypeOffset = (TypeOffset*)(pRel + 1);
		DWORD dwCount = (pRel->SizeOfBlock - 8) / 2;	//需要重定位的数量
		for (int i = 0; i < dwCount; i++)
		{
			if (pTypeOffset[i].type != 3)
			{
				continue;
			}
			//需要重定位的地址
			DWORD* pFixAddr = (DWORD*)(pRel->VirtualAddress + pTypeOffset[i].offset + stubDllbase);

			DWORD dwOld;
			//修改属性为可写
			VirtualProtect(pFixAddr, 4, PAGE_READWRITE, &dwOld);
			//去掉dll当前加载基址
			*pFixAddr -= stubDllbase;
			//去掉默认的段首RVA
			*pFixAddr -= stubTextRva;
			//换上目标文件的加载基址
			*pFixAddr += targetDllbase;
			//加上新区段的段首RVA
			*pFixAddr += targetNewScnRva;
			//把属性修改回去
			VirtualProtect(pFixAddr, 4, dwOld, &dwOld);
		}
		//切换到下一个重定位块
		pRel = (IMAGE_BASE_RELOCATION*)((DWORD)pRel + pRel->SizeOfBlock);
	}

}
//******************
//加密代码段
//time:
//******************
void Encry(_In_ char* hpe,_In_ StubInfo pstub) {
	//获取代码段首地址
	BYTE* TargetText = GetSecByName(hpe, ".text")->PointerToRawData + (BYTE*)hpe;
	//获取代码段大小
	DWORD TargetTextSize = GetSecByName(hpe, ".text")->Misc.VirtualSize;
	//加密代码段
	for (int i = 0; i < TargetTextSize; i++) {
		TargetText[i] ^= 0x15;
	}
	pstub.pStubConf->textScnRVA = GetSecByName(hpe, ".text")->VirtualAddress;
	pstub.pStubConf->textScnSize = TargetTextSize;
	pstub.pStubConf->key = 0x15;
}

void LoadStub(_In_ StubInfo* pstub) {
	pstub->dllbase = (char*)LoadLibraryEx(L"F:\\stubdll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
	pstub->pfnStart = (DWORD)GetProcAddress((HMODULE)pstub->dllbase, "Start");
	pstub->pStubConf = (StubConf*)GetProcAddress((HMODULE)pstub->dllbase, "g_conf");
}