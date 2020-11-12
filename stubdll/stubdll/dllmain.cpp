

// 合并.data到.text段
#pragma comment(linker,"/merge:.data=.text")
// 合并.rdata到.text段
#pragma comment(linker,"/merge:.rdata=.text")
// 将.text改成可读可写可执行
#pragma comment(linker, "/section:.text,RWE")

#include <Windows.h>
typedef struct _StubConf
{
	DWORD srcOep;		//入口点
	DWORD textScnRVA;	//代码段RVA
	DWORD textScnSize;	//代码段的大小
	DWORD key;			//解密密钥
}StubConf;

//导出一个全局变量
extern "C" __declspec(dllexport)StubConf g_conf = { 0 };

//定义函数指针和变量
typedef void* (WINAPI* FnGetProcAddress)(HMODULE, const char*);
FnGetProcAddress MyGetProcAddress;

typedef void* (WINAPI* FnLoadLibraryA)(char*);
FnLoadLibraryA MyLoadLibraryA;

typedef void* (WINAPI* FnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
FnVirtualProtect MyVirtualProtect;


void Decrypt()
{
	unsigned char* pText = (unsigned char*)g_conf.textScnRVA + 0x400000;
	//修改代码段的属性
	DWORD old = 0;
	MyVirtualProtect(pText, g_conf.textScnSize, PAGE_READWRITE, &old);
	//解密代码段
	for (DWORD i = 0; i < g_conf.textScnSize; i++)
	{
		pText[i] ^= g_conf.key;
	}
	//把属性修改回去
	MyVirtualProtect(pText, g_conf.textScnSize, old, &old);

}


void GetApis()
{
	HMODULE hKernel32;

	_asm
	{
		pushad;
		; //获取kernel32.dll的加载基址;
		;// 1. 找到PEB的首地址;
		mov eax, fs: [0x30] ;
		mov eax, [eax + 0ch];
		mov eax, [eax + 0ch];
		mov eax, [eax];
		mov eax, [eax];
		mov eax, [eax + 018h];
		mov hKernel32, eax;
		mov ebx, [eax + 03ch];
		add ebx, eax;
		add ebx, 078h;
		mov ebx, [ebx];
		add ebx, eax;
		lea ecx, [ebx + 020h];
		mov ecx, [ecx]; // ecx => 名称表的首地址(rva);
		add ecx, eax; // ecx => 名称表的首地址(va);
		xor edx, edx; // 作为index来使用.
	_WHILE:;
		mov esi, [ecx + edx * 4];
		lea esi, [esi + eax];
		cmp dword ptr[esi], 050746547h; 47657450 726F6341 64647265 7373;
		jne _LOOP;
		cmp dword ptr[esi + 4], 041636f72h;
		jne _LOOP;
		cmp dword ptr[esi + 8], 065726464h;
		jne _LOOP;
		cmp word  ptr[esi + 0ch], 07373h;
		jne _LOOP;
		mov edi, [ebx + 024h];
		add edi, eax;

		mov di, [edi + edx * 2];
		and edi, 0FFFFh;
		mov edx, [ebx + 01ch];
		add edx, eax;
		mov edi, [edx + edi * 4];
		add edi, eax; ;
		mov MyGetProcAddress, edi;
		jmp _ENDWHILE;
	_LOOP:;
		inc edx; // ++index;
		jmp _WHILE;
	_ENDWHILE:;
		popad;
	}

	MyLoadLibraryA = (FnLoadLibraryA)MyGetProcAddress(hKernel32, "LoadLibrary");
	MyVirtualProtect = (FnVirtualProtect)MyGetProcAddress(hKernel32, "VirtualProtect");


}
extern "C" __declspec(dllexport) __declspec(naked)
void Start()
{
	//获取函数的API地址
	GetApis();
	//解密代码段
	Decrypt();
	//跳转到原始OEP
	__asm
	{
		mov eax, g_conf.srcOep;
		add eax, 0x400000
			jmp eax
	}
}
