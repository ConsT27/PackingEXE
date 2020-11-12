#include <Windows.h>
//#include "stdafx.h"
#include <tchar.h>
#include <stdio.h>
#include "PE.h"

int main() {
	//打开被加壳文件
	char PePath[] = "F:\\Project.exe";
	DWORD PeSize;
	char* PeHmoudle = GetFileHmoudle(PePath,&PeSize);
	//加载stub
	StubInfo pstub = { 0 };
	LoadStub(&pstub); 
	
	//加密代码段
	DWORD textRVA = GetSecByName(PeHmoudle, ".text")->VirtualAddress;
	DWORD textSize = GetSecByName(PeHmoudle, ".text")->Misc.VirtualSize;
	Encry(PeHmoudle,pstub);

	//添加新区段
	char SecName[] = ".fuck";
	char* PeNewHmoudle = AddSec(PeHmoudle, PeSize, SecName, GetSecByName(pstub.dllbase, ".text")->Misc.VirtualSize);
	
	//stub重定位修复
	FixStub(GetOptHeader(PeNewHmoudle)->ImageBase,
		(DWORD)pstub.dllbase,
		GetLastSec(PeNewHmoudle)->VirtualAddress,
		GetSecByName(pstub.dllbase,".text")->VirtualAddress);
	auto b = (DWORD*)GetProcAddress((HMODULE)pstub.dllbase, "OriginEntry");
	pstub.pStubConf->srcOep = GetOptHeader(PeNewHmoudle)->AddressOfEntryPoint;  //获取原入口点
	
	//stub移植
	memcpy(GetLastSec(PeNewHmoudle)->PointerToRawData+ PeNewHmoudle,
		GetSecByName(pstub.dllbase, ".text")->VirtualAddress+pstub.dllbase,
		GetSecByName(pstub.dllbase,".text")->Misc.VirtualSize);
	
	////入口点修改
	GetOptHeader(PeNewHmoudle)->AddressOfEntryPoint =
		pstub.pfnStart-(DWORD)pstub.dllbase-GetSecByName(pstub.dllbase,".text")->VirtualAddress+GetLastSec(PeNewHmoudle)->VirtualAddress;
	auto a =pstub.pfnStart-(DWORD)pstub.dllbase-GetSecByName(pstub.dllbase,".text")->VirtualAddress+GetLastSec(PeNewHmoudle)->VirtualAddress;
	auto d =GetProcAddress((HMODULE)pstub.dllbase, "OriginEntry");

	//去随机基址
	GetOptHeader(PeNewHmoudle)->DllCharacteristics &= (~0x40);
	
	//保存文件
	SaveFile("F:\\fuck.exe", PeNewHmoudle, PeSize);

	return 0;
}