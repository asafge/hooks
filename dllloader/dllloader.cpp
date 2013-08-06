// dllloader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{
	printf("Loading DLL...\n");
	HMODULE handle = LoadLibraryW(_T("mhook-test.dll"));
	printf("Testing hook...\n");
	HMODULE hProc = LoadLibraryA("wsock32.dll");
	HMODULE hProc2 = LoadLibraryA("bonkey_dolls.dll");
	FreeLibrary(hProc);
	return 0;
}

