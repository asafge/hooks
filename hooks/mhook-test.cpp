//Copyright (c) 2007-2008, Marton Anka
//
//Permission is hereby granted, free of charge, to any person obtaining a 
//copy of this software and associated documentation files (the "Software"), 
//to deal in the Software without restriction, including without limitation 
//the rights to use, copy, modify, merge, publish, distribute, sublicense, 
//and/or sell copies of the Software, and to permit persons to whom the 
//Software is furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included 
//in all copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
//OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
//THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
//FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
//IN THE SOFTWARE.

#include "stdafx.h"
#include "mhook-lib/mhook.h"
#include <process.h>
#include <time.h>

FILE *file;

//=========================================================================
// Define _NtOpenProcess so we can dynamically bind to the function
//
typedef struct _CLIENT_ID {
	DWORD_PTR UniqueProcess;
	DWORD_PTR UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef ULONG (WINAPI* _NtOpenProcess)(OUT PHANDLE ProcessHandle, 
	     IN ACCESS_MASK AccessMask, IN PVOID ObjectAttributes, 
		 IN PCLIENT_ID ClientId ); 

//=========================================================================
// Define _SelectObject so we can dynamically bind to the function
typedef HGDIOBJ (WINAPI* _SelectObject)(HDC hdc, HGDIOBJ hgdiobj); 

typedef HMODULE (WINAPI* _LoadLibrary)(LPCSTR libname);

typedef FARPROC (WINAPI* _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

//=========================================================================
// Get the current (original) address to the functions to be hooked
//
_NtOpenProcess TrueNtOpenProcess = (_NtOpenProcess)
	GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess");

_SelectObject TrueSelectObject = (_SelectObject)
	GetProcAddress(GetModuleHandle(L"gdi32"), "SelectObject");

_LoadLibrary TrueLoadLibraryA = (_LoadLibrary)
	GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryA");

_GetProcAddress TrueGetProcAddress = (_GetProcAddress)
	GetProcAddress(GetModuleHandle(L"kernel32"), "GetProcAddress");

//=========================================================================
// This is the function that will replace NtOpenProcess once the hook 
// is in place
//
ULONG WINAPI HookNtOpenProcess(OUT PHANDLE ProcessHandle, 
							   IN ACCESS_MASK AccessMask, 
							   IN PVOID ObjectAttributes, 
							   IN PCLIENT_ID ClientId)
{
	printf("OpenProcess,%d", ClientId->UniqueProcess);
	return TrueNtOpenProcess(ProcessHandle, AccessMask, 
		ObjectAttributes, ClientId);
}

void my_print(char* fmt, ...)
{
	va_list args;
	SYSTEMTIME st;
	GetSystemTime(&st);

	va_start(args, fmt);
	fprintf(file, "%d,%02d:%02d:%02d,", getpid(), st.wHour, st.wMinute, st.wSecond);
	vfprintf(file, fmt, args);
	fprintf(file, "\n");
	va_end(args);
}

void log(char* fmt, ...)
{
	return;
}

HMODULE WINAPI HookLoadLibraryA( LPCSTR libname)
{
	my_print("LoadLibraryA,%s", libname);
	return TrueLoadLibraryA(libname);
}

FARPROC WINAPI HookGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	my_print("GetProcAddress,%s", lpProcName);
	return TrueGetProcAddress(hModule, lpProcName);
}

void hook_loadlibrary()
{
	if (Mhook_SetHook((PVOID*)&TrueLoadLibraryA, HookLoadLibraryA)) 
	{
		HMODULE hProc = LoadLibraryA("wsock32.dll");
		if (hProc) {
			printf("Successfully opened self\n");
			FreeLibrary((HMODULE)hProc);
		}
		else {
			printf("Could not open self");
		}
	}
	Mhook_SetHook((PVOID*)&TrueGetProcAddress, HookGetProcAddress);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	char *ptr = NULL; 

	switch( fdwReason )
	{
		case DLL_PROCESS_ATTACH:
			char buffer[256];
			char path[256];	
			char baseName[256];	
			
			srand(time(NULL));
			GetModuleFileNameA(NULL, path, 256);
			ptr = strrchr(path, '\\');
			if (ptr != NULL)
				strcpy(baseName, ptr+1);
			else
				strcpy(baseName, "NA");

			_snprintf(buffer, 256, "C:\\hooks\\hook_log_%s_%d_%d.txt", baseName, getpid(), rand());

			fopen_s(&file, buffer, "a+");
			strcpy(&baseName[0], strlwr(baseName));
			if ((strcmp(baseName, "winword.exe") == 0) ||
				(strcmp(baseName, "notepad.exe") == 0)) 
			{
				my_print("+ DLL attached and initialized.\n");
				hook_loadlibrary();
			}
			break;

		case DLL_PROCESS_DETACH:
			my_print("+ unloading DLL\n");
			Mhook_Unhook((PVOID*)&TrueLoadLibraryA);
			Mhook_Unhook((PVOID*)&TrueGetProcAddress);
			fclose(file);
			break;
	}
	return TRUE;
}
