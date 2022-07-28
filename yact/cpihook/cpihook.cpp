// cpihook.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include <malloc.h>
#include <stdio.h>

#pragma warning(disable : 4996)

#include <stdlib.h>

#include <windows.h>
#include <imagehlp.h>

#ifdef _X86_
#pragma comment(lib,"UxTheme.lib")
#include <uxtheme.h>
#endif

#pragma comment(lib,"imagehlp.lib")

DWORD JMPPTR4ARM=0;

BYTE JMPCodeOLD[32] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
#ifdef _WIN64
BYTE JMPCode[] = { 0xFF, 0x25, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
#else
#ifdef _ARM_
BYTE JMPCode[] = { 0xDF, 0xF8, 0, 0xF0, 0x11, 0x22, 0x33, 0x44 };
#else
BYTE JMPCode[] = { 0xb8,0xcc,0xcc,0xcc, 0xcc,0xff,0xe0,0xcc };
#endif
#endif
BYTE* cpi;
BYTE* cpi4acc;

void* RewriteFunctionImp(const char* szRewriteModuleName, const char* szRewriteFunctionName, void* pRewriteFunctionPointer)
{
	for (int i = 0; i < 2; i++) {
		// ベースアドレス
		DWORD dwBase = 0;
		if (i == 0) {
			if (szRewriteModuleName) {
				dwBase = (DWORD)(intptr_t)::GetModuleHandleA(szRewriteModuleName);
			}
		}
		else if (i == 1) {
			dwBase = (DWORD)(intptr_t)GetModuleHandle(NULL);
		}
		if (!dwBase)continue;

		// イメージ列挙
		ULONG ulSize;
		PIMAGE_IMPORT_DESCRIPTOR pImgDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData((HMODULE)(intptr_t)dwBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);
		for (; pImgDesc->Name; pImgDesc++) {
			const char* szModuleName = (char*)(intptr_t)(dwBase + pImgDesc->Name);
			// THUNK情報
			PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(intptr_t)(dwBase + pImgDesc->FirstThunk);
			PIMAGE_THUNK_DATA pOrgFirstThunk = (PIMAGE_THUNK_DATA)(intptr_t)(dwBase + pImgDesc->OriginalFirstThunk);
			// 関数列挙
			for (; pFirstThunk->u1.Function; pFirstThunk++, pOrgFirstThunk++) {
				if (IMAGE_SNAP_BY_ORDINAL(pOrgFirstThunk->u1.Ordinal))continue;
				PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)(intptr_t)(dwBase + (DWORD)pOrgFirstThunk->u1.AddressOfData);
				if (!szRewriteFunctionName) {
					// 表示のみ
					printf("Module:%s Hint:%d, Name:%s\n", szModuleName, pImportName->Hint, pImportName->Name);
				}
				else {
					// 書き換え判定
					if (stricmp((const char*)pImportName->Name, szRewriteFunctionName) != 0)continue;

					// 保護状態変更
					DWORD dwOldProtect;
					if (!VirtualProtect(&pFirstThunk->u1.Function, sizeof(pFirstThunk->u1.Function), PAGE_READWRITE, &dwOldProtect))
						return NULL; // エラー

					// 書き換え
					void* pOrgFunc = (void*)(intptr_t)pFirstThunk->u1.Function; // 元のアドレスを保存しておく
					WriteProcessMemory(GetCurrentProcess(), &pFirstThunk->u1.Function, &pRewriteFunctionPointer, sizeof(pFirstThunk->u1.Function), NULL);
					pFirstThunk->u1.Function = (DWORD)(intptr_t)pRewriteFunctionPointer;

					// 保護状態戻し
					VirtualProtect(&pFirstThunk->u1.Function, sizeof(pFirstThunk->u1.Function), dwOldProtect, &dwOldProtect);
					return pOrgFunc; // 元のアドレスを返す
				}
			}
		}
	}
	return NULL;
}

void* RewriteFunction(const char* szRewriteModuleName, const char* szRewriteFunctionName, void* pRewriteFunctionPointer)
{
	return RewriteFunctionImp(szRewriteModuleName, szRewriteFunctionName, pRewriteFunctionPointer);
}

void PrintFunctions()
{
	printf("----\n");
	RewriteFunctionImp(NULL, NULL, NULL);
	printf("----\n");
}

typedef DWORD (WINAPI *__CreateProcessInternalW)(
	__in         DWORD unknown1,                              // always (?) NULL
	__in_opt     LPCWSTR lpApplicationName,
	__inout_opt  LPWSTR lpCommandLine,
	__in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
	__in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
	__in         BOOL bInheritHandles,
	__in         DWORD dwCreationFlags,
	__in_opt     LPVOID lpEnvironment,
	__in_opt     LPCWSTR lpCurrentDirectory,
	__in         LPSTARTUPINFOW lpStartupInfo,
	__out        LPPROCESS_INFORMATION lpProcessInformation,
	__in         DWORD unknown2                               // always (?) NULL
);
typedef DWORD(WINAPI* __CreateProcessInternalA)(
	__in         DWORD unknown1,                              // always (?) NULL
	__in_opt     LPCSTR lpApplicationName,
	__inout_opt  LPSTR lpCommandLine,
	__in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
	__in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
	__in         BOOL bInheritHandles,
	__in         DWORD dwCreationFlags,
	__in_opt     LPVOID lpEnvironment,
	__in_opt     LPCSTR lpCurrentDirectory,
	__in         LPSTARTUPINFOA lpStartupInfo,
	__out        LPPROCESS_INFORMATION lpProcessInformation,
	__in         DWORD unknown2                               // always (?) NULL
	);
typedef DWORD(WINAPI* __CreateProcessW)(
	__in_opt     LPCWSTR lpApplicationName,
	__inout_opt  LPWSTR lpCommandLine,
	__in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
	__in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
	__in         BOOL bInheritHandles,
	__in         DWORD dwCreationFlags,
	__in_opt     LPVOID lpEnvironment,
	__in_opt     LPCWSTR lpCurrentDirectory,
	__in         LPSTARTUPINFOW lpStartupInfo,
	__out        LPPROCESS_INFORMATION lpProcessInformation
	);
typedef DWORD(WINAPI* __CreateProcessA)(
	__in_opt     LPCSTR lpApplicationName,
	__inout_opt  LPSTR lpCommandLine,
	__in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
	__in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
	__in         BOOL bInheritHandles,
	__in         DWORD dwCreationFlags,
	__in_opt     LPVOID lpEnvironment,
	__in_opt     LPCSTR lpCurrentDirectory,
	__in         LPSTARTUPINFOA lpStartupInfo,
	__out        LPPROCESS_INFORMATION lpProcessInformation
	);

__CreateProcessW ptr4cpi;
__CreateProcessW ptr4cpi2;
__CreateProcessW ptr4cpi3;
__CreateProcessInternalA ptr4cpia;
__CreateProcessA ptr4cpia2;
__CreateProcessA ptr4cpia3;

wchar_t wchar4tmp[4096];
wchar_t wchar4tmp2[4096];
wchar_t wchar4tmp3[2];
wchar_t wchar4tmp4[4096];
wchar_t wchar4tmp5[4096];
char wchar4tmpa[4096];
char wchar4tmpa2[4096];
char wchar4tmpa3[2];
int cpiflags0000;

void DbgPrint(
  _In_  PCHAR Format,
   ...
)
{
	char Buff[512];	
    va_list va;
	va_start(va,Format);
	vsprintf_s(Buff,Format,va);

	OutputDebugStringA(Buff);
}

int PeLdrIsValidX86(LPCWSTR FileName)
{
	char Buff1[512];
	wchar_t Buff[1024];
	if(SearchPathW(0,FileName,L".DLL",1024,Buff,0)==0)
		wcscpy_s(Buff,FileName);

	HANDLE H=CreateFileW(Buff,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,0,OPEN_EXISTING,0,0);
	if(H==INVALID_HANDLE_VALUE)
	{
		DbgPrint("IsValidX86: can't open file: %S\n",Buff);
		SetLastError(ERROR_NOT_FOUND);
		return 0;
	}

// Validate PE
	DWORD Len=0;
	if(ReadFile(H,Buff1,512,&Len,0)==FALSE || Len!=512 || Buff1[0]!='M' || Buff1[1]!='Z')
	{
		DbgPrint("IsValidX86: invalid file format (no MZ): %S\n",Buff);
		CloseHandle(H);
		SetLastError(ERROR_INVALID_EXE_SIGNATURE);
		return 0;
	}
	if(SetFilePointer(H,((PIMAGE_DOS_HEADER) Buff1)->e_lfanew,0,FILE_BEGIN)==INVALID_SET_FILE_POINTER)
	{
		DbgPrint("IsValidX86: invalid file format (bad e_lfanew): %S (%d)\n",Buff,GetLastError());
		CloseHandle(H);
		SetLastError(ERROR_INVALID_EXE_SIGNATURE);
		return 0;
	}
	if(ReadFile(H,Buff1,512,&Len,0)==FALSE || Len!=512 || Buff1[0]!='P' || Buff1[1]!='E' || Buff1[2]!=0 || Buff1[3]!=0 )
	{
		DbgPrint("IsValidX86: invalid file format (no PE): %S\n",Buff);
		CloseHandle(H);
		SetLastError(ERROR_INVALID_EXE_SIGNATURE);
		return 0;
	}
	if(Buff1[4]!=0x4c || Buff1[5]!=1 )
	{
		DbgPrint("IsValidX86: invalid machine (not 0x14c): %S\n",Buff);
		CloseHandle(H);
		SetLastError(ERROR_INVALID_EXE_SIGNATURE);
		return 0;
	}

	CloseHandle(H);

	bool IsGUI=((PIMAGE_NT_HEADERS)Buff1)->OptionalHeader.Subsystem==IMAGE_SUBSYSTEM_WINDOWS_GUI;

	return IsGUI?1:-1;
}

extern HMODULE CpiHookModule;

DWORD CPIHookThread(void* Arr[2])
{
	__try 
	{
		DWORD *Arg=(DWORD*)Arr[0];
		wchar_t *Path=(wchar_t*)Arr[1];
		LPWSTR App=(LPWSTR)Arg[1];
		LPWSTR Cmdline=(LPWSTR)Arg[2];

		if(App==0 && Cmdline==0)
			return 0;

		if(App==0)		// extract app name from cmd line
		{
			wcscpy_s(Path,32768,Cmdline);
			wchar_t *TmpCmd=Path;
			wchar_t *P=0;
			if(Path[0]=='\"')
			{
				TmpCmd++;
				P=wcschr(TmpCmd,'\"');
			} else
				P=wcschr(TmpCmd,' ');
			if(P)
				*P=0;
			App=TmpCmd;
		}

		int Type=PeLdrIsValidX86(App);
		if(Type!=0)
		{
			SetEnvironmentVariable(L"EMU_PROGRAM",App);
			Arg[1]=(DWORD)Path;
		}

		wcscpy_s(Path,32768,L"c:\\x86");
		DWORD Ret=GetModuleFileNameW(CpiHookModule,Path,MAX_PATH);
		wchar_t *Pp=wcsrchr(Path,'\\');
		if(Pp)
			*Pp=0;
		if(Type>0)
			wcscat_s(Path,32768,L"\\thunk86.exe");
		else
			wcscat_s(Path,32768,L"\\thunk86c.exe");

		HWND Hw=FindWindowW(L"X86AutoHook",0);
		if(Hw)
			PostMessageW(Hw,WM_COMMAND,0,0);
	} __except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return 0;
}


DWORD WINAPI MyCreateProcessInternalW(
	__in         DWORD unknown1,                              // always (?) NULL
	__in_opt     LPCWSTR lpApplicationName,
	__inout_opt  LPWSTR lpCommandLine,
	__in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
	__in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
	__in         BOOL bInheritHandles,
	__in         DWORD dwCreationFlags,
	__in_opt     LPVOID lpEnvironment,
	__in_opt     LPCWSTR lpCurrentDirectory,
	__in         LPSTARTUPINFOW lpStartupInfo,
	__out        LPPROCESS_INFORMATION lpProcessInformation,
	__in         DWORD unknown2                               // always (?) NULL
) {
	//MessageBoxW(0, L"Test!", L"", 0);
	DWORD ret;
	memcpy(cpi, JMPCodeOLD, sizeof(JMPCode)); FlushInstructionCache(GetCurrentProcess(), cpi, sizeof(JMPCode));
	wchar_t windowsdir[1024] = L"";
	DWORD Ret = GetModuleFileNameW(0, windowsdir, 1024);
	wchar_t* windowsdir2 = wcsrchr(windowsdir, '\\');
	wchar_t windowsdir3[2048] = L"";
	const wchar_t windowsdirtmp[128] = L"\\execveapp.exe";
	wchar_t windowsdirtmp2[1024] = L"";
	if (windowsdir2) { *windowsdir2 = 0; }
	wcscat_s(windowsdirtmp2, windowsdir);
	wcscat_s(windowsdirtmp2, ((wchar_t*)windowsdirtmp));
	char windowsdirtmp2x[1024];
	wcstombs(windowsdirtmp2x, windowsdirtmp2, 1024);
	//MessageBoxW(0, windowsdirtmp2, L"", 0);
	FILE* fp4chk = fopen((char*)windowsdirtmp2x, "r");
	if (fp4chk != 0) {
		fclose(fp4chk);
		if (((wchar_t*)lpApplicationName) != 0) {
			wcscat_s(windowsdir3, windowsdirtmp2);
			wcscat_s(windowsdir3, L" ");
			wcscat_s(windowsdir3, L"\"");
			wcscat_s(windowsdir3, ((wchar_t*)lpApplicationName));
			wcscat_s(windowsdir3, L"\"");
			wcscat_s(windowsdir3, ((wchar_t*)lpCommandLine) + wcslen(((wchar_t*)lpApplicationName)));
			ret = ((__CreateProcessInternalW)cpi4acc)(unknown1, windowsdirtmp2, windowsdir3, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, unknown2);
			memcpy(cpi, JMPCode, sizeof(JMPCode)); FlushInstructionCache(GetCurrentProcess(), cpi, sizeof(JMPCode)); return ret;
		}
		else {
			wcscat_s(windowsdir3, windowsdirtmp2);
			wcscat_s(windowsdir3, L" ");
			wcscat_s(windowsdir3, ((wchar_t*)lpCommandLine));
			ret = ((__CreateProcessInternalW)cpi4acc)(unknown1, windowsdirtmp2, windowsdir3, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, unknown2);
			memcpy(cpi, JMPCode, sizeof(JMPCode)); FlushInstructionCache(GetCurrentProcess(), cpi, sizeof(JMPCode)); return ret;
		}
	}
	else {
		if (fp4chk != nullptr) { fclose(fp4chk); }
		/*if (lpCommandLine != nullptr) { MessageBoxW(0, lpCommandLine, L"lpCommandLine", 0); }
		if (lpApplicationName != nullptr) { MessageBoxW(0, lpApplicationName,L"lpApplicationName" , 0); }*/
		//if (ptr4cpi == NULL) { ptr4cpi = ptr4cpi2; }
		int cnt4cpi = 0;
		int cnt4cpi2 = 0;
		int cnt4cpi3 = 0;
		cpiflags0000 = 0;
		for (int cnt = 0; cnt < 4096; cnt++) { wchar4tmp[cnt] = '\0'; wchar4tmp2[cnt] = '\0'; wchar4tmp4[cnt] = '\0'; wchar4tmp5[cnt] = '\0'; }
		if (lpCommandLine != nullptr) {
			//MessageBoxW(0, lpCommandLine, L"lpCommandLine", 0);
			for (int cnt = 0; cnt < wcslen(lpCommandLine); cnt++)
			{
				wchar4tmp3[0] = lpCommandLine[cnt];
				if ((cpiflags0000 & 2) == 0 && wchar4tmp3[0] == L'\"') { cpiflags0000 ^= 1; }
				else if ((cpiflags0000 & 1) == 0 && wchar4tmp3[0] == L'\'') { cpiflags0000 ^= 2; }
				else if ((cpiflags0000 & 3) == 0 && wchar4tmp3[0] == L' ') { cpiflags0000 |= 4; cnt4cpi2 = cnt; }
				else if ((cpiflags0000 & 4) == 0) { wchar4tmp2[cnt4cpi] = wchar4tmp3[0]; cnt4cpi++; }
				else if ((cpiflags0000 & 4) != 0) { wchar4tmp4[cnt4cpi3] = wchar4tmp3[0]; cnt4cpi3++; }

			}
			//MessageBoxW(0, wchar4tmp2, L"wchar4tmp2", 0);
			DWORD Ret = GetModuleFileNameW(CpiHookModule, wchar4tmp, MAX_PATH);
			wchar_t* Pp = wcsrchr(wchar4tmp, '\\');
			if (Pp)
				*Pp = 0;
			if (PeLdrIsValidX86(wchar4tmp2) == 1) { SetEnvironmentVariable(L"EMU_PROGRAM", wchar4tmp2); wcsncat(wchar4tmp, L"\\peloader.exe ", 15); }
			else if (PeLdrIsValidX86(wchar4tmp2) != 0) { SetEnvironmentVariable(L"EMU_PROGRAM", wchar4tmp2); wcsncat(wchar4tmp, L"\\peloaderc.exe ", 16); }
			else { ret = ((__CreateProcessInternalW)cpi4acc)(unknown1, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, unknown2); memcpy(cpi, JMPCode, sizeof(JMPCode)); FlushInstructionCache(GetCurrentProcess(), cpi, sizeof(JMPCode)); return ret; }
			wcsncpy(wchar4tmp5, wchar4tmp, wcslen(wchar4tmp));
			if (wcslen(wchar4tmp) != 0) { wchar4tmp5[wcslen(wchar4tmp) - 1] = 0; } else { wchar4tmp5[0] = 0; }
			wcsncat(wchar4tmp, wchar4tmp4, cnt4cpi3);
			//MessageBoxW(0, wchar4tmp, L"wchar4tmp", 0);
			//MessageBoxW(0, lpApplicationName, L"lpApplicationName", 0);
			if (lpApplicationName == nullptr) {
				ret = ((__CreateProcessInternalW)cpi4acc)(unknown1, lpApplicationName, wchar4tmp, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, unknown2);
			} else {
				if (lpApplicationName == L"") {
					ret = ((__CreateProcessInternalW)cpi4acc)(unknown1, lpApplicationName, wchar4tmp, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, unknown2);
				} else {
					ret = ((__CreateProcessInternalW)cpi4acc)(unknown1, wchar4tmp5, wchar4tmp, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, unknown2);
				}
			}
			memcpy(cpi, JMPCode, sizeof(JMPCode)); FlushInstructionCache(GetCurrentProcess(), cpi, sizeof(JMPCode)); return ret;
		}
		if (lpApplicationName != nullptr) {
			//MessageBoxW(0, lpApplicationName, L"lpApplicationName", 0);
			DWORD Ret = GetModuleFileNameW(CpiHookModule, wchar4tmp, MAX_PATH);
			wchar_t* Pp = wcsrchr(wchar4tmp, '\\');
			if (Pp)
				*Pp = 0;
			if (PeLdrIsValidX86(lpApplicationName) == 1) {
				SetEnvironmentVariable(L"EMU_PROGRAM", lpApplicationName);
				wcsncat(wchar4tmp, L"\\peloader.exe", 14);
				ret = ((__CreateProcessInternalW)cpi4acc)(unknown1, wchar4tmp, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, unknown2);
				memcpy(cpi, JMPCode, sizeof(JMPCode)); FlushInstructionCache(GetCurrentProcess(), cpi, sizeof(JMPCode)); return ret;
			}
			else if (PeLdrIsValidX86(lpApplicationName) != 0) {
				SetEnvironmentVariable(L"EMU_PROGRAM", lpApplicationName);
				wcsncat(wchar4tmp, L"\\peloaderc.exe", 15);
				ret = ((__CreateProcessInternalW)cpi4acc)(unknown1, wchar4tmp, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, unknown2);
				memcpy(cpi, JMPCode, sizeof(JMPCode)); FlushInstructionCache(GetCurrentProcess(), cpi, sizeof(JMPCode)); return ret;
			}
			else {
				ret = ((__CreateProcessInternalW)cpi4acc)(unknown1, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, unknown2);
				memcpy(cpi, JMPCode, sizeof(JMPCode)); FlushInstructionCache(GetCurrentProcess(), cpi, sizeof(JMPCode)); return ret;
			}
		}
		ret = ((__CreateProcessInternalW)cpi4acc)(unknown1, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, unknown2);
		memcpy(cpi, JMPCode, sizeof(JMPCode)); FlushInstructionCache(GetCurrentProcess(), cpi, sizeof(JMPCode)); return ret;
	}
}

wchar_t lpApplicationName_tmp[4096];


static __declspec(thread) wchar_t Path[32768];	// Thread-safe buffer
void MyCPIHook(DWORD* Arg)
{
#ifdef _ARM_
	return;
#endif
	void *Arr[2];
	Arr[0]=Arg;
	Arr[1]=Path;
	HANDLE H=CreateThread(0,256*1024,(LPTHREAD_START_ROUTINE)CPIHookThread,(void*)Arr,STACK_SIZE_PARAM_IS_A_RESERVATION,0);
	if(H)
	{
		WaitForSingleObject(H,INFINITE);
		CloseHandle(H);
	}
}

bool HookInstalled=false;
bool cpihookx = false;

extern "C" __declspec(dllexport) bool CpiMakeHook()
{
	if(HookInstalled)
		return true;

	HookInstalled = true;

#ifdef _X86_
	SetThemeAppProperties(0);
#endif

	HMODULE HM=LoadLibraryA("kernelbase.dll");
	if(HM==0)
		return false;
	//ptr4cpia = (__CreateProcessInternalA)GetProcAddress(HM, "CreateProcessInternalA");
	//BYTE* cpi=(BYTE*)GetProcAddress(HM,"CreateProcessInternalW");
	cpi = (BYTE*)GetProcAddress(HM, "CreateProcessInternalW");
	cpi4acc = (BYTE*)GetProcAddress(HM, "CreateProcessInternalW");
	if(cpi==0)
	{
		HM=LoadLibraryA("kernel32.dll");
		if(HM==0)
			return false;

		//ptr4cpia = (__CreateProcessInternalA)GetProcAddress(HM, "CreateProcessInternalA");
		cpi=(BYTE*)GetProcAddress(HM,"CreateProcessInternalW");
		cpi4acc = (BYTE*)GetProcAddress(HM, "CreateProcessInternalW");
		if(cpi==0)
			return false;
	}

	//printf("%08X\n", (&cpi));

#ifdef _ARM_
/*
6DE28040 E92D 000F            push.w      {r0-r3}  
6DE28044 E92D 4FF0            push        {r4-r11,lr}  
6DE28048 F8DF 101C            ldr.w       r1,CBCode+28h (6DE28068h)  
6DE2804C A800                 add         r0,sp,#0  
6DE2804E 4788                 blx         r1  
6DE28050 F8DF B018            ldr         r11,CBCode+2Ch (6DE2806Ch)  
6DE28054 F8DD 0020            ldr.w       r0,[sp,#0x20]  
6DE28058 F8DD 1024            ldr.w       r1,[sp,#0x24]  
6DE2805C F8DD 2028            ldr.w       r2,[sp,#0x28]  
6DE28060 F8DD 302C            ldr.w       r3,[sp,#0x2C]  
6DE28064 4758                 bx          r11  
6DE28066 0000                 movs        r0,r0  
6DE28068 6655                 ...
6DE2806A 8877                 ...
6DE2806C 2211                 ...
6DE2806E 4433                 ...
*/
	if (((DWORD)(&cpi)) & 1) {
		cpi--;	// THUMB
	}
	else { JMPCode[0] = 0x04; JMPCode[1] = 0xF0; JMPCode[2] = 0x1F; JMPCode[3] = 0xE5; }
	static BYTE CBCode[]={0x2D, 0xE9, 0xF, 0, 0x2D, 0xE9, 0xF0, 0x4F, 9, 0xA8,
		0xDF, 0xF8, 0x1C, 0x10, 0x88, 0x47, 0xDD, 0xF8, 0x24,
		0, 0xDD, 0xF8, 0x28, 0x10, 0xDD, 0xF8, 0x2C, 0x20,
		0xDD, 0xF8, 0x30, 0x30, 0xD, 0xF2, 0x1C, 0xB, 0xDF,
		0xF8, 4, 0xF0, 0x88, 0x77, 0x66, 0x55, 0x11, 0x22,
		0x33, 0x44};
	//BYTE JMPCode[]={0xDF, 0xF8, 0, 0xF0, 0x11, 0x22, 0x33, 0x44};	// should be 8 bytes exactly!
#if 0
	if (cpi[0] != 0x0f || cpi[1] != 0xb4 || cpi[2] != 0x2d || cpi[3] != 0xe9 || cpi[4] != 0xf0 || cpi[5] != 0x4f || cpi[6] != 0x0d || cpi[7] != 0xf2 || cpi[9] != 0x0b) {
		return false;
	}
#endif

#else
	//if (cpi[0] == 0x8B && cpi[1] == 0xFF && cpi[2] == 0x55 && cpi[3] == 0x8B && cpi[4] == 0xEC && cpi[5] == 0x6A && cpi[6] == 0xFE) { cpi += 7; cpihookx = true; }
#if 0
	if (cpi[0] != 0x68 || cpi[5] != 0x68) {
		return false;
	}
#endif
	/*
55                   push        ebp  
8B EC                mov         ebp,esp  
8D 45 08             lea         eax,[ebp+8]  
50                   push        eax  
B8 CC CC CC CC       mov         eax,0CCCCCCCCh  
FF D0                call        eax  
89 EC                mov         esp,ebp  
5D                   pop         ebp  
CC CC CC CC cc
CC CC CC CC cc
B8 CC CC CC CC       mov         eax,0CCCCCCCCh  
ff e0				 jmp		 eax
*/
	static BYTE CBCode[]={0x55,0x8B,0xEC,0x8D,0x45,0x08,0x50,0xb8,0xcc,0xcc,0xcc,0xcc,0xff,0xd0,0x89,0xec,0x5d,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xb8,0xcc,0xcc,0xcc,0xcc,0xff,0xe0};
	//BYTE JMPCode[]={0xb8,0xcc,0xcc,0xcc, 0xcc,0xff,0xe0,0xcc};	// should be 8 bytes exactly!
#endif
	DWORD Tmp;
#if 0
	BYTE *thunk=(BYTE*)malloc(sizeof(CBCode));
	memcpy(thunk,CBCode,sizeof(CBCode));
#endif
#ifdef _WIN64
	* (UINT64*)(JMPCode + 2) = ((UINT64)(&MyCreateProcessInternalW));
#else
#ifdef _ARM_
	* (DWORD*)(JMPCode + 4) = 1|((DWORD)(&MyCreateProcessInternalW));
#else
	* (DWORD*)(JMPCode + 1) = ((DWORD)(&MyCreateProcessInternalW));
#endif
#endif
#if 0
#ifdef _ARM_
	thunk[34]=cpi[8];
	*(DWORD*)(thunk+sizeof(CBCode)-8)=1|(DWORD)MyCPIHook;
	*(DWORD*)(thunk+sizeof(CBCode)-4)=1|(((DWORD)cpi)+10);
	*(DWORD*)(JMPCode+4)=1|((DWORD)thunk);
#else
	memcpy(thunk+sizeof(CBCode)-17,cpi,10);
	*(DWORD*)(thunk+8)=(DWORD)MyCPIHook;
	*(DWORD*)(thunk+sizeof(CBCode)-6)=((DWORD)cpi)+10;
	*(DWORD*)(JMPCode+1)=((DWORD)thunk);
#endif
#endif
#if 0
	if (cpihookx == true) {
		VirtualProtect(&cpi - 7, 7, PAGE_EXECUTE_READWRITE, &Tmp);
		memcpy(&cpi - 7, JMPCodeOLD, 7);
	}
#endif
	VirtualProtect(cpi,sizeof(JMPCode),PAGE_EXECUTE_READWRITE,&Tmp);

//	InterlockedExchange64((volatile LONGLONG*)cpi,*(LONGLONG*)JMPCode);
	memcpy(JMPCodeOLD,cpi, sizeof(JMPCode));
	memcpy(cpi,JMPCode, sizeof(JMPCode));
	//printf("cpi:0x%08X\n0x%08X\n%02X%02X%02X%02X\n", (&cpi), (&cpi4acc), (*cpi), (*(cpi + 1)), (*(cpi + 2)), (*(cpi + 3)));
	//memcpy(cpi,JMPCode,8);

	/*VirtualProtect(thunk, sizeof(CBCode), PAGE_EXECUTE_READWRITE, &Tmp);
	FlushInstructionCache(GetCurrentProcess(),thunk,sizeof(CBCode));*/
	FlushInstructionCache(GetCurrentProcess(),cpi,sizeof(JMPCode));

	return true;
}

DWORD WINAPI ThreadProc(		// this thread would start after the process finishes its initialization
  _In_  LPVOID lpParameter
)
{
	__try 
	{
		if(CpiMakeHook())
			OutputDebugStringA("cpihook.dll: CPI hook installed\n");
		else
			OutputDebugStringA("cpihook.dll: Failed to install CPI hook\n");
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return 0;
}

bool HookThisProcess()
{
	CloseHandle(CreateThread(0,256*1024,ThreadProc,0,STACK_SIZE_PARAM_IS_A_RESERVATION,0));
	return true;
}
