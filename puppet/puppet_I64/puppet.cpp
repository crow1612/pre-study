// puppet_1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h> 
#include <windows.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")
#include "Fp_ShellLoader.h"

BOOL attachProcess(LPTSTR lszHostPath)
{
	CFpShellLoader sl(lszHostPath);
	return sl.injectProcess();
}

void doWork()
{
	MessageBox(NULL,L"进程插入完成",L"Do Work",MB_OK); 
}

int APIENTRY _tWinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPTSTR    lpCmdLine,
	int       nCmdShow)
{ 
	__try
	{
		LPTSTR pszPath = L"C:\\Windows\\explorer.exe";
		if (attachProcess(pszPath))
			doWork();
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{}
	return 0; 
}