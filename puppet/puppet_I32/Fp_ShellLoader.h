///////////////////////////////////////////////////////////////////////////////
//
// Fun Player
// �粥
//
//  Module Name:	Fp_ShellLoader.h    
//  Version:    	3.0.1.1
//  Author:     	wucj
//	created:		2016/04/19
//
//
// Copyright 2005-, Funshion Online Technologies Ltd.
// All Rights Reserved
//
// ��Ȩ 2005-�������������߼������޹�˾
// ���а�Ȩ����
//
// This is UNPUBLISHED PROPRIETARY SOURCE CODE of Funshion Online Technologies Ltd.;
// the contents of this file may not be disclosed to third parties, copied or
// duplicated in any form, in whole or in part, without the prior written
// permission of Funshion Online Technologies Ltd. 
//
// ���Ǳ����������߼������޹�˾δ������˽��Դ���롣���ļ����������δ���������߼�����
// �޹�˾��������ͬ�⣬���������κε�����͸¶��й�ܲ��ֻ�ȫ��; Ҳ�������κ���ʽ��˽�Ա��ݡ�
//
///////////////////////////////////////////////////////////////////////////////
#pragma once

typedef struct _ChildProcessInfo {

	DWORD dwBaseAddress; 
	DWORD dwReserve; 
} CHILDPROCESS, *PCHILDPROCESS;

class CFpShellLoader
{
public:
	explicit CFpShellLoader(LPTSTR lpszHostPath);
	~CFpShellLoader(void);
		
	BOOL injectProcess();

	bool isAttached();
	DWORD getSelfImageSize(HMODULE hModule);
	BOOL unloadShell(HANDLE ProcHnd, unsigned long BaseAddr);

	BOOL createInjectProcess(PPROCESS_INFORMATION pi, PCONTEXT pThreadCxt, CHILDPROCESS *pChildProcess);

	LPCVOID getLoadAddress(HANDLE hProcess, DWORD dwProcessId );
	LPCVOID getBaseAddress(HANDLE hProcess);

private:
	LPTSTR m_lpszHostPath;
};

