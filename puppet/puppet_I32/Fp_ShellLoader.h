///////////////////////////////////////////////////////////////////////////////
//
// Fun Player
// 风播
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
// 版权 2005-，北京风行在线技术有限公司
// 所有版权保护
//
// This is UNPUBLISHED PROPRIETARY SOURCE CODE of Funshion Online Technologies Ltd.;
// the contents of this file may not be disclosed to third parties, copied or
// duplicated in any form, in whole or in part, without the prior written
// permission of Funshion Online Technologies Ltd. 
//
// 这是北京风行在线技术有限公司未公开的私有源代码。本文件及相关内容未经风行在线技术有
// 限公司事先书面同意，不允许向任何第三方透露，泄密部分或全部; 也不允许任何形式的私自备份。
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

