#pragma once

typedef struct _ChildProcessInfo {

	DWORD64 dwBaseAddress; 
	DWORD64 dwReserve; 
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
	LPVOID getLoadAddress();
	LPVOID getLoadAddress(HANDLE hProc, DWORD dwProcId);

private:
	LPTSTR m_lpszHostPath;
	LPVOID m_pLoadAddress;
};

