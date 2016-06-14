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

