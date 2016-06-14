#include "StdAfx.h"
#include "Fp_ShellLoader.h"
#include "Fp_CommonFile.h"
#include "ProcessUtil.h"
#include <winternl.h>

typedef NTSTATUS (WINAPI *NtQueryInformationProcessPtr)(
	HANDLE processHandle,
	PROCESSINFOCLASS processInformationClass,
	PVOID processInformation,
	ULONG processInformationLength,
	PULONG returnLength);


CFpShellLoader::CFpShellLoader(LPTSTR lpszHostPath)
	: m_lpszHostPath(NULL)
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
		if (NULL == hModule)
			__leave; 

		PIMAGE_DOS_HEADER pDosheader = (PIMAGE_DOS_HEADER)hModule; 
		PIMAGE_NT_HEADERS pVirPeHead = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDosheader->e_lfanew); 
		 
		//DWORD dwImageSize = getSelfImageSize(hModule); // 通过FS段寄存器获得文件的映射大小
		//DWORD dwImageSize = getImageSize(); // 通过读取文件中的PE头获得内存映射大小
		DWORD dwImageSize = pVirPeHead->OptionalHeader.SizeOfImage; // 通过当前进程的基地址获得内存映射大小

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

		DWORD dwWrite;
		DWORD *PPEB = (DWORD *)ThreadCxt.Ebx; 
		BOOL bRet = WriteProcessMemory(pi.hProcess, &PPEB[2], &lpVirtual, sizeof(DWORD), &dwWrite); // 重写装载地址 
		if (!WriteProcessMemory(pi.hProcess, lpVirtual, hModule, dwImageSize, &dwWrite)) // 写入自己进程的代码到目标进程 
			__leave;

		printf("image inject into process success.\r\n"); 

		ThreadCxt.ContextFlags = CONTEXT_FULL; 
		if ((DWORD)lpVirtual == stChildProcess.dwBaseAddress) 
			ThreadCxt.Eax = (DWORD)pVirPeHead->OptionalHeader.ImageBase + pVirPeHead->OptionalHeader.AddressOfEntryPoint; 
		else 
			ThreadCxt.Eax = (DWORD)lpVirtual + pVirPeHead->OptionalHeader.AddressOfEntryPoint; 

#ifdef _DEBUG 
		printf("EAX = [0x%08x]\r\n",ThreadCxt.Eax); 
		printf("EBX = [0x%08x]\r\n",ThreadCxt.Ebx); 
		printf("ECX = [0x%08x]\r\n",ThreadCxt.Ecx); 
		printf("EDX = [0x%08x]\r\n",ThreadCxt.Edx); 
		printf("EIP = [0x%08x]\r\n",ThreadCxt.Eip); 
#endif 
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
	DWORD dwImageSize; 
	__asm 
	{ 
		mov ecx,0x30 
			mov eax, fs:[ecx] 
		mov eax, [eax + 0x0c] 
		mov esi, [eax + 0x0c] 
		add esi,0x20 
			lodsd 
			mov dwImageSize,eax 
	} 
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
		pThreadCxt->ContextFlags = CONTEXT_FULL; 
		GetThreadContext(pi->hThread, pThreadCxt); 

		DWORD *PPEB = (DWORD *)pThreadCxt->Ebx;
		//LPCVOID p0 = getLoadAddress(pi->hProcess, pi->dwProcessId); // 通过PEB获得新建进程的装载基地址。
		LPCVOID p = &PPEB[2]; // 通过Ebx获得新建进程的装载基地址（即，进程基地址的地址）
		DWORD read;
		BOOL bRet = ReadProcessMemory(pi->hProcess, &PPEB[2], (LPVOID)&(pChildProcess->dwBaseAddress), sizeof(DWORD), &read); 
		return bRet;
	} 
	return FALSE; 
}

LPCVOID CFpShellLoader::getLoadAddress( HANDLE hProcess, DWORD dwProcessId )
{
	HANDLE hProcessNew = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, 0, dwProcessId);

	HMODULE hModule = LoadLibrary(TEXT("Ntdll.dll "));
	if (NULL == hModule)
		return NULL;

	PROCESS_BASIC_INFORMATION pbi = {0};
	NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hModule, "NtQueryInformationProcess");
	LONG status = NtQueryInformationProcess(hProcessNew, ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	if (NULL != hModule)
		FreeLibrary(hModule);

	if (NULL != hProcessNew)
		CloseHandle(hProcessNew);

	//myprint(L"peb address", pbi.PebBaseAddress->Reserved2);

	myprint(L"pbi base address", (int)pbi.PebBaseAddress->Reserved3[1]);
	myprint(L"pbi address of base address", (int)&pbi.PebBaseAddress->Reserved3[1]);
	return (LPCVOID)(int)&pbi.PebBaseAddress->Reserved3[1];
}

LPCVOID CFpShellLoader::getBaseAddress( HANDLE hProcess )
{
	HMODULE hModule = LoadLibrary(TEXT("Ntdll.dll "));
	if (NULL == hModule)
		return NULL;

	PROCESS_BASIC_INFORMATION pbi = {0};
	NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hModule, "NtQueryInformationProcess");
	LONG status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	//LONG status = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	if (NULL != hModule)
		FreeLibrary(hModule);

	//myprint(L"peb address", pbi.PebBaseAddress->Reserved2);

	myprint(L"pbi base address", (int)pbi.PebBaseAddress->Reserved3[1]);
	myprint(L"pbi address of base address", (int)&pbi.PebBaseAddress->Reserved3[1]);
	return (LPCVOID)pbi.PebBaseAddress->Reserved3[1];
}
