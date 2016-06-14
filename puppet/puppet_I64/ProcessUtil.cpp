#include "StdAfx.h"  
#include "ProcessUtil.h"  
#pragma comment(lib, "Psapi.lib")


CProcessUtil::CProcessUtil(void)  
{  
}  

CProcessUtil::~CProcessUtil(void)  
{  
}  

/* 
Get a list of process ids by searching current system 
Input:  
processName: the name of process 
Return: 
PIDList: a list of DWORD, each one is an id of a process 
*/  
PIDList CProcessUtil::GetPIDListByProcessName( CString processName )  
{  
	// return list  
	PIDList mlist;  
	// convert CString to TCHAR  
	int strLen = processName.GetLength();  
	TCHAR* processPath = new TCHAR[strLen+1];  
	//ASSERT(processPath);  
	lstrcpy(processPath,processName.GetBuffer(strLen));  
	processName.ReleaseBuffer();  

	HANDLE hProcessSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);  
	if(hProcessSnap==INVALID_HANDLE_VALUE){  
		return mlist;  
	}  

	PROCESSENTRY32 pe32;  
	pe32.dwSize = sizeof(PROCESSENTRY32);  
	// get all process's snapshot  
	BOOL bMore=Process32First(hProcessSnap,&pe32);    
	while(bMore){  
		bMore=Process32Next(hProcessSnap,&pe32);  
		if(!_wcsicmp(pe32.szExeFile,processName)){  
			//PrintModules(pe32.th32ProcessID);  
			mlist.push_back(pe32.th32ProcessID) ;  
			continue;  
		}  
	}  
	//clean snapshot object and free memory  
	CloseHandle(hProcessSnap);  
	delete[] processPath;  
	processPath=NULL;  
	// return list  
	return mlist;  

}  

/* 
Find a list of dlls given by dllList in a pid's all modules 
Input:   
pid: a specific id of a given process 
allList: a list of dlls' names with CString type 
Output:  
map: PID => ( DLL'sname => InjectioinStatus(TRUE/FLASE) ) 
*/  
DllStatusMap CProcessUtil::FindDllsInProcess( DWORD pid, StringList dllList )  
{  
	// return value <DLL's name => exist in Process>  
	DllStatusMap dllsInProcess;  
	for (StringList::iterator slit=dllList.begin();  
		slit!=dllList.end();  
		++slit)  
	{  
		dllsInProcess[*slit] = FALSE;  
	}  

	// search for all modules in a specific process  
	HMODULE hMods[1024];  
	HANDLE hProcess;  
	DWORD cbNeeded;  

	// Get a handle to the process.  
	hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid );  
	if (NULL == hProcess)  
		return dllsInProcess;  

	// Get a list of all the modules in this process.  
	if(EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))  
	{  
		for ( UINT i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )  
		{  
			TCHAR szModName[MAX_PATH];  
			// Get the full path to the module's file.  
			if ( GetModuleFileNameEx( hProcess, hMods[i], szModName,  
				sizeof(szModName) / sizeof(TCHAR)))  
			{  
				// extra dll name  
				ExtraDllNameInPath(&szModName[0]);  
				// convert from TCHAR* to CString  
				CString dllName;  
				dllName.Format(_T("%s"),szModName);  
				CheckDllInList(dllsInProcess,dllName);  

			}//if  
		}//for  
	}//if  

	// Release the handle to the process.  
	CloseHandle( hProcess );  

	return dllsInProcess;  

}  

/* 
Check whether a DLL given by dllName exist in a dlllsInProcess 
Input: 
dllsInProcess: <String,BOO> i.e. <DLL's name, does this DLL exist in a specific pid> 
dllName: the name of a DLL which is need to be figured out 
Output:  
null 

*/  
void CProcessUtil::CheckDllInList( DllStatusMap &dllsInProcess, CString dllName )  
{  
	for (DllStatusMap::iterator mpit=dllsInProcess.begin();  
		mpit!=dllsInProcess.end();  
		++mpit)  
	{  
		CString dllNameInList = mpit->first;  
		if (!dllNameInList.CompareNoCase(dllName))  
		{  
			mpit->second = TRUE;  
		}  
	}  

}  

/* extract dll name from it's full path, e.g. input: C:\Windows\System32\abc.dll , return abc.dll 
*/  
TCHAR* CProcessUtil::ExtraDllNameInPath( TCHAR* dllFullPath )  
{  
	TCHAR *strPtr = dllFullPath;  
	size_t len = wcslen(dllFullPath);  
	size_t lastSlash=0;  
	for(unsigned i=0;i<len;++i){  
		if(dllFullPath[i]==_T('\\')){  
			lastSlash = i;  
		}  
	}  
	if(lastSlash==0){  
		return strPtr;  
	}else{  
		wcsncpy_s(strPtr,len,&dllFullPath[lastSlash+1],len-lastSlash);  
	}  
	return strPtr;  
}  


/* 
Make use of _fopen to query the status of a service given by serviceName 
*/  
CString CProcessUtil::QueryServiceStatusByName( CString serviceName )  
{  
	CString queryCmd = _T("sc query ") + serviceName;  
	CString statusStr = _T("NULL");  
	char cmd_charptr[100];  
	memset(cmd_charptr,0,100);  
	WideCharToMultiByte(CP_ACP,0,queryCmd,-1,cmd_charptr,80,NULL,NULL);  
	FILE *pipe = _popen(cmd_charptr,"r");  
	if(!pipe) return statusStr;  
	char buffer[128];  
	while(!feof(pipe)){  
		if(fgets(buffer,128,pipe)!=NULL){  
			char *pstr = strstr(buffer,"STATE");  
			if(NULL != pstr){  
				CString fullString(buffer);  
				//CString statusString;  
				int colon_pos = fullString.Find(':');  
				//CString statusString =   
				fullString.Delete(0,colon_pos+4);// get the value after state  
				return fullString;  

			}  
		}//if  
	}//while  
	_pclose(pipe);  
	return statusStr;  
}  

/* 
Get System previlige  
*/  
BOOL CProcessUtil::GetSystemOperationPrivilege()  
{  
	// TODO: Add your control notification handler code here  
	HANDLE hToken; // handle to process token   
	TOKEN_PRIVILEGES tkp; // pointer to token structure  
	OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES |   
		TOKEN_QUERY, &hToken); // Get the LUID for shutdown privilege.                
	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);   
	tkp.PrivilegeCount = 1; // one privilege to set  
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;     
	// Get shutdown privilege for this process.   
	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES) NULL, 0);  
	// Cannot test the return value of AdjustTokenPrivileges.    
	if (GetLastError() != ERROR_SUCCESS){  
		return FALSE;  
	}else{  
		return TRUE;  
	}     
}  

HMODULE CProcessUtil::getModuleHandle( DWORD pid, LPCTSTR lpszModuleName )
{
	HMODULE hMods[1024];  
	DWORD cbNeeded;  

	// Get a handle to the process.  
	HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid );  
	if (NULL == hProcess)  
		return NULL;  

	// Get a list of all the modules in this process.  
	if(EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))  
	{  
		for ( UINT i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )  
		{  
			TCHAR szModName[MAX_PATH];  
			// Get the full path to the module's file.  
			if ( GetModuleFileNameEx( hProcess, hMods[i], szModName,  
				sizeof(szModName) / sizeof(TCHAR)))  
			{  
				if (0 == wcsicmp(szModName, lpszModuleName))
				{
					CloseHandle(hProcess);
					return hMods[i];
				}
			}
		}
	}

	// Release the handle to the process.  
	CloseHandle( hProcess );  

	return NULL;  
}