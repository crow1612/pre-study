#pragma once
#include <Windows.h>
#include <atlstr.h>  
#include <wtypes.h>  
#include <list>  
#include <map>  
#include <tchar.h>  
#include <tlhelp32.h>  
#include <psapi.h>  

using namespace std;

typedef std::list<CString>    StringList;                     // String list  
typedef std::list<DWORD>  PIDList;                        // Process ID (DWORD) list  
typedef std::map<CString,BOOL> DllStatusMap;              // < CString: DLL's name, BOOL: injection status  
typedef std::map<DWORD,DllStatusMap> ProcessDllMap;           // DWORD: process's id; DllInjectionStatus: list of dlls which are injected  
typedef std::map<CString,std::list<DWORD>> DllProcessMap;   // CString: DLL's name, size_t: total counts in ProcessInjectionStatus  

class CProcessUtil  
{  
public:  
	CProcessUtil(void);  
	~CProcessUtil(void);  

	// process function list  
	PIDList GetPIDListByProcessName( CString processName );             // get a list of PID by the given name of a process  
	DllStatusMap FindDllsInProcess( DWORD pid, StringList dllList );    // search all DLLs associate with a process to check whether a given list DLL exist in it  
	// service function list  
	CString QueryServiceStatusByName( CString serviceName );            // query the status of a specific system service by given name  
	BOOL GetSystemOperationPrivilege();                                 // get system privilege   
private:  
	void CheckDllInList( DllStatusMap &dllsInProcess, CString dllName );    // check whether a dll given by parameter:dllName exist in a dlllsInProcess  
	TCHAR* ExtraDllNameInPath( TCHAR* dllFullPath );        // extra module name from a full path  
};  