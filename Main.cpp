#include <conio.h>  
#include "stdafx.h" 
#include <windows.h>  
#include <tlhelp32.h>  
#include <shlwapi.h>  
#include <stdio.h>  

//Defenierung von notwendigen Variabeln
#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ 
#define WIN32_LEAN_AND_MEAN  


//Deklarierung von der Prozess ID
DWORD GetProcessId(IN PCHAR szExeName);

//Deklarierung unserer Funktion 
BOOL CreateRemoteThreadInject(DWORD ID, const char * dll);


int main()

{
	//Dec unserer DLL Variabel 
	char dll[MAX_PATH];
	// You can inject more then 1 dll at the time, however we need to declare them ofc > char dll2[MAX_PATH];
	GetFullPathName("your.dll", MAX_PATH, dll, NULL); // Pfad der DLL | Genaue Pfad Angabe nicht nötig falls sich die DLL im selben Ordner wie der Injector befindet
	//^dll2 > GetFullPathName("your.dll", MAX_PATH, dll2, NULL);


	//Funktion für Process ID
	DWORD ID = GetProcessId("target.exe");
	if (!CreateRemoteThreadInject(ID, dll))
	{
		//Wenn  creatermote true returnd 
		printf("Injection failed");
		Sleep(3000);
		exit(1);

	}
	else
	{
		printf("Injection Sucsessfull !");
		Sleep(3000);

	}

	/*if (!CreateRemoteThreadInject(ID, dll2))
	{
		//Wenn  creatermote true returnd 
		printf("Injection of second dll failed");
		Sleep(3000);


	}
	else
	{
		printf("Injection of second dll Sucsessfull !");
		Sleep(3000);
		exit(1);
			
	}*/

}

DWORD GetProcessId(IN PCHAR szExeName)

{
	DWORD dwCount = 0;
	DWORD dwRet = 0;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 pe = { 0 };
		pe.dwSize = sizeof(PROCESSENTRY32);

		BOOL bRet = Process32First(hSnapshot, &pe);

		while (bRet)
		{
			if (!_stricmp(pe.szExeFile, szExeName))
			{
				dwCount++;
				dwRet = pe.th32ProcessID;
			}
			bRet = Process32Next(hSnapshot, &pe);
		}

		if (dwCount > 1)
			dwRet = 0xFFFFFFFF;

		CloseHandle(hSnapshot);
	}

	return dwRet;
}

BOOL CreateRemoteThreadInject(DWORD ID, const char * dll)

{
	LPVOID LoadLibrary;

	//Dec der memory welche wir allocaten
	LPVOID Memory;


	//Handle für unsere Prozesse 
	HANDLE Process;



	//Wenn wir keine process id haben wird false returnd 
	if (!ID)
	{
		return false;
	}

	Process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, ID);

	//Suchen der load libarry
	LoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

	Memory = (LPVOID)VirtualAllocEx(Process, NULL, strlen(dll) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// String Name unserer DLL wird in memory allocated
	WriteProcessMemory(Process, (LPVOID)Memory, dll, strlen(dll) + 1, NULL);


	// Laden der DLL
	CreateRemoteThread(Process, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibrary, (LPVOID)Memory, NULL, NULL);

	CloseHandle(Process);



	//Free restliche Memory
	VirtualFreeEx(Process, (LPVOID)Memory, 0, MEM_RELEASE);

	return true;
}
