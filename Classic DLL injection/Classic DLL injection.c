#include <Windows.h>
#include <TlHelp32.h>

int main()
{
	LPCTSTR sTargetProcessName = L"target.exe";
	WCHAR sDllPath[] = L"injectme.dll";

	// locate LoadLibrary()
	HMODULE hKernel32 = GetModuleHandle((LPCTSTR)L"kernel32");
	FARPROC fpLoadLibrary = GetProcAddress(hKernel32, (LPCSTR)"LoadLibraryW");
		
	// retrieve & walk process snapshot
	HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hProcessSnapshot, &pe32);

	HANDLE hRemoteProcess;
	do {
		if (0 == lstrcmp(sTargetProcessName, pe32.szExeFile)) {
			hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			CloseHandle(hProcessSnapshot);
			break;
		}
	} while (Process32Next(hProcessSnapshot, &pe32));

	// allocate space for dll path in target process
	LPVOID pRemoteAllocation = VirtualAllocEx(hRemoteProcess, NULL, sizeof(sDllPath), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	// write dll path to target process
	WriteProcessMemory(hRemoteProcess, pRemoteAllocation, sDllPath, sizeof(sDllPath), NULL);

	// create a remote thread in the target process
	HANDLE hRemoteThread = CreateRemoteThread(hRemoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fpLoadLibrary, pRemoteAllocation, 0, NULL);
	CloseHandle(hRemoteProcess);

	return 0;
}