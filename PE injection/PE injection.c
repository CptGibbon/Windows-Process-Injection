#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>

void function();

int main()
{
	LPCTSTR sTargetProcessName = L"target.exe";

	// get handle to our process image and retrieve appropriate PE headers
	HMODULE hThisProcess = GetModuleHandle(NULL);
	PIMAGE_NT_HEADERS PEHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)hThisProcess + ((PIMAGE_DOS_HEADER)hThisProcess)->e_lfanew);
	DWORD dwModuleSize = PEHeaders->OptionalHeader.SizeOfImage;

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

	// allocate space for module in target process
	LPVOID lpRemoteAllocation = VirtualAllocEx(hRemoteProcess, NULL, dwModuleSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// difference between remote and local image addresses
	DWORD_PTR delta = (DWORD_PTR)((LPBYTE)lpRemoteAllocation - ((LPBYTE)hThisProcess));

	// local copy of module image in preparation for reloc fixups
	LPBYTE pLocalCopy = malloc(dwModuleSize);
	memcpy(pLocalCopy, hThisProcess, dwModuleSize);

	// find .reloc section
	PIMAGE_DATA_DIRECTORY pDataDirectory = &PEHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	PIMAGE_BASE_RELOCATION relocs = (PIMAGE_BASE_RELOCATION)(pLocalCopy + pDataDirectory->VirtualAddress);

	// walk reloc blocks
	while (relocs->VirtualAddress != 0) {
		// only process if block contains relocation descriptors
		if (relocs->SizeOfBlock > sizeof(IMAGE_BASE_RELOCATION)) {
			// count relocation descriptors
			DWORD dwNumDesciptors = (relocs->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			LPWORD lpwDescriptorList = (LPWORD)((LPBYTE)relocs + sizeof(IMAGE_BASE_RELOCATION));

			// for each descriptor
			for (DWORD i = 0; i < dwNumDesciptors; i++) {
				if (lpwDescriptorList[i] > 0) {
					// 'fix' points to fixup location
					DWORD_PTR* fix = (DWORD_PTR*)(pLocalCopy + (relocs->VirtualAddress + (0x0FFF & (lpwDescriptorList[i]))));
					// add delta to fix address for new location in remote process
					*fix += delta;
				}
			}
		}
		// point 'relocs' at next reloc block
		relocs = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocs + relocs->SizeOfBlock);
	}

	// write fixed module to target process
	size_t szBytesWritten;
	WriteProcessMemory(hRemoteProcess, lpRemoteAllocation, pLocalCopy, dwModuleSize, &szBytesWritten);
	free(pLocalCopy);

	// calculate address of function() in remote process
	LPTHREAD_START_ROUTINE tStartRoutine = (LPTHREAD_START_ROUTINE)((LPBYTE)lpRemoteAllocation + ((LPBYTE)function - (LPBYTE)hThisProcess));

	// create remote thread in target process
	DWORD dwRemoteThreadID;
	HANDLE hRemoteThread = CreateRemoteThread(hRemoteProcess, NULL, 0, tStartRoutine, NULL, 0, &dwRemoteThreadID);
	CloseHandle(hRemoteProcess);

	return 0;
}

// call this from the remote process
void function()
{
	_tprintf(TEXT("function() called successfully\n"));
}
