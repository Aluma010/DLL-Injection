# include <stdio.h>
# include <windows.h>
# include <winternl.h>

// Defines:
typedef NTSTATUS(NTAPI* MYPROC) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID Reserved2[2];
	UNICODE_STRING FullDllName;
	BYTE Reserved4[4];
	PVOID ShortDllName;
	PVOID Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	} DUMMYUNIONNAME;
#pragma warning(pop)
	ULONG TimeDateStamp;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2;
	PVOID pFirstEntry;
	PVOID Reserved3;
	LIST_ENTRY InMemoryOrderModuleList;
} MY_PEB_LDR_DATA, * PMY_PEB_LDR_DATA;

# define MAX_STR_LEN (256)
# define RETURN_ERROR_WRONG_USAGE (13)
# define RETURN_ERROR_FAILED_GETTING_HANDLE (2)
# define RETURN_ERROR_FAILED_LOADING_NTDLL (3)
# define RETURN_ERROR_FAILED_GETTING_NTQUERYINFORMATIONPROCESS (4)
# define RETURN_ERROR_FAILED_USING_NTQUERYINFORMATIONPROCESS (5)
# define RETURN_ERROR_FAILED_GETTING_PEB_ADDRESS (6)
# define RETURN_ERROR_FAILED_GETTING_LDR_DATA (7)
# define RETURN_ERROR_PRINTING_LISTS (8)
# define RETURN_ERROR_DELETING_MODULE (9)
# define RETURN_ERROR_FAILED_DELETING_MODULE_FROM_LOADORDER_LIST (10)
# define RETURN_ERROR_FAILED_DELETING_MODULE_FROM_MEMORYORDER_LIST (11)
# define RETURN_ERROR_FAILED_DELETING_MODULE_FROM_INITIALIZATIONORDER_LIST (12)
# define RETURN_ERROR_FAILED_GETTING_MODULE_FILENAME (14)

// Functions Declarations:
void PrintThreeLists(MY_LDR_DATA_TABLE_ENTRY* inFirstListEntry);
int DeleteModuleFromThreeLists(MY_LDR_DATA_TABLE_ENTRY* inFirstListEntry, char* pModuleToDelete);
int DeleteModuleFromLoadOrder(MY_LDR_DATA_TABLE_ENTRY* inFirstListEntry, char* pModuleToDelete);
int DeleteModuleFromMemoryOrder(MY_LDR_DATA_TABLE_ENTRY* inFirstListEntry, char* pModuleToDelete);
int DeleteModuleFromInitializationOrder(MY_LDR_DATA_TABLE_ENTRY* inFirstListEntry, char* pModuleToDelete);

// Functions Definitions:

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	DWORD dwResult = 0;
	HMODULE hNtdll = NULL;
	LONG lReturnLength = 0;
	HANDLE hTargetProc = NULL;
	PMY_PEB_LDR_DATA pLdrData = NULL;
	NTSTATUS ntTargetProcStatus = { 0 };
	wchar_t wcaFilename[MAX_STR_LEN] = { 0 };
	MY_LDR_DATA_TABLE_ENTRY* myCurEntry = NULL;
	MY_LDR_DATA_TABLE_ENTRY* myFirstEntry = NULL;
	PROCESS_BASIC_INFORMATION TargetInfo = { 0 };
	MYPROC pFunctionNtQueryInformationProcess = NULL;

	// for debugging:
	OutputDebugStringW(L"\ndllTest module loaded successfully! :)\n");

	hTargetProc = GetCurrentProcess();
	if (NULL == hTargetProc)
	{
		printf("Error: Failed to get handle to the target process. Error code is: %d.\nExiting program...", GetLastError());
		return RETURN_ERROR_FAILED_GETTING_HANDLE;
	}

	hNtdll = LoadLibraryW(L"ntdll.dll");
	if (NULL == hNtdll)
	{
		printf("Error: Failed to load NTDLL. Error code is: %d.\nExiting program...", GetLastError());
		CloseHandle(hTargetProc);
		return RETURN_ERROR_FAILED_LOADING_NTDLL;
	}

	pFunctionNtQueryInformationProcess = GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (NULL == pFunctionNtQueryInformationProcess)
	{
		printf("Error: Failed to get function NtQueryInformationProcess. Error code is: %d.\nExiting program...", GetLastError());
		CloseHandle(hTargetProc);
		CloseHandle(hNtdll);
		return RETURN_ERROR_FAILED_GETTING_NTQUERYINFORMATIONPROCESS;
	}

	ntTargetProcStatus = pFunctionNtQueryInformationProcess(hTargetProc, ProcessBasicInformation, &TargetInfo, sizeof(TargetInfo), &lReturnLength);
	if (ERROR_SUCCESS != ntTargetProcStatus)
	{
		printf("Error: Failed to get process information with function NtQueryInformationProcess. Error code is: %d.\nYou should check the error code here: https://davidvielmetter.com/tips/ntstatus-error-code-list/ \nExiting program...", ntTargetProcStatus);
		CloseHandle(hTargetProc);
		CloseHandle(hNtdll);
		return RETURN_ERROR_FAILED_USING_NTQUERYINFORMATIONPROCESS;
	}

	if (NULL == TargetInfo.PebBaseAddress)
	{
		printf("Error: Failed to get process PEB address. Error code is: %d.\nYou should check the error code here: https://davidvielmetter.com/tips/ntstatus-error-code-list/ \nExiting program...", ntTargetProcStatus);
		CloseHandle(hTargetProc);
		CloseHandle(hNtdll);
		return RETURN_ERROR_FAILED_GETTING_PEB_ADDRESS;
	}

	pLdrData = (MY_PEB_LDR_DATA*)TargetInfo.PebBaseAddress->Ldr;
	myFirstEntry = (MY_LDR_DATA_TABLE_ENTRY*)pLdrData->pFirstEntry;
	myCurEntry = (MY_LDR_DATA_TABLE_ENTRY*)myFirstEntry->InLoadOrderLinks.Flink;
	if (NULL == myCurEntry)
	{
		printf("Error: Failed to get modules info for the current process. Check last error code: %d", GetLastError());
		CloseHandle(hTargetProc);
		CloseHandle(hNtdll);
		return RETURN_ERROR_FAILED_GETTING_LDR_DATA;
	}

	// get the wanted dll name to delete
	dwResult = GetModuleFileNameW(hModule, wcaFilename, MAX_STR_LEN);
	if (0 == dwResult)
	{
		printf("Error: An error occured while trying to get module filename. Exiting program.");
		CloseHandle(hTargetProc);
		CloseHandle(hNtdll);
		return RETURN_ERROR_FAILED_GETTING_MODULE_FILENAME;
	}

	if (ERROR_SUCCESS != DeleteModuleFromThreeLists(myFirstEntry, wcaFilename))
	{
		printf("Error: An error occured while trying to delete module from lists via function DeleteModuleFromThreeLists. Exiting program.");
		CloseHandle(hTargetProc);
		CloseHandle(hNtdll);
		return RETURN_ERROR_DELETING_MODULE;
	}

	// for debugging:
	OutputDebugStringW(L"\nModule hiding was sucessful!\n");

	// close handles and exit
	CloseHandle(hNtdll);
	CloseHandle(hTargetProc);

	return TRUE;
}

int DeleteModuleFromThreeLists(MY_LDR_DATA_TABLE_ENTRY* inFirstListEntry, char* pModuleToDelete)
{
	if (DeleteModuleFromLoadOrder(inFirstListEntry, pModuleToDelete))
	{
		return RETURN_ERROR_FAILED_DELETING_MODULE_FROM_LOADORDER_LIST;
	}

	if (DeleteModuleFromMemoryOrder(inFirstListEntry, pModuleToDelete))
	{
		return RETURN_ERROR_FAILED_DELETING_MODULE_FROM_MEMORYORDER_LIST;
	}

	if (DeleteModuleFromInitializationOrder(inFirstListEntry, pModuleToDelete))
	{
		return RETURN_ERROR_FAILED_DELETING_MODULE_FROM_INITIALIZATIONORDER_LIST;
	}

	return ERROR_SUCCESS;
}

int DeleteModuleFromLoadOrder(MY_LDR_DATA_TABLE_ENTRY* inFirstListEntry, char* pModuleToDelete)
{
	MY_LDR_DATA_TABLE_ENTRY* pCurEntry = (MY_LDR_DATA_TABLE_ENTRY*)inFirstListEntry->InLoadOrderLinks.Flink;
	MY_LDR_DATA_TABLE_ENTRY* pPreEntry = inFirstListEntry;
	void* pStop = (void*)pCurEntry->InLoadOrderLinks.Blink->Blink;  // we take 2 steps backwards because we want to avoid the "HideDLL.exe" entry and get back the address of the ldr;

	do
	{
		if (0 == wcscmp(pModuleToDelete, pCurEntry->FullDllName.Buffer))			// If this is the wanted DLL to hide
		{
			pPreEntry->InLoadOrderLinks.Flink = pCurEntry->InLoadOrderLinks.Flink;
			pCurEntry->InLoadOrderLinks.Flink->Blink = (LIST_ENTRY*)pPreEntry;
			return 0;
		}
		pPreEntry = pCurEntry;
		pCurEntry = (MY_LDR_DATA_TABLE_ENTRY*)pCurEntry->InLoadOrderLinks.Flink;
	} while (pStop != pCurEntry);		// This is our way to check is we've seen all of the modules

	return 1;
}

int DeleteModuleFromMemoryOrder(MY_LDR_DATA_TABLE_ENTRY* inFirstListEntry, char* pModuleToDelete)
{
	MY_LDR_DATA_TABLE_ENTRY* pCurEntry = (MY_LDR_DATA_TABLE_ENTRY*)inFirstListEntry->InLoadOrderLinks.Flink;
	MY_LDR_DATA_TABLE_ENTRY* pPreEntry = inFirstListEntry;
	void* pStop = (void*)pCurEntry->InLoadOrderLinks.Blink->Blink;  // we take 2 steps backwards because we want to avoid the "HideDLL.exe" entry and get back the address of the ldr;

	do
	{
		if (0 == wcscmp(pModuleToDelete, pCurEntry->FullDllName.Buffer))			// If this is the wanted DLL to hide
		{
			pPreEntry->InMemoryOrderLinks.Flink = pCurEntry->InMemoryOrderLinks.Flink;
			pCurEntry->InMemoryOrderLinks.Flink->Blink = (LIST_ENTRY*)pPreEntry;
			return 0;
		}
		pPreEntry = pCurEntry;
		pCurEntry = (MY_LDR_DATA_TABLE_ENTRY*)(((char*)pCurEntry->InMemoryOrderLinks.Flink) - sizeof(LIST_ENTRY));
	} while (pStop != pCurEntry);		// This is our way to check is we've seen all of the modules

	return 1;
}

int DeleteModuleFromInitializationOrder(MY_LDR_DATA_TABLE_ENTRY* inFirstListEntry, char* pModuleToDelete)
{
	MY_LDR_DATA_TABLE_ENTRY* pCurEntry = (MY_LDR_DATA_TABLE_ENTRY*)inFirstListEntry->InLoadOrderLinks.Flink;
	MY_LDR_DATA_TABLE_ENTRY* pPreEntry = inFirstListEntry;
	void* pStop = (void*)pCurEntry->InLoadOrderLinks.Blink->Blink;  // we take 2 steps backwards because we want to avoid the "HideDLL.exe" entry and get back the address of the ldr;

	do
	{
		if (0 == wcscmp(pModuleToDelete, pCurEntry->FullDllName.Buffer))			// If this is the wanted DLL to hide
		{
			pPreEntry->InInitializationOrderLinks.Flink = pCurEntry->InInitializationOrderLinks.Flink;
			pCurEntry->InInitializationOrderLinks.Flink->Blink = (LIST_ENTRY*)pPreEntry;
			return 0;
		}
		pPreEntry = pCurEntry;
		if (0 == pCurEntry->InInitializationOrderLinks.Flink)
		{
			pCurEntry = (MY_LDR_DATA_TABLE_ENTRY*)pCurEntry->InLoadOrderLinks.Flink;
		}
		else
		{
			pCurEntry = (MY_LDR_DATA_TABLE_ENTRY*)(((char*)pCurEntry->InInitializationOrderLinks.Flink) - 2*sizeof(LIST_ENTRY));
		}
	} while (pStop != pCurEntry);		// This is our way to check is we've seen all of the modules

	return 1;
}

// the function PrintThreeLists prints the 3 LDR lists. 
// the function isn't in use as part of this module, but should be used for debugging only.
void PrintThreeLists(MY_LDR_DATA_TABLE_ENTRY* inFirstListEntry)
{
	MY_LDR_DATA_TABLE_ENTRY* pCurEntry = inFirstListEntry;
	void* pStop = (void*)pCurEntry->InLoadOrderLinks.Blink->Blink;  // we take 2 steps backwards because we want to avoid the "HideDLL.exe" entry and get back the address of the ldr;
	int i = 0;

	printf("\nPrinting LoadOrder List:\n");
	i = 1;
	do
	{
		printf("LoadOrder List, Module n. %d is: %ls\n", i, pCurEntry->FullDllName.Buffer);

		i++;
		pCurEntry = (MY_LDR_DATA_TABLE_ENTRY*)pCurEntry->InLoadOrderLinks.Flink;
	} while (pStop != pCurEntry);

	printf("\nPrinting MemoryOrder List:\n");
	i = 1;
	pCurEntry = inFirstListEntry;
	do
	{
		printf("MemoryOrder List, Module n. %d is: %ls\n", i, pCurEntry->FullDllName.Buffer);

		i++;
		pCurEntry = (MY_LDR_DATA_TABLE_ENTRY*)(((char*)pCurEntry->InMemoryOrderLinks.Flink) - sizeof(LIST_ENTRY));
	} while (pStop != pCurEntry);

	printf("\nPrinting InitializationOrder List:\n");
	i = 1;
	pCurEntry = inFirstListEntry;
	do
	{
		printf("InitializationOrder List, Module n. %d is: %ls\n", i, pCurEntry->FullDllName.Buffer);

		i++;
		pCurEntry = (MY_LDR_DATA_TABLE_ENTRY*)(((char*)pCurEntry->InInitializationOrderLinks.Flink) - 2*sizeof(LIST_ENTRY));
	} while (pStop != pCurEntry);

}
