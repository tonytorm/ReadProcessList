#include "FileHandleFinder.h"
#include <stdio.h>
#include <Psapi.h>
#include <tchar.h>
#include <strsafe.h>


/* Structures retrieved and queried during handle enumeration */
typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);

typedef NTSTATUS(NTAPI* _NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

/*typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
	HANDLE HandleValue;
	ULONG_PTR HandleCount;
	ULONG_PTR PointerCount;
	ULONG GrantedAccess;
	ULONG ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;*/

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;



std::string FileHandleFinder::GetLastWinErrorAsString()
{
    //Get the error message ID, if any.
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0) {
        return std::string(); //No error message has been recorded
    }

    LPSTR messageBuffer = nullptr;

    //Ask Win32 to give us the string version of that message ID.
    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    //Copy the error message into a std::string.
    std::string message(messageBuffer, size);

    //Free the Win32's string's buffer.
    LocalFree(messageBuffer);

    return message;
}


bool FileHandleFinder::FindProcessIDByName(std::string nameToLookFor, int& ID) {
    
    // Get the list of process identifiers.
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    unsigned int i;

    // convert name for comparison with silly windows string types
    std::string tempN = nameToLookFor + ".exe";
    std::wstring tempW(tempN.begin(), tempN.end());
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)){
        return 1;
    }

    // Calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD);

    // Iterate through each process.
    for (i = 0; i < cProcesses; i++){
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
        if (aProcesses[i] != 0){
            // Get the process name.
            if (NULL != hProcess){
                HMODULE hMod;
                DWORD cbNeeded;

                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
                    &cbNeeded))
                {
                    GetModuleBaseName(hProcess, hMod, szProcessName,
                        sizeof(szProcessName) / sizeof(TCHAR));

                    // Check if the input name equals.
                    
                    if (tempW.compare(szProcessName) == 0) {
                        ID = aProcesses[i];
                        CloseHandle(hProcess);
                        return true;
                    }
                }
            }
        }
        CloseHandle(hProcess);
    }

    ID = -1; 
    return false;
}

BOOL FileHandleFinder::GetFileNameFromHandle(HANDLE hFile, WCHAR* fName)
{
	BOOL bSuccess = FALSE; // Was this function successful?
	TCHAR pszFilename[MAX_PATH + 1]; // Holds filename once retrieved
	HANDLE hFileMap; // Handle used for the CreateFileMapping();

	/* Create file mapping */
	hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

	if (hFileMap)
	{
		/* Map view of file */
		void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

		if (pMem)
		{
			/* At this point, we are able to retrieve the filename */
			if (GetMappedFileName(GetCurrentProcess(), pMem, pszFilename, MAX_PATH))
			{

				/* Now we want to make it into the friendly format with drive lettes etc */
				TCHAR szTemp[BUFSIZE];
				szTemp[0] = '\0';

				if (GetLogicalDriveStrings(BUFSIZE - 1, szTemp))
				{
					TCHAR szName[MAX_PATH];
					TCHAR szDrive[3] = TEXT(" :");
					BOOL bFound = FALSE;
					TCHAR* p = szTemp;

					do
					{
						// Copy the drive letter to the template string
						*szDrive = *p;

						// Look up each device name
						if (QueryDosDevice(szDrive, szName, MAX_PATH))
						{
							size_t uNameLen = _tcslen(szName);

							if (uNameLen < MAX_PATH)
							{
								bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0
									&& *(pszFilename + uNameLen) == _T('\\');

								if (bFound)
								{
									// Reconstruct pszFilename using szTempFile
									// Replace device path with DOS path
									TCHAR szTempFile[MAX_PATH];
									StringCchPrintf(szTempFile, MAX_PATH, TEXT("%s%s"), szDrive, pszFilename + uNameLen);
									StringCchCopyN(pszFilename, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
								}
							}
						}

						// Go to the next NULL character.
						while (*p++);
					} while (!bFound && *p); // end of string
				}
			}
			/* Function completed successfully */
			bSuccess = TRUE;
			UnmapViewOfFile(pMem);
		}

		CloseHandle(hFileMap);
	}
	else {
		CloseHandle(hFileMap);
		return bSuccess;
	}
	/* Copy the filename string into our _OUT_ variable */
	wcscpy_s(fName, MAX_PATH, pszFilename);
	return bSuccess;
}

int FileHandleFinder::findProcessFileHandles(int ourID, std::vector<std::string>& filePaths) {    // using NtQuerySystemInformation

	_NtQuerySystemInformation NtQuerySystemInformation =
		(_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

	_NtDuplicateObject NtDuplicateObject =
		(_NtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject");

	_NtQueryObject NtQueryObject =
		(_NtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");

	NTSTATUS status, status_g;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle;
	ULONG i;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	bool stopLooking = false;

	handleInfoSize = 0x10000;
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

	/* NtQuerySystemInformation won't give us the correct buffer size, so we guess by doubling the buffer size. */
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

	/* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
	if (!NT_SUCCESS(status))
	{
		printf("NtQuerySystemInformation failed!\n");
		return 1;
	}


	/* Loop for each handle on the system, processing it accordingly... */
	for (i = 0; i < handleInfo->HandleCount; i++)
	{
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		//std::cout << "proc id: " << handle.ProcessId << '\n';

		// early exit if it's not our process
		if (handle.ProcessId != ourID) {
			/*std::cout << "exited because this handle ID doesnt match" << '\n';*/
			//if (stopLooking) return 0;
			continue;
		}
		/* Open a handle to the process associated with the handle */
		if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId))) {
			std::cout << "couldnt open process asssociated with handle:  " << GetLastWinErrorAsString() << '\n';
			continue;
		}

		/* Duplicate the handle so we can query it. */
		if (!NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, GENERIC_READ, 0, 0)))
		{
			std::cout << "couldnt duplicate handle:  " << GetLastWinErrorAsString() << '\n';
			CloseHandle(processHandle);
			CloseHandle(dupHandle);
			continue;
		}

		/* Query the object type */
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL)))
		{
			std::cout << "couldnt cast handle into object type:  " << GetLastWinErrorAsString() << '\n';
			free(objectTypeInfo);
			CloseHandle(processHandle);
			CloseHandle(dupHandle);
			continue;
		}

		/* If it's not a file handle, go to next one (as we're only interested in file handles) */
		if (wcscmp(objectTypeInfo->Name.Buffer, L"File"))
		{
			free(objectTypeInfo);
			CloseHandle(processHandle);
			CloseHandle(dupHandle);
			continue;
		}

		/* Identify the filename from the handle we're looking at */
		WCHAR* wHandleFileName = new WCHAR[MAX_PATH]();

		if (!GetFileNameFromHandle(dupHandle, wHandleFileName))
		{
			std::cout << "couldnt identify filename from handle:  " << GetLastWinErrorAsString() << '\n';
			free(objectTypeInfo);
			free(wHandleFileName);
			CloseHandle(processHandle);
			CloseHandle(dupHandle);
			continue;
		}
		std::wcout << wHandleFileName << '\n';
		stopLooking = true;
		std::wstring wFilePath(wHandleFileName);
		std::string filePath(wFilePath.begin(), wFilePath.end());
		filePaths.emplace_back(filePath);

		free(objectTypeInfo);
		free(wHandleFileName);
		CloseHandle(dupHandle);
		CloseHandle(processHandle);
	}
	free(handleInfo);

	return 0;
}

//some very useful source code 
//potentially al the material to enumerate a process handle without having to iterate through every system handle is in the next links
//https://processhacker.sourceforge.io/doc/hndlprv_8c_source.html
//https://processhacker.sourceforge.io/doc/kph_8c_source.html#l00937