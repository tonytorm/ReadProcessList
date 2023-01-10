#pragma once
#include <windows.h>
#include <winternl.h>
#include <string.h>
#include <vector>
#include <iostream>

/* Definitions used to enumerate handles */
#define NT_SUCCESS(x) ((signed int)(x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemHandleInformation 16
#define ProcessHandleInformation 0x33
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define BUFSIZE 512
#define ObjectTypeInformation 2

class FileHandleFinder
{
public :
	bool FindProcessIDByName(std::string nameToLookFor, int& ID); 
	std::string GetLastWinErrorAsString();
	BOOL GetFileNameFromHandle(HANDLE hFile, WCHAR* fName);
	int findProcessFileHandles(int ourID, std::vector<std::string>& filePaths);    // using NtQuerySystemInformation
};

