/*  This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>. */

﻿#include <Windows.h>
#include <windef.h>
#include <stdio.h>
#include <strsafe.h>
#include <TlHelp32.h>
#include <errno.h>
#include <string>
#include <iostream>
#include <direct.h>

typedef struct _HookInformation
{
	__int64 HookAddress;
	char LibraryPath[MAX_PATH];
	char FunctionName[64];
	char AdditionalParameters[4][64];
} HookInformation;

void __cdecl odprintf(const char *format, ...)
{
	char    buf[4096], *p = buf;
	va_list args;
	int     n;

	va_start(args, format);
	n = _vsnprintf_s(p, 4096, sizeof buf - 3, format, args); // buf-3 is room for CR/LF/NUL
	va_end(args);

	p += (n < 0) ? sizeof buf - 3 : n;

	while (p > buf  &&  isspace(p[-1]))
		*--p = '\0';

	*p++ = '\r';
	*p++ = '\n';
	*p = '\0';

	OutputDebugStringA(buf);
}

void ErrorExit(LPTSTR lpszFunction, LPCSTR lpAdditionalHelp)
{
	// Retrieve the system error message for the last-error code
	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("ERROR: %s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	//MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	wprintf((LPWSTR)lpDisplayBuf);
	if (lpAdditionalHelp != NULL)
		printf("ADDITIONAL HELP: %s\n", lpAdditionalHelp);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}


DWORD GetModuleHandleInjection(HANDLE proc, PCHAR dllName)
{
	LPVOID RemoteString = NULL, GetModuleHandleAddy;
	GetModuleHandleAddy = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleA");

	if (dllName != NULL)
	{
		RemoteString = (LPVOID)VirtualAllocEx(proc, NULL, strlen(dllName), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (RemoteString == NULL)
		{
			CloseHandle(proc); // Close the process handle.
			ErrorExit(TEXT("VirtualAllocEx"), NULL);
		}

		if (WriteProcessMemory(proc, (LPVOID)RemoteString, dllName, strlen(dllName), NULL) == 0)
		{
			VirtualFreeEx(proc, RemoteString, 0, MEM_RELEASE); // Free the memory we were going to use.
			CloseHandle(proc); // Close the process handle.
			ErrorExit(TEXT("WriteProcessMemory"), NULL);
		}
	}

	HANDLE hThread = CreateRemoteThread(proc, NULL, NULL, (LPTHREAD_START_ROUTINE)GetModuleHandleAddy, (LPVOID)RemoteString, NULL, NULL);
	if (hThread == NULL)
	{
		VirtualFreeEx(proc, RemoteString, 0, MEM_RELEASE); // Free the memory we were going to use.
		CloseHandle(proc); // Close the process handle.
		ErrorExit(TEXT("CreateRemoteThread"), NULL);
	}

	DWORD dwThreadExitCode = 0;

	// Lets wait for the thread to finish 10 seconds is our limit.
	// During this wait, DllMain is running in the injected DLL, so
	// DllMain has 10 seconds to run.
	WaitForSingleObject(hThread, 10000);

	// Lets see what it says...
	GetExitCodeThread(hThread, &dwThreadExitCode);

	// No need for this handle anymore, lets get rid of it.
	CloseHandle(hThread);

	// Lets clear up that memory we allocated earlier.
	VirtualFreeEx(proc, RemoteString, 0, MEM_RELEASE);

	return dwThreadExitCode;
}

DWORD LoadLibraryInjection(HANDLE proc, PCHAR dllName)
{
	LPVOID RemoteString, LoadLibAddy;
	LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	RemoteString = (LPVOID)VirtualAllocEx(proc, NULL, strlen(dllName), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (RemoteString == NULL)
	{
		CloseHandle(proc); // Close the process handle.
		ErrorExit(TEXT("VirtualAllocEx"), NULL);
	}

	if (WriteProcessMemory(proc, (LPVOID)RemoteString, dllName, strlen(dllName), NULL) == 0)
	{
		VirtualFreeEx(proc, RemoteString, 0, MEM_RELEASE); // Free the memory we were going to use.
		CloseHandle(proc); // Close the process handle.
		ErrorExit(TEXT("WriteProcessMemory"), NULL);
	}
	
	HANDLE hThread;
	if ((hThread = CreateRemoteThread(proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL)) == NULL)
	{
		VirtualFreeEx(proc, RemoteString, 0, MEM_RELEASE); // Free the memory we were going to use.
		CloseHandle(proc); // Close the process handle.
		ErrorExit(TEXT("CreateRemoteThread"), NULL);
	}

	DWORD dwThreadExitCode = 0;

	// Lets wait for the thread to finish 10 seconds is our limit.
	// During this wait, DllMain is running in the injected DLL, so
	// DllMain has 10 seconds to run.
	WaitForSingleObject(hThread, 10000);

	// Lets see what it says...
	GetExitCodeThread(hThread, &dwThreadExitCode);

	// No need for this handle anymore, lets get rid of it.
	CloseHandle(hThread);

	// Lets clear up that memory we allocated earlier.
	VirtualFreeEx(proc, RemoteString, 0, MEM_RELEASE);

	// Alright lets remove this DLL from the loaded DLL list!
	WCHAR dllNameW[MAX_PATH];
	MultiByteToWideChar(CP_UTF8, 0, dllName, (int)(strlen(dllName) + 1), dllNameW, MAX_PATH);

	return dwThreadExitCode;
}

int GetFunctionOffset(const char* libraryPath, const char* name)
{
	HMODULE hLibrary = GetModuleHandle(libraryPath);
	if (hLibrary == NULL)
		hLibrary = LoadLibrary(libraryPath);

	if (hLibrary == NULL)
		return -1;

	FARPROC functionAddress = GetProcAddress(hLibrary, name);
	if (functionAddress == 0)
		return -1;

	return (int)((__int64)functionAddress - (__int64)hLibrary);
}


int main(int argc, const char* argv[])
{
	if (argc < 6)
	{
		printf("Usage: hookfunction [executableName|pid] moduleName hookAddress libraryPath functionName\r\n");
		return 3;
	}

	char* temp;
	int pid = (int)strtol(argv[1], &temp, 10);
	if (errno == ERANGE || temp != '\0')
	{
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (hSnapshot == INVALID_HANDLE_VALUE)
			return 1;

		PROCESSENTRY32 processEntry;
		memset(&processEntry, 0, sizeof(processEntry));
		processEntry.dwSize = sizeof(processEntry);
		if (!Process32First(hSnapshot, &processEntry))
			return 2;

		do
		{
			if (strcmp(processEntry.szExeFile, argv[1]) == 0)
				pid = processEntry.th32ProcessID;
		} while (Process32Next(hSnapshot, &processEntry));

		CloseHandle(hSnapshot);
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
		return 5;

	char libraryPath[MAX_PATH];
	_getcwd(libraryPath, sizeof(libraryPath));
	strcat(libraryPath, "\\HookFunctionDll.dll");

	DWORD hRemoteModule = GetModuleHandleInjection(hProcess, libraryPath);
	if (hRemoteModule == NULL)
		LoadLibraryInjection(hProcess, libraryPath);
	hRemoteModule = GetModuleHandleInjection(hProcess, libraryPath);

	if (hRemoteModule == NULL)
		return 6;

	HookInformation hookInformation;
	memset(&hookInformation, 0, sizeof(hookInformation));

	char moduleName[MAX_PATH];
	strcpy(moduleName, argv[2]);

	hookInformation.HookAddress = strtol(argv[3], NULL, 16) + GetModuleHandleInjection(hProcess, NULL);
	strcpy(hookInformation.LibraryPath, argv[4]);
	strcpy(hookInformation.FunctionName, argv[5]);

	if (sizeof(hookInformation.AdditionalParameters) > 0)
	{
		for (int i = 0; i < sizeof(hookInformation.AdditionalParameters) / sizeof(hookInformation.AdditionalParameters[0]) && 6 + i < argc; i++)
			strcpy_s(hookInformation.AdditionalParameters[i], argv[6 + i]);
	}

	void* data = VirtualAllocEx(hProcess, NULL, sizeof(hookInformation), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	SIZE_T bytesWritten;
	WriteProcessMemory(hProcess, data, &hookInformation, sizeof(hookInformation), &bytesWritten);

	int hookFunctionOffset = GetFunctionOffset(libraryPath, "Hook");
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(hRemoteModule + hookFunctionOffset), data, 0, NULL);

	DWORD dwThreadExitCode = 0;
	WaitForSingleObject(hThread, 10000);

	GetExitCodeThread(hThread, &dwThreadExitCode);
	CloseHandle(hThread);

	//Don't free leave it because it is being used actively by python hooks
	//VirtualFree(data, NULL, MEM_FREE);

	/*printf("Unhook? (y/n)\r\n");
	std::string answer;
	std::cin >> answer;

	if (strcmp(answer.c_str(), "y") == 0)
	{
		int unhookFunctionOffset = GetFunctionOffset(libraryPath, "Unhook");
		hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(hRemoteModule + unhookFunctionOffset), data, 0, NULL);
		WaitForSingleObject(hThread, 10000);
		CloseHandle(hThread);
	}*/

	return 0;
}
