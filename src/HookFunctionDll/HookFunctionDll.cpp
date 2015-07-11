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

#include <hooklib.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <Windows.h>

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

BOOL WINAPI DllMain(HINSTANCE module_handle, DWORD reason_for_call, LPVOID reserved)
{
	return TRUE;
}

extern "C" __declspec(dllexport) ENTRY_STUB_TRAMP* Hook(HookInformation* hookInformation)
{
	printf("Hooking function at %08X.\r\n", hookInformation->HookAddress);
	printf("Calling function %s ", hookInformation->FunctionName);
	printf("in DLL %s.\r\n", hookInformation->LibraryPath);
	
	HMODULE hLibrary = GetModuleHandle(hookInformation->LibraryPath);
	if (hLibrary == NULL)
		hLibrary = LoadLibrary(hookInformation->LibraryPath);

	if (hLibrary == NULL)
		return NULL;

	FARPROC pFunction = GetProcAddress(hLibrary, hookInformation->FunctionName);
	if (pFunction == NULL)
		return NULL;

	if (strcmp(hookInformation->FunctionName, "PythonHook") == 0)
	{
		void* (*pythonHook)(const char* functionName, const char* declSpec, int parameters, const char* format) = (void* (*)(const char* functionName, const char* declSpec, int parameters, const char* format))(pFunction);
		pFunction = (FARPROC)pythonHook(hookInformation->AdditionalParameters[0], hookInformation->AdditionalParameters[1], atoi(hookInformation->AdditionalParameters[2]), strlen(hookInformation->AdditionalParameters[3]) < 1 ? NULL : hookInformation->AdditionalParameters[3]);
	}

	ENTRY_STUB_TRAMP* pFileStub;
	DWORD dwRet = EntryStub_create(&pFileStub, (void*)hookInformation->HookAddress, SIZEOF_JMPPATCH);
	if (dwRet == HOOKING_SUCCESS)
	{
		BOOL bFunctionHooked = EntryStub_hook(pFileStub, pFunction);

		if (bFunctionHooked == FALSE)
			dwRet = HOOKING_FAILURE;
	}

	FARPROC pSetOriginalFunctionMappingFunction = GetProcAddress(hLibrary, "SetOriginalFunctionMapping");
	if (pFunction != NULL)
		((void(*)(void* from, void* to))pSetOriginalFunctionMappingFunction)(pFunction, pFileStub->pTrampoline);

	return pFileStub;
}

extern "C" __declspec(dllexport) void Unhook(ENTRY_STUB_TRAMP* stubTramp)
{
	EntryStub_unhook(stubTramp);
	delete stubTramp;
}
