#include "stdafx.h"
#include <windows.h>
#include <stdio.h>


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBox(NULL, L"DllMain loaded - DLL_PROCESS_ATTACH", L"Success", 0);
	case DLL_PROCESS_DETACH:
		MessageBox(NULL, L"DllMain loaded - DLL_PROCESS_DETACH", L"Success", 0);
	case DLL_THREAD_ATTACH:
		MessageBox(NULL, L"DllMain loaded - DLL_THREAD_ATTACH", L"Success", 0);
	case DLL_THREAD_DETACH:
		MessageBox(NULL, L"DllMain loaded - DLL_THREAD_DETACH", L"Success", 0);
	}
	return TRUE;
}

extern "C" __declspec(dllexport) BOOL poc()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	WCHAR wszCommandLine[MAX_PATH];
	wcscpy_s(wszCommandLine, L"C:\\windows\\system32\\notepad.exe");

	// Start the child process. 
	if (!CreateProcess(NULL,   // No module name (use command line)
		wszCommandLine,        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		printf("CreateProcess failed (%d).\n", GetLastError());
		return false;
	}

	// Wait until child process exits.
	WaitForSingleObject(pi.hProcess, INFINITE);

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}
