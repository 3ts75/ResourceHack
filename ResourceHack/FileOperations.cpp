#include "FileOperations.h"
#include "CreateType.h"

DWORD FileRead(std::string& strFilePath, LPVOID& lpBuffer) {
	DWORD ret{ 0 };

	do {
		OriginalHandle hFile{ CreateFileA(strFilePath.c_str(), GENERIC_READ,
			0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL) };
		if (hFile.get_handle() == INVALID_HANDLE_VALUE) {
			printf("%d", GetLastError());
			break;
		}

		PLARGE_INTEGER lpFileSize{ new LARGE_INTEGER() };
		GetFileSizeEx(hFile.get_handle(), lpFileSize);
		if (!GetFileSizeEx(hFile.get_handle(), lpFileSize)) {
			break;
		}

		//lpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lpFileSize->QuadPart);
		lpBuffer = VirtualAlloc(nullptr, lpFileSize->QuadPart, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (lpBuffer == NULL) {
			break;
		}

		if (!ReadFile(hFile.get_handle(), lpBuffer, lpFileSize->QuadPart, nullptr, NULL)) {
			ret = true;
			break;
		}

		ret = lpFileSize->QuadPart;
	} while (false);

	return ret;
}


template<class T>
bool FileWrite(const char* strFilePath, T lpBuffer, DWORD& dwFileSize) {
	bool ret{ false };

	do {
		OriginalHandle hFile{ CreateFileA(strFilePath, GENERIC_READ | GENERIC_WRITE,
			0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL) };
		if (hFile.get_handle() == INVALID_HANDLE_VALUE) {
			ret = true;
			break;
		}

		if (!WriteFile(hFile.get_handle(), lpBuffer, dwFileSize, nullptr, NULL)) {
			ret = true;
			break;
		}
	} while (false);

	return false;
}

template bool FileWrite<char*>(const char* strFilePath, char* lpBuffer, DWORD& dwFileSize);
template bool FileWrite<LPVOID>(const char* strFilePath, LPVOID lpBuffer, DWORD& dwFileSize);