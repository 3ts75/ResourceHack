#pragma once
#include <Windows.h>

#include <string>

DWORD FileRead(std::string& strFilePath, LPVOID& lpBuffer);

template<class T>
bool FileWrite(const char* strFilePath, T lpBuffer, DWORD& dwFileSize);