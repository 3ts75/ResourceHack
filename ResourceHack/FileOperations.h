#pragma once
#include <Windows.h>

#include <string>

DWORD DiskToMemory(std::string& strFilePath, LPVOID& lpBuffer);

template<class T>
bool MemoryToDisk(const char* strFilePath, T lpBuffer, DWORD& dwFileSize);