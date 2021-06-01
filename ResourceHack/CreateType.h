#pragma once
#include <Windows.h>

class OriginalHandle {
	HANDLE _handle = 0;
public:
	OriginalHandle(HANDLE handle) : _handle(handle) {}
	~OriginalHandle() {
		if (this->_handle)
			CloseHandle(this->_handle);
	}

	HANDLE get_handle() {
		return this->_handle;
	}
};

class IMAGE_PE_HEADER {
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS64 nt_headers;
	PIMAGE_SECTION_HEADER section_header;

public:
	template<typename T>
	IMAGE_PE_HEADER(T pe_binary) :
		section_header((PIMAGE_SECTION_HEADER)((ULONGLONG)nt_headers + sizeof(IMAGE_NT_HEADERS64))),
		nt_headers((PIMAGE_NT_HEADERS64)((ULONGLONG)dos_header + dos_header->e_lfanew)),
		dos_header((PIMAGE_DOS_HEADER)pe_binary) {}

	auto get_dos() { return this->dos_header; }
	auto get_nt() { return this->nt_headers; }
	auto get_section() { return this->section_header; }
};

typedef IMAGE_PE_HEADER* PIMAGE_PE_HEADER;
