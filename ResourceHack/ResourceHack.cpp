#include "CreateType.h"
#include "FileOperations.h"

#include <iostream>
using namespace std;

PIMAGE_SECTION_HEADER NewSection(PIMAGE_PE_HEADER header) {
	PIMAGE_SECTION_HEADER begin_section{ &header->get_section()[0] };
	PIMAGE_SECTION_HEADER end_section{ &header->get_section()[header->get_nt()->FileHeader.NumberOfSections - 1] };
	PIMAGE_SECTION_HEADER new_section{ &header->get_section()[header->get_nt()->FileHeader.NumberOfSections] };

	memcpy_s(new_section->Name, sizeof(new_section->Name), ".hacked", 8);
	new_section->VirtualAddress =
		((end_section->VirtualAddress + end_section->Misc.VirtualSize) / header->get_nt()->OptionalHeader.SectionAlignment + 1)
		* header->get_nt()->OptionalHeader.SectionAlignment;

	++header->get_nt()->FileHeader.NumberOfSections;

	return (size_t)new_section - (size_t)header->get_dos() < begin_section->PointerToRawData ? new_section : nullptr;
}

void ResourceResetting(PIMAGE_RESOURCE_DIRECTORY& resource_base, DWORD& resource_virtual_address, DWORD& hacked_virtual_address, PIMAGE_RESOURCE_DIRECTORY& resource_directory, LPVOID& after_buffer, DWORD& after_size, LPVOID& before_buffer, DWORD& before_size) {
	PIMAGE_RESOURCE_DIRECTORY_ENTRY resource_entry{ (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((ULONGLONG)resource_directory + sizeof(*resource_directory)) };

	for (int i = 0; i < (resource_directory->NumberOfNamedEntries + resource_directory->NumberOfIdEntries); ++i) {
		if (resource_entry[i].DataIsDirectory) {
			PIMAGE_RESOURCE_DIRECTORY resource{ (PIMAGE_RESOURCE_DIRECTORY)((ULONGLONG)resource_base + resource_entry[i].OffsetToDirectory) };
			ResourceResetting(resource_base, resource_virtual_address, hacked_virtual_address, resource, after_buffer, after_size, before_buffer, before_size);
		}
		else {
			PIMAGE_RESOURCE_DATA_ENTRY data_entry{ (PIMAGE_RESOURCE_DATA_ENTRY)((ULONGLONG)resource_base + resource_entry[i].OffsetToDirectory) };
			
			data_entry->OffsetToData -= resource_virtual_address;
			data_entry->OffsetToData += hacked_virtual_address;

			LPVOID check_address{ (LPVOID)((ULONGLONG)resource_base + data_entry->OffsetToData - hacked_virtual_address) };
			if (memcmp(check_address, before_buffer, before_size) == 0) {
				data_entry->OffsetToData = (ULONGLONG)after_buffer - (ULONGLONG)resource_base + hacked_virtual_address;
			}
		}
	}
}

LPVOID ResourceHack(LPVOID& buffer, DWORD& size, string& after_path, string& before_path) {
	PIMAGE_PE_HEADER pe_header{ new IMAGE_PE_HEADER(buffer) };
	PIMAGE_DATA_DIRECTORY rsrc_data_dir{ &pe_header->get_nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE] };
	LPVOID write_buffer{ nullptr };
	DWORD write_size{ size };

	auto hacked_section = NewSection(pe_header);

	if (rsrc_data_dir->VirtualAddress && rsrc_data_dir->Size) {
		LPVOID resource_buffer{ nullptr };
		DWORD resource_size{ 0 };
		LPVOID after_buffer{ nullptr };
		DWORD after_size{ 0 };
		PIMAGE_SECTION_HEADER resource_section{ nullptr };

		for (WORD i = 0; i < pe_header->get_nt()->FileHeader.NumberOfSections; ++i) {
			if (rsrc_data_dir->VirtualAddress == pe_header->get_section()[i].VirtualAddress) {
				resource_buffer = (LPVOID)((ULONGLONG)pe_header->get_dos() + pe_header->get_section()[i].PointerToRawData);
				resource_size = pe_header->get_section()[i].Misc.VirtualSize;
				hacked_section->Characteristics = pe_header->get_section()[i].Characteristics;
				resource_section = &pe_header->get_section()[i];
			}
		}
		write_size += (resource_size / 0x10 + 2) * 0x10;

		after_size = DiskToMemory(after_path, after_buffer);
		write_size += after_size;
		write_size = (write_size / pe_header->get_nt()->OptionalHeader.FileAlignment + 1) * pe_header->get_nt()->OptionalHeader.FileAlignment;

		hacked_section->Misc.VirtualSize = (resource_size / 0x10 + 2) * 0x10 + after_size;
		pe_header->get_nt()->OptionalHeader.SizeOfImage = ((hacked_section->VirtualAddress + hacked_section->Misc.VirtualSize) / pe_header->get_nt()->OptionalHeader.SectionAlignment + 1) * pe_header->get_nt()->OptionalHeader.SectionAlignment;
		hacked_section->SizeOfRawData = (((resource_size / 0x10 + 2) * 0x10 + after_size) / pe_header->get_nt()->OptionalHeader.FileAlignment + 1) * pe_header->get_nt()->OptionalHeader.FileAlignment;
		hacked_section->PointerToRawData = size;
		rsrc_data_dir->VirtualAddress = hacked_section->VirtualAddress;
		rsrc_data_dir->Size = hacked_section->Misc.VirtualSize;

		write_buffer = VirtualAlloc(nullptr, write_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		memcpy_s(write_buffer, write_size, buffer, size);
		memcpy_s((LPVOID)((ULONGLONG)write_buffer + size), write_size - size, resource_buffer, resource_size);
		memcpy_s((LPVOID)((ULONGLONG)write_buffer + size + (resource_size / 0x10 + 2) * 0x10), write_size - size - (resource_size / 0x10 + 2) * 0x10, after_buffer, after_size);

		PIMAGE_RESOURCE_DIRECTORY hacked_dir{ (PIMAGE_RESOURCE_DIRECTORY)((ULONGLONG)write_buffer + size) };
		LPVOID before_buffer{ nullptr };
		DWORD before_size{ 0 };
		before_size = DiskToMemory(before_path, before_buffer);
		after_buffer = (LPVOID)((ULONGLONG)write_buffer + size + (resource_size / 0x10 + 2) * 0x10);
		ResourceResetting(hacked_dir, resource_section->VirtualAddress, hacked_section->VirtualAddress, hacked_dir, after_buffer, after_size, before_buffer, before_size);
	}


	if (pe_header)
		delete pe_header;

	size = write_size;
	return write_buffer;
}

int main() {
	string path{ "C:\\temp\\6_decode.bin" };
	string after_path{ "C:\\temp\\after.bin" };
	string before_path{ "C:\\temp\\before.bin" };
	LPVOID read_buffer{ nullptr };
	DWORD size{ 0 };
	LPVOID write_buffer{ nullptr };

	size = DiskToMemory(path, read_buffer);

	path += ".exe";

	write_buffer = ResourceHack(read_buffer, size, after_path, before_path);

	MemoryToDisk(path.c_str(), write_buffer, size);
}