#pragma once

#include "nal.h"

#include <cstdint>
#include <string>
#include <vector>

struct Payload {
	uint64_t image = 0;
	uint64_t image_size = 0;
	uint64_t stub = 0;
	uint64_t gate = 0;
	uint64_t nt_add_atom = 0;
	uint32_t hook_len = 0;
	uint8_t original[32] = {};
	bool hooked = false;
	void* comm = 0;
	void* data = 0;
};

bool map_payload(Nal* nal, const std::vector<uint8_t>& file, void* comm, void* data, Payload* out, std::string* error);
bool install_gate(Nal* nal, Payload* payload, std::string* error);
bool remove_gate_and_free(Nal* nal, Payload* payload, std::string* error);
uint32_t pe_export_rva(const uint8_t* file, size_t n, const char* name);
