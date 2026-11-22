#include "mapper.h"
#include "decode.h"
#include "../shared/protocol.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstring>
#include <cstdio>
#include <string>

namespace {

void set_err(std::string* error, const std::string& s)
{
	if (error) *error = s;
	std::fprintf(stderr, "[-] %s\n", s.c_str());
}

bool in_image(uint32_t rva, uint32_t bytes, uint32_t size)
{
	return rva < size && bytes <= size - rva;
}

} // namespace

uint32_t pe_export_rva(const uint8_t* file, size_t n, const char* name)
{
	if (!file || n < sizeof(IMAGE_DOS_HEADER) || !name) return 0;
	auto dos = (const IMAGE_DOS_HEADER*)file;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
	if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > n) return 0;
	auto nt = (const IMAGE_NT_HEADERS64*)(file + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
	auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!dir.VirtualAddress || !dir.Size) return 0;
	if (!in_image(dir.VirtualAddress, dir.Size, (uint32_t)n) && dir.VirtualAddress + dir.Size > n) {
		/* Exports are RVAs. The raw file is not an image, so this only works when
		   the export directory and its strings are stored at the RVA, which is true
		   for a mapped image. For a file, walk sections. */
	}
	auto rva_to_raw = [&](uint32_t rva) -> const uint8_t* {
		auto sec = IMAGE_FIRST_SECTION(nt);
		for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
			uint32_t va = sec[i].VirtualAddress;
			uint32_t span = sec[i].Misc.VirtualSize;
			if (span < sec[i].SizeOfRawData) span = sec[i].SizeOfRawData;
			if (rva >= va && rva < va + span) {
				uint32_t raw = sec[i].PointerToRawData + (rva - va);
				if ((size_t)raw >= n) return 0;
				return file + raw;
			}
		}
		if (rva < nt->OptionalHeader.SizeOfHeaders && rva < n) return file + rva;
		return 0;
	};
	auto exp = rva_to_raw(dir.VirtualAddress);
	if (!exp) return 0;
	auto ed = (const IMAGE_EXPORT_DIRECTORY*)exp;
	if (ed->NumberOfNames > 4096) return 0;
	auto names = (const uint32_t*)rva_to_raw(ed->AddressOfNames);
	auto ords = (const uint16_t*)rva_to_raw(ed->AddressOfNameOrdinals);
	auto funcs = (const uint32_t*)rva_to_raw(ed->AddressOfFunctions);
	if (!names || !ords || !funcs) return 0;
	for (uint32_t i = 0; i < ed->NumberOfNames; ++i) {
		auto cur = (const char*)rva_to_raw(names[i]);
		if (!cur) continue;
		if (std::strcmp(cur, name) != 0) continue;
		if (ords[i] >= ed->NumberOfFunctions) return 0;
		return funcs[ords[i]];
	}
	return 0;
}

bool map_payload(Nal* nal, const std::vector<uint8_t>& file, void* comm, void* data, Payload* out, std::string* error)
{
	if (!nal || !out || !comm || !data) return false;
	if (file.size() < sizeof(IMAGE_DOS_HEADER)) {
		set_err(error, "wt_phys.sys is too small");
		return false;
	}
	auto dos = (const IMAGE_DOS_HEADER*)file.data();
	if (dos->e_magic != IMAGE_DOS_SIGNATURE || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > file.size()) {
		set_err(error, "wt_phys.sys is not a PE");
		return false;
	}
	auto nt = (const IMAGE_NT_HEADERS64*)(file.data() + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
		nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		set_err(error, "wt_phys.sys is not an x64 image");
		return false;
	}
	if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0) {
		set_err(error, "wt_phys.sys has no relocations. Link it with /FIXED:NO.");
		return false;
	}
	auto first = IMAGE_FIRST_SECTION(nt);
	uint32_t header = first->VirtualAddress;
	if (header < 0x200 || header > 0x10000 || (header & 0xFFF)) {
		set_err(error, "first section is not on a 4K boundary; refusing a headerless map");
		return false;
	}
	uint32_t image_size = nt->OptionalHeader.SizeOfImage;
	if (image_size <= header || image_size > 0x1000000) {
		set_err(error, "SizeOfImage is unusable");
		return false;
	}
	uint32_t gate_rva = pe_export_rva(file.data(), file.size(), "WtGate");
	if (gate_rva < header) {
		set_err(error, "WtGate export is missing. Link driver\\wt_phys.def.");
		return false;
	}
	if (nt->OptionalHeader.AddressOfEntryPoint < header) {
		set_err(error, "DriverEntry is inside the header. Refusing a headerless map.");
		return false;
	}
	uint32_t body = image_size - header;
	uint32_t alloc_size = (body + 0xFFF) & ~0xFFFu;
	if (!nal->resolve_helpers()) {
		set_err(error, nal->last_error.empty() ? "helper resolution failed" : nal->last_error);
		return false;
	}
	uint8_t prologue[64] = {};
	if (!nal->read(nal->nt_add_atom, prologue, sizeof(prologue))) {
		set_err(error, "could not read NtAddAtom");
		return false;
	}
	int steal = steal_hook(prologue, (int)sizeof(prologue), 12);
	if (steal < 12) {
		set_err(error, "NtAddAtom prologue is not a safe 12-byte hook boundary on this kernel. Not installing a gate.");
		return false;
	}
	std::vector<uint8_t> local(image_size, 0);
	if (nt->OptionalHeader.SizeOfHeaders > file.size()) {
		set_err(error, "headers are truncated");
		return false;
	}
	std::memcpy(local.data(), file.data(), nt->OptionalHeader.SizeOfHeaders);
	for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
		if (!first[i].PointerToRawData || !first[i].SizeOfRawData) continue;
		if ((size_t)first[i].PointerToRawData + first[i].SizeOfRawData > file.size()) {
			set_err(error, "section raw data is out of the file");
			return false;
		}
		if (!in_image(first[i].VirtualAddress, first[i].SizeOfRawData, image_size)) {
			set_err(error, "section virtual range is out of the image");
			return false;
		}
		std::memcpy(local.data() + first[i].VirtualAddress, file.data() + first[i].PointerToRawData, first[i].SizeOfRawData);
	}

	uint64_t kernel_base_alloc = nal->alloc_independent(alloc_size);
	if (!kernel_base_alloc) {
		set_err(error, "MmAllocateIndependentPagesEx failed");
		return false;
	}
	uint64_t adjusted = kernel_base_alloc - header;
	int64_t delta = (int64_t)adjusted - (int64_t)nt->OptionalHeader.ImageBase;

	auto reloc = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	uint32_t cursor = reloc.VirtualAddress;
	uint32_t reloc_end = reloc.VirtualAddress + reloc.Size;
	while (cursor + sizeof(IMAGE_BASE_RELOCATION) <= reloc_end) {
		auto block = (IMAGE_BASE_RELOCATION*)(local.data() + cursor);
		if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || cursor + block->SizeOfBlock > reloc_end) {
			nal->free_independent(kernel_base_alloc, alloc_size);
			set_err(error, "relocation block is corrupt");
			return false;
		}
		uint32_t count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
		auto entries = (uint16_t*)(block + 1);
		for (uint32_t i = 0; i < count; ++i) {
			uint16_t type = entries[i] >> 12;
			uint16_t off = entries[i] & 0xFFF;
			if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
			if (type != IMAGE_REL_BASED_DIR64) {
				nal->free_independent(kernel_base_alloc, alloc_size);
				set_err(error, "relocation type is not DIR64");
				return false;
			}
			uint32_t target = block->VirtualAddress + off;
			if (!in_image(target, 8, image_size)) {
				nal->free_independent(kernel_base_alloc, alloc_size);
				set_err(error, "relocation target is out of the image");
				return false;
			}
			uint64_t* slot = (uint64_t*)(local.data() + target);
			*slot = (uint64_t)((int64_t)*slot + delta);
		}
		cursor += block->SizeOfBlock;
	}

	auto load_cfg = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	if (load_cfg.VirtualAddress && load_cfg.Size >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie) + sizeof(uint64_t) &&
		in_image(load_cfg.VirtualAddress, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie) + 8, image_size)) {
		auto cfg = (IMAGE_LOAD_CONFIG_DIRECTORY64*)(local.data() + load_cfg.VirtualAddress);
		uint64_t cookie_va = cfg->SecurityCookie;
		if (cookie_va) {
			uint64_t rva = cookie_va - adjusted;
			if (rva < image_size - 8) {
				uint64_t* cookie = (uint64_t*)(local.data() + rva);
				if (*cookie == 0x2B992DDFA232ull) {
					uint64_t fresh = 0x2B992DDFA232ull ^ GetCurrentProcessId() ^ GetCurrentThreadId();
					if (fresh == 0x2B992DDFA232ull) fresh = 0x2B992DDFA233ull;
					*cookie = fresh;
				}
			}
		}
	}

	auto imp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (imp.VirtualAddress && imp.Size) {
		if (!in_image(imp.VirtualAddress, imp.Size, image_size)) {
			nal->free_independent(kernel_base_alloc, alloc_size);
			set_err(error, "import directory is out of the image");
			return false;
		}
		for (uint32_t at = imp.VirtualAddress; at + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= imp.VirtualAddress + imp.Size; at += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
			auto desc = (IMAGE_IMPORT_DESCRIPTOR*)(local.data() + at);
			if (!desc->Name) break;
			if (!in_image(desc->Name, 1, image_size)) {
				nal->free_independent(kernel_base_alloc, alloc_size);
				set_err(error, "import name is out of the image");
				return false;
			}
			const char* mod_name = (const char*)(local.data() + desc->Name);
			uint64_t mod = nal->ntos;
			if (_stricmp(mod_name, "ntoskrnl.exe") != 0 && _stricmp(mod_name, "NTOSKRNL.exe") != 0 &&
				_stricmp(mod_name, "ntoskrnl") != 0) {
				nal->free_independent(kernel_base_alloc, alloc_size);
				set_err(error, std::string("import from an unexpected module: ") + mod_name);
				return false;
			}
			uint32_t thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
			uint32_t iat_rva = desc->FirstThunk;
			for (;;) {
				if (!in_image(thunk_rva, 8, image_size) || !in_image(iat_rva, 8, image_size)) {
					nal->free_independent(kernel_base_alloc, alloc_size);
					set_err(error, "import thunk is out of the image");
					return false;
				}
				uint64_t thunk = *(uint64_t*)(local.data() + thunk_rva);
				if (!thunk) break;
				if (thunk & (1ull << 63)) {
					nal->free_independent(kernel_base_alloc, alloc_size);
					set_err(error, "ordinal import is not supported");
					return false;
				}
				if (!in_image((uint32_t)thunk + 2, 1, image_size)) {
					nal->free_independent(kernel_base_alloc, alloc_size);
					set_err(error, "import-by-name is out of the image");
					return false;
				}
				const char* fn = (const char*)(local.data() + (uint32_t)thunk + 2);
				uint64_t addr = nal->kernel_export(mod, fn);
				if (!addr) {
					nal->free_independent(kernel_base_alloc, alloc_size);
					set_err(error, std::string("unresolved import ") + fn);
					return false;
				}
				*(uint64_t*)(local.data() + iat_rva) = addr;
				thunk_rva += 8;
				iat_rva += 8;
			}
		}
	}

	std::vector<uint8_t> zeros(alloc_size, 0);
	if (!nal->write(kernel_base_alloc, zeros.data(), zeros.size())) {
		nal->free_independent(kernel_base_alloc, alloc_size);
		set_err(error, "could not zero the kernel allocation");
		return false;
	}
	if (!nal->write(kernel_base_alloc, local.data() + header, body)) {
		nal->free_independent(kernel_base_alloc, alloc_size);
		set_err(error, "could not write the payload image");
		return false;
	}
	if (!nal->protect(kernel_base_alloc, alloc_size, PAGE_EXECUTE_READWRITE)) {
		nal->free_independent(kernel_base_alloc, alloc_size);
		set_err(error, "MmSetPageProtection(RWX) failed. The pages are not left allocated.");
		return false;
	}

	uint64_t param_pool = nal->alloc_pool(0x1000, 'rWtP');
	if (!param_pool) {
		nal->free_independent(kernel_base_alloc, alloc_size);
		set_err(error, "parameter pool allocation failed");
		return false;
	}
	WT_MAP_PARAM param = {};
	param.comm_va = (wt_u64)(uintptr_t)comm;
	param.data_va = (wt_u64)(uintptr_t)data;
	param.nt_add_atom = nal->nt_add_atom;
	param.magic = WT_MAP_MAGIC;
	param.client_pid = GetCurrentProcessId();
	param.image_base = kernel_base_alloc;
	param.image_size = alloc_size;
	param.free_pages = nal->mm_free_pages;
	param.ex_free_pool = nal->ex_free;
	param.delay_fn = nal->ke_delay;
	param.hook_len = (wt_u32)steal;
	if (steal + 12 > (int)sizeof(param.tramp)) {
		nal->free_pool(param_pool);
		nal->free_independent(kernel_base_alloc, alloc_size);
		set_err(error, "trampoline does not fit");
		return false;
	}
	std::memcpy(param.original, prologue, steal);
	std::memcpy(param.tramp, prologue, steal);
	uint64_t resume = nal->nt_add_atom + (uint64_t)steal;
	param.tramp[steal] = 0x48;
	param.tramp[steal + 1] = 0xB8;
	std::memcpy(param.tramp + steal + 2, &resume, 8);
	param.tramp[steal + 10] = 0xFF;
	param.tramp[steal + 11] = 0xE0;
	if (!nal->write(param_pool, &param, sizeof(param))) {
		nal->free_pool(param_pool);
		nal->free_independent(kernel_base_alloc, alloc_size);
		set_err(error, "could not write the map parameter");
		return false;
	}
	uint64_t status = 0;
	uint64_t entry = adjusted + nt->OptionalHeader.AddressOfEntryPoint;
	if (!nal->call4(&status, entry, param_pool, 0, 0, 0)) {
		nal->free_pool(param_pool);
		nal->free_independent(kernel_base_alloc, alloc_size);
		set_err(error, "DriverEntry call did not dispatch");
		return false;
	}
	WT_MAP_PARAM back = {};
	nal->read(param_pool, &back, sizeof(back));
	nal->free_pool(param_pool);
	if ((int32_t)(uint32_t)status < 0) {
		nal->free_independent(kernel_base_alloc, alloc_size);
		char msg[96];
		std::snprintf(msg, sizeof(msg), "DriverEntry returned 0x%08lx", (unsigned long)(uint32_t)status);
		set_err(error, msg);
		return false;
	}
	out->image = kernel_base_alloc;
	out->image_size = alloc_size;
	out->stub = back.stub;
	out->gate = adjusted + gate_rva;
	out->nt_add_atom = nal->nt_add_atom;
	out->hook_len = (uint32_t)steal;
	std::memcpy(out->original, prologue, steal);
	out->hooked = false;
	out->comm = comm;
	out->data = data;
	std::printf("[+] payload at 0x%llx size 0x%llx gate 0x%llx stub 0x%llx hook %u\n",
		(unsigned long long)out->image, (unsigned long long)out->image_size,
		(unsigned long long)out->gate, (unsigned long long)out->stub, out->hook_len);
	return true;
}

bool install_gate(Nal* nal, Payload* payload, std::string* error)
{
	if (!nal || !payload || !payload->gate || !payload->hook_len || payload->hook_len > 32) return false;
	uint8_t jmp[32];
	std::memset(jmp, 0x90, sizeof(jmp));
	jmp[0] = 0x48;
	jmp[1] = 0xB8;
	std::memcpy(jmp + 2, &payload->gate, 8);
	jmp[10] = 0xFF;
	jmp[11] = 0xE0;
	if (!nal->write_ro(payload->nt_add_atom, jmp, payload->hook_len)) {
		set_err(error, "could not install the NtAddAtom gate");
		return false;
	}
	payload->hooked = true;
	std::printf("[+] NtAddAtom gate installed for this process only (other callers chain to the real function)\n");
	return true;
}

bool remove_gate_and_free(Nal* nal, Payload* payload, std::string* error)
{
	if (!nal || !payload || !payload->image) return false;
	if (payload->hooked) {
		if (!nal->write_ro(payload->nt_add_atom, payload->original, payload->hook_len)) {
			set_err(error, "could not restore NtAddAtom. The payload was NOT freed, because freeing it would leave a hook into dead pages.");
			return false;
		}
		payload->hooked = false;
		std::printf("[+] NtAddAtom prologue restored from the saved bytes\n");
	}
	if (payload->stub) {
		nal->free_pool(payload->stub);
		payload->stub = 0;
	}
	bool freed = nal->free_independent(payload->image, payload->image_size);
	if (!freed) set_err(error, "MmFreeIndependentPages failed");
	payload->image = 0;
	return freed;
}
