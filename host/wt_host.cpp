#include "ini.h"
#include "geom.h"
#include "nal.h"
#include "mapper.h"
#include "overlay.h"
#include "../shared/protocol.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

WT_COMM* g_comm = 0;
uint8_t* g_data = 0;
using AddAtom_t = long(__stdcall*)(const wchar_t*, unsigned long, unsigned short*);
AddAtom_t g_add = 0;
volatile LONG g_quit = 0;

BOOL WINAPI on_ctrl(DWORD)
{
	InterlockedExchange(&g_quit, 1);
	return TRUE;
}

bool transact(WT_COMM* req)
{
	if (!g_comm || !g_add || !req) return false;
	req->magic = WT_MAGIC;
	req->status = WT_ST_IDLE;
	std::memcpy(g_comm, req, sizeof(*req));
	MemoryBarrier();
	InterlockedExchange((volatile LONG*)&g_comm->status, (LONG)WT_ST_REQ);
	unsigned short atom = 0;
	g_add(L"", 0, &atom);
	MemoryBarrier();
	std::memcpy(req, g_comm, sizeof(*req));
	return req->status == WT_ST_OK;
}

bool read_block(uint64_t addr, void* buf, uint32_t size)
{
	uint8_t* out = (uint8_t*)buf;
	while (size) {
		uint32_t chunk = size > WT_READ_MAX ? WT_READ_MAX : size;
		WT_COMM req = {};
		req.cmd = WT_CMD_READ;
		req.address = addr;
		req.size = chunk;
		if (!transact(&req) || req.result != chunk) return false;
		std::memcpy(out, g_data, chunk);
		addr += chunk;
		out += chunk;
		size -= chunk;
	}
	return true;
}

bool read_pod(uint64_t addr, void* buf, uint32_t size)
{
	return read_block(addr, buf, size);
}

std::wstring exe_dir()
{
	wchar_t path[MAX_PATH];
	DWORD n = GetModuleFileNameW(0, path, MAX_PATH);
	if (!n || n >= MAX_PATH) return L"";
	std::wstring s(path, path + n);
	size_t slash = s.find_last_of(L"\\/");
	if (slash == std::wstring::npos) return L"";
	return s.substr(0, slash + 1);
}

std::string read_file(const std::wstring& path)
{
	HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (h == INVALID_HANDLE_VALUE) return "";
	DWORD sz = GetFileSize(h, 0);
	std::string text(sz, '\0');
	DWORD got = 0;
	ReadFile(h, text.data(), sz, &got, 0);
	CloseHandle(h);
	text.resize(got);
	return text;
}

bool load_image(const std::wstring& path, std::vector<uint8_t>* out)
{
	HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (h == INVALID_HANDLE_VALUE) return false;
	DWORD sz = GetFileSize(h, 0);
	out->resize(sz);
	DWORD got = 0;
	BOOL ok = ReadFile(h, out->data(), sz, &got, 0);
	CloseHandle(h);
	return ok && got == sz && sz > 0;
}

int scatter_units(const uint64_t* ptrs, int count, const WtOffsets* off, DrawFrame* frame, int local_team, int have_team, const WtMat4* view, int have_view, float sw, float sh)
{
	int listed = 0;
	int drawn = 0;
	frame->count = 0;
	for (int base_i = 0; base_i < count; base_i += 16) {
		int batch = count - base_i;
		if (batch > 16) batch = 16;
		std::memset(g_data, 0, WT_READ_MAX);
		for (int i = 0; i < batch; ++i) {
			WT_ITEM* item = (WT_ITEM*)(g_data + (size_t)(i * 3) * sizeof(WT_ITEM));
			uint32_t slot = (uint32_t)(i * 32);
			item[0].address = ptrs[base_i + i] + off->position;
			item[0].size = 12;
			item[0].out_off = (uint16_t)slot;
			item[1].address = ptrs[base_i + i] + off->team;
			item[1].size = 4;
			item[1].out_off = (uint16_t)(slot + 16);
			item[2].address = ptrs[base_i + i] + off->state;
			item[2].size = 4;
			item[2].out_off = (uint16_t)(slot + 20);
			float* pos = (float*)(g_data + WT_SCATTER_OUT + slot);
			pos[0] = pos[1] = pos[2] = std::nanf("");
		}
		WT_COMM req = {};
		req.cmd = WT_CMD_SCATTER;
		req.size = (wt_u32)(batch * 3);
		if (!transact(&req)) return -1;
		for (int i = 0; i < batch; ++i) {
			uint32_t slot = (uint32_t)(i * 32);
			float* pos = (float*)(g_data + WT_SCATTER_OUT + slot);
			int team = *(int*)(g_data + WT_SCATTER_OUT + slot + 16);
			int state = *(int*)(g_data + WT_SCATTER_OUT + slot + 20);
			if (!std::isfinite(pos[0]) || !std::isfinite(pos[1]) || !std::isfinite(pos[2])) continue;
			if (std::fabs(pos[0]) > 1.0e7f || std::fabs(pos[1]) > 1.0e7f || std::fabs(pos[2]) > 1.0e7f) continue;
			if (off->state_max_alive >= 0 && state > off->state_max_alive) continue;
			if (frame->count >= 128) break;
			DrawUnit* u = &frame->units[frame->count];
			u->pos.x = pos[0];
			u->pos.y = pos[1];
			u->pos.z = pos[2];
			u->team = team;
			u->enemy = have_team ? (team != local_team) : -1;
			float d2 = 0.f;
			if (frame->have_local) d2 = wt_dist2(&frame->local_pos, &u->pos);
			u->dist = std::sqrt(d2);
			u->on_screen = 0;
			u->sx = 0;
			u->sy = 0;
			if (have_view && off->esp) {
				float sx = 0, sy = 0;
				if (wt_w2s(view, &u->pos, sw, sh, off->w2s, &sx, &sy)) {
					u->on_screen = 1;
					u->sx = sx;
					u->sy = sy;
					++drawn;
				}
			}
			++frame->count;
			++listed;
		}
	}
	frame->listed = listed;
	frame->drawn = drawn;
	return listed;
}

bool build_frame(const WtOffsets* off, uint64_t base, DrawFrame* frame, float sw, float sh)
{
	frame->count = 0;
	frame->listed = 0;
	frame->drawn = 0;
	frame->have_local = 0;
	frame->base = base;
	uint64_t cgame = 0;
	if (!read_pod(base + off->cgame, &cgame, 8) || !cgame) return true;
	uint64_t local = 0;
	read_pod(base + off->localplayer, &local, 8);
	int local_team = 0;
	int have_team = 0;
	if (local) {
		uint64_t owned = 0;
		if (read_pod(local + off->owned_unit, &owned, 8) && owned) {
			float pos[3] = {};
			if (read_pod(owned + off->position, pos, 12) && std::isfinite(pos[0]) && std::isfinite(pos[1]) && std::isfinite(pos[2])) {
				frame->local_pos.x = pos[0];
				frame->local_pos.y = pos[1];
				frame->local_pos.z = pos[2];
				frame->have_local = 1;
			}
			if (read_pod(owned + off->team, &local_team, 4)) have_team = 1;
		}
	}
	WtMat4 view = {};
	int have_view = 0;
	if (off->viewmatrix_is_pointer) {
		uint64_t ptr = 0;
		if (read_pod(base + off->viewmatrix, &ptr, 8) && ptr && read_pod(ptr, view.m, 64)) have_view = 1;
	} else if (read_pod(base + off->viewmatrix, view.m, 64)) {
		have_view = 1;
	}
	uint64_t lists[3] = { off->unit_list, off->unit_list2, off->unit_list3 };
	uint64_t counts[3] = { off->unit_count, off->unit_count2, off->unit_count3 };
	uint64_t ptrs[128];
	int nptr = 0;
	for (int li = 0; li < 3; ++li) {
		uint64_t list = 0;
		int32_t count = 0;
		if (!read_pod(cgame + lists[li], &list, 8)) continue;
		if (!read_pod(cgame + counts[li], &count, 4)) continue;
		if (!list || count <= 0) continue;
		if (count > off->max_units) count = off->max_units;
		if (count > 128) count = 128;
		uint64_t raw[128];
		if (!read_block(list, raw, (uint32_t)count * 8)) continue;
		for (int i = 0; i < count && nptr < off->max_units && nptr < 128; ++i) {
			if (!raw[i]) continue;
			int dup = 0;
			for (int j = 0; j < nptr; ++j) if (ptrs[j] == raw[i]) dup = 1;
			if (!dup) ptrs[nptr++] = raw[i];
		}
	}
	if (!nptr) return true;
	return scatter_units(ptrs, nptr, off, frame, local_team, have_team, &view, have_view, sw, sh) >= 0;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
	SetProcessDPIAware();
	SetConsoleCtrlHandler(on_ctrl, TRUE);
	std::printf("wt_host  read-only War Thunder radar/ESP\n");
	std::printf("no aim write, no injected overlay, no handle opened on aces.exe\n");
	nal_log_system_state();
	if (argc < 2) {
		std::printf("usage: wt_host.exe C:\\path\\to\\iqvw64e.sys [offsets.ini]\n");
		return 2;
	}
	std::wstring dir = exe_dir();
	std::wstring ini_path = argc >= 3 ? argv[2] : dir + L"offsets.ini";
	std::wstring image_path = dir + L"wt_phys.sys";
	WtOffsets off;
	std::string ini_text = read_file(ini_path);
	if (ini_text.empty()) {
		std::printf("[!] %ls missing, using compiled defaults. Those defaults are unverified.\n", ini_path.c_str());
	} else {
		std::string err;
		if (!ini_apply(ini_text, &off, &err)) {
			std::printf("[-] offsets.ini: %s\n", err.c_str());
			return 2;
		}
		std::printf("[+] offsets from %ls  verified=%d\n", ini_path.c_str(), off.verified);
	}
	if (!off.verified) {
		std::printf("[!] cgame/localplayer/viewmatrix are the 2.59.0.98 numbers from UnknownCheats\n");
		std::printf("    post 4852008 (2026-11-05). That post then said the view matrix was found\n");
		std::printf("    again and did not publish a replacement. Field offsets were already in\n");
		std::printf("    this tree and were not re-derived. listed 0 in a match means the layout\n");
		std::printf("    moved. listed 0 in the hangar only means a match is not running.\n");
	}

	std::vector<uint8_t> image;
	if (!load_image(image_path, &image)) {
		std::printf("[-] missing %ls. Build it with build.bat first.\n", image_path.c_str());
		return 2;
	}

	void* comm_page = VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	void* data_page = VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!comm_page || !data_page || !VirtualLock(comm_page, 0x1000) || !VirtualLock(data_page, 0x1000)) {
		std::printf("[-] could not lock the communication pages\n");
		return 2;
	}
	g_comm = (WT_COMM*)comm_page;
	g_data = (uint8_t*)data_page;
	g_add = (AddAtom_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAddAtom");
	if (!g_add) {
		std::printf("[-] ntdll!NtAddAtom is missing\n");
		return 2;
	}

	Nal nal;
	if (!nal.open_from(argv[1])) return 1;
	if (!nal.clear_traces()) {
		std::printf("[-] trace cleanup failed (%s). Unloading the loader. Nothing is left mapped.\n", nal.last_error.c_str());
		nal.close_and_shred();
		return 1;
	}
	Payload payload = {};
	std::string err;
	if (!map_payload(&nal, image, comm_page, data_page, &payload, &err)) {
		std::printf("[-] map failed. Unloading the loader.\n");
		nal.close_and_shred();
		return 1;
	}
	if (!install_gate(&nal, &payload, &err)) {
		remove_gate_and_free(&nal, &payload, &err);
		nal.close_and_shred();
		return 1;
	}
	WT_COMM ping = {};
	ping.cmd = WT_CMD_PING;
	if (!transact(&ping) || ping.result != WT_MAGIC) {
		std::printf("[-] payload ping failed (status %u result 0x%llx). Restoring NtAddAtom and freeing the image before unload.\n",
			ping.status, (unsigned long long)ping.result);
		remove_gate_and_free(&nal, &payload, &err);
		nal.close_and_shred();
		return 1;
	}
	std::printf("[+] ping ok. Unloading the vulnerable loader before the game starts.\n");
	nal.close_and_shred();
	std::printf("[+] loader is not resident. Start War Thunder now.\n");
	std::printf("    INSERT toggles drawing. END, or Ctrl+C, restores NtAddAtom and queues the page free.\n");
	std::printf("    The free runs about two seconds later on a system worker, then that stub frees itself.\n");
	std::printf("    DagorWClass / \"War Thunder\" were not checked against a live client here.\n");

	HINSTANCE instance = GetModuleHandleW(0);
	HWND hwnd = overlay_create(instance);
	if (!hwnd) {
		std::printf("[-] overlay window failed\n");
		InterlockedExchange(&g_quit, 1);
	}
	int draw = 1;
	int insert_down = 0;
	uint64_t base = 0;
	uint32_t pid = 0;
	DWORD last_log = 0;
	int warned_pid = 0;
	DrawFrame frame = {};

	while (!g_quit) {
		MSG msg;
		while (PeekMessageW(&msg, 0, 0, 0, PM_REMOVE)) {
			if (msg.message == WM_QUIT) InterlockedExchange(&g_quit, 1);
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}
		int end_down = (GetAsyncKeyState(VK_END) & 0x8000) != 0;
		int insert_now = (GetAsyncKeyState(VK_INSERT) & 0x8000) != 0;
		if (insert_now && !insert_down) draw = !draw;
		insert_down = insert_now;
		if (end_down) InterlockedExchange(&g_quit, 1);

		HWND game = find_game_window(&off);
		overlay_fit(hwnd, game, game != 0);
		RECT rc = {};
		if (hwnd) GetClientRect(hwnd, &rc);
		float sw = (float)(rc.right - rc.left);
		float sh = (float)(rc.bottom - rc.top);

		if (!base) {
			WT_COMM find = {};
			find.cmd = WT_CMD_FIND;
			std::memcpy(find.image, "aces.exe", 8);
			if (transact(&find)) {
				base = find.address;
				pid = (uint32_t)find.result;
				std::printf("[+] aces.exe pid %u base 0x%llx\n", pid, (unsigned long long)base);
			}
		} else {
			uint16_t mz = 0;
			if (!read_pod(base, &mz, 2) || mz != 0x5A4D) {
				std::printf("[!] module header is gone. Looking again.\n");
				base = 0;
				pid = 0;
			}
		}
		frame = {};
		frame.draw_enabled = draw;
		frame.pid = pid;
		frame.have_game = game != 0;
		if (base) {
			if (!build_frame(&off, base, &frame, sw, sh)) {
				std::printf("[!] read failed. The process may have exited.\n");
				base = 0;
			}
		}
		frame.draw_enabled = draw;
		frame.pid = pid;
		frame.base = base;
		if (game && pid) {
			DWORD wpid = 0;
			GetWindowThreadProcessId(game, &wpid);
			if (wpid && wpid != pid && !warned_pid) {
				std::printf("[!] window pid %lu is not the aces.exe pid %u. The window match may be wrong.\n", wpid, pid);
				warned_pid = 1;
			}
		}
		if (hwnd) overlay_paint(hwnd, &frame, &off);
		DWORD now = GetTickCount();
		if (now - last_log > 1000) {
			std::printf("listed %d drawn %d %s\n", frame.listed, frame.drawn, draw ? "drawing" : "hidden");
			last_log = now;
		}
		Sleep(33);
	}

	if (hwnd) DestroyWindow(hwnd);
	WT_COMM stop = {};
	stop.cmd = WT_CMD_STOP;
	bool stopped = transact(&stop);
	if (!stopped) {
		std::printf("[-] STOP was not acknowledged. NtAddAtom may still be patched until reboot.\n");
		std::printf("    The mapped pages were not freed from here. Do not start the game again on this boot.\n");
		return 1;
	}
	std::printf("[+] STOP acknowledged (stub queued = %llu). Waiting 3 seconds for the teardown stub.\n",
		(unsigned long long)stop.result);
	std::printf("    That wait was not timed on a live kernel in this workspace.\n");
	Sleep(3000);
	std::printf("[+] host exit. Loader service and temp file were already removed. Turn Memory Integrity\n");
	std::printf("    and the vulnerable-driver blocklist back on if you disabled them, then reboot.\n");
	return 0;
}

int main()
{
	int argc = 0;
	wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	int rc = wmain(argc, argv);
	if (argv) LocalFree(argv);
	return rc;
}
