#include "../host/decode.h"
#include "../host/geom.h"
#include "../host/ini.h"
#include "../shared/cleanup_stub.h"
#include "../shared/protocol.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <stddef.h>

static int g_fail = 0;

static void expect(int cond, const char* msg)
{
	if (!cond) {
		std::printf("FAIL %s\n", msg);
		++g_fail;
	}
}

int main()
{
	expect(offsetof(WT_COMM, magic) == 0, "magic");
	expect(offsetof(WT_COMM, status) == 4, "status");
	expect(offsetof(WT_COMM, cmd) == 8, "cmd");
	expect(offsetof(WT_COMM, address) == 16, "address");
	expect(offsetof(WT_COMM, result) == 40, "result");
	expect(offsetof(WT_COMM, image) == 48, "image");
	expect(sizeof(WT_COMM) == 64, "comm size");
	expect(sizeof(WT_ITEM) == 16, "item size");
	expect(offsetof(WT_FREE_INFO, timeout) == 0x28, "timeout");
	expect(offsetof(WT_FREE_INFO, delay_fn) == 0x30, "delay");
	expect(WT_CLEANUP_STUB_LEN == 50, "stub length");
	expect(kCleanupStub[0] == 0x53 && kCleanupStub[49] == 0xE0, "stub ends with jmp rax");
	expect(WT_STUB_INFO == 0x80 && WT_STUB_INFO + sizeof(WT_FREE_INFO) <= WT_STUB_ITEM, "stub layout");

	/* Second published MmSetPageProtection site. The call is the last byte.
	   Adding 13, as one circulating kdmapper copy does, does not land on it. */
	const uint8_t prot2[] = {
		0x0F, 0x45, 0x00, 0x00, 0x45, 0x8B, 0x00, 0x00, 0x00, 0x00,
		0x8D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xE8
	};
	const char* prot2_mask = "xx??xx????x??????xxx";
	expect(sizeof(prot2) == 20 && std::strlen(prot2_mask) == 20, "prot2 width");
	expect(prot2[19] == 0xE8 && prot2[17] == 0xFF && prot2[18] == 0xFF, "prot2 E8 is index 19");
	expect(prot2[10] == 0x8D && prot2[13] != 0xE8, "index 13 is not the call");

	const uint8_t prologue[] = {
		0x4C, 0x8B, 0xDC,
		0x49, 0x89, 0x5B, 0x10,
		0x49, 0x89, 0x73, 0x18,
		0x57,
		0x48, 0x83, 0xEC, 0x20
	};
	expect(steal_hook(prologue, (int)sizeof(prologue), 12) == 12, "steal 12 on a real-looking prologue");
	expect(decode_one(prologue, 3, 0) == 3, "mov r11, rsp");

	const uint8_t endbr[] = { 0xF3, 0x0F, 0x1E, 0xFA, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0xC4, 0xC3 };
	expect(steal_hook(endbr, (int)sizeof(endbr), 12) == 12, "endbr64 plus sub plus mov");

	const uint8_t rip[] = { 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
	expect(steal_hook(rip, (int)sizeof(rip), 12) < 0, "reject rip-relative steal");

	struct DecodeResult rel = {};
	expect(decode_one(rip, 16, &rel) == 7 && rel.rip_relative == 1, "rip length");

	WtOffsets off;
	std::string err;
	const char* text =
		"# comment\n"
		"cgame=0x10\n"
		"w2s = 1\n"
		"radar_range=2500\n"
		"window_class=Foo\n"
		"verified=0\n"
		"max_units=10\n";
	expect(ini_apply(text, &off, &err) == 1, "ini apply");
	expect(off.cgame == 0x10 && off.w2s == 1 && off.radar_range == 2500.f, "ini values");
	expect(off.window_class == "Foo" && off.max_units == 10, "ini strings");
	expect(off.localplayer == 0x7A22CB0ull, "untouched default");
	expect(ini_apply("nope\n", &off, &err) == 0, "ini reject");
	expect(ini_apply("world_up=9\n", &off, &err) == 0, "world_up reject");

	WtMat4 mat = {};
	mat.m[0] = 1;
	mat.m[5] = 1;
	mat.m[10] = 1;
	mat.m[15] = 1;
	WtVec3 origin = { 0, 0, 0 };
	float sx = -1, sy = -1;
	expect(wt_w2s(&mat, &origin, 200, 100, 0, &sx, &sy) == 1, "w2s origin");
	expect(std::fabs(sx - 100.f) < 0.01f && std::fabs(sy - 50.f) < 0.01f, "w2s center");
	WtVec3 behind = { 0, 0, -1 };
	WtMat4 back = {};
	back.m[11] = 1;
	expect(wt_w2s(&back, &behind, 200, 100, 0, &sx, &sy) == 0, "behind camera");

	WtVec3 local = { 0, 10, 0 };
	WtVec3 unit = { 100, 10, -50 };
	float ox = 0, oy = 0;
	wt_radar(&local, &unit, 1, 200.f, &ox, &oy);
	expect(std::fabs(ox - 0.5f) < 0.001f && std::fabs(oy - (-0.25f)) < 0.001f, "radar y-up");

	if (g_fail) {
		std::printf("%d failed\n", g_fail);
		return 1;
	}
	std::printf("logic tests passed\n");
	return 0;
}
