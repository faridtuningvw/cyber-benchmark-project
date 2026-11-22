#pragma once

/* Minimal x64 length decoder for a kernel prologue.
   Unknown opcodes fail closed. RIP-relative instructions are reported so the
   hook builder can refuse to steal them (the trampoline would be wrong). */

#include <stddef.h>
#include <stdint.h>

struct DecodeResult {
	int length;
	int rip_relative;
};

static int decode_one(const uint8_t* p, int maxn, struct DecodeResult* out)
{
	int i = 0;
	int prefixes = 0;
	int rex_w = 0;
	int opsize16 = 0;
	int addr32 = 0;
	uint8_t op;
	uint8_t op2 = 0;
	int two = 0;
	int modrm = 0;
	int imm = 0;

	if (out) {
		out->length = -1;
		out->rip_relative = 0;
	}
	if (!p || maxn <= 0) return -1;

	while (i < maxn && prefixes < 8) {
		uint8_t c = p[i];
		if (c == 0x66) { opsize16 = 1; ++i; ++prefixes; continue; }
		if (c == 0x67) { addr32 = 1; ++i; ++prefixes; continue; }
		if (c == 0xF0 || c == 0xF2 || c == 0xF3 || c == 0x2E || c == 0x36 ||
			c == 0x3E || c == 0x26 || c == 0x64 || c == 0x65) {
			++i;
			++prefixes;
			continue;
		}
		if (c >= 0x40 && c <= 0x4F) {
			rex_w = (c & 0x08) != 0;
			++i;
			++prefixes;
			continue;
		}
		break;
	}
	if (i >= maxn) return -1;
	op = p[i++];
	if (op == 0xC4 || op == 0xC5 || op == 0x62) return -1;

	if (op == 0x0F) {
		if (i >= maxn) return -1;
		op2 = p[i++];
		two = 1;
	}

	if (!two) {
		if (op == 0x27 || op == 0x2F || op == 0x37 || op == 0x3F) return -1;
		if (op <= 0x3D || op == 0x63) {
			modrm = 1;
		} else if (op >= 0x50 && op <= 0x5F) {
			modrm = 0;
		} else if (op == 0x68) imm = 4;
		else if (op == 0x6A) imm = 1;
		else if (op == 0x69) { modrm = 1; imm = opsize16 ? 2 : 4; }
		else if (op == 0x6B) { modrm = 1; imm = 1; }
		else if (op >= 0x70 && op <= 0x7F) imm = 1;
		else if (op == 0x80) { modrm = 1; imm = 1; }
		else if (op == 0x81) { modrm = 1; imm = opsize16 ? 2 : 4; }
		else if (op == 0x82) return -1;
		else if (op == 0x83) { modrm = 1; imm = 1; }
		else if (op >= 0x84 && op <= 0x8F) modrm = 1;
		else if (op >= 0x90 && op <= 0x9F) modrm = 0;
		else if (op >= 0xA0 && op <= 0xA3) imm = addr32 ? 4 : 8;
		else if (op == 0xA8) imm = 1;
		else if (op == 0xA9) imm = opsize16 ? 2 : 4;
		else if (op >= 0xB0 && op <= 0xB7) imm = 1;
		else if (op >= 0xB8 && op <= 0xBF) imm = rex_w ? 8 : (opsize16 ? 2 : 4);
		else if (op == 0xC0 || op == 0xC1) { modrm = 1; imm = 1; }
		else if (op == 0xC2) imm = 2;
		else if (op == 0xC3 || op == 0xC9 || op == 0xCC) imm = 0;
		else if (op == 0xC6) { modrm = 1; imm = 1; }
		else if (op == 0xC7) { modrm = 1; imm = opsize16 ? 2 : 4; }
		else if (op >= 0xE0 && op <= 0xE3) imm = 1;
		else if (op == 0xE8 || op == 0xE9) imm = 4;
		else if (op == 0xEB) imm = 1;
		else if (op >= 0xD0 && op <= 0xD3) modrm = 1;
		else if (op == 0xF6 || op == 0xF7 || op == 0xFE || op == 0xFF) modrm = 1;
		else return -1;
	} else {
		if (op2 == 0x1E || op2 == 0x1F || op2 == 0xB6 || op2 == 0xB7 ||
			op2 == 0xBE || op2 == 0xBF || op2 == 0xAF) {
			modrm = 1;
		} else if (op2 >= 0x80 && op2 <= 0x8F) {
			imm = 4;
		} else {
			return -1;
		}
	}

	if (modrm) {
		uint8_t m;
		int mod;
		int rm;
		int reg;
		if (i >= maxn) return -1;
		m = p[i++];
		mod = m >> 6;
		rm = m & 7;
		reg = (m >> 3) & 7;
		if (!addr32 && mod != 3 && rm == 4) {
			uint8_t s;
			int base;
			if (i >= maxn) return -1;
			s = p[i++];
			base = s & 7;
			if (mod == 0 && base == 5) {
				if (i + 4 > maxn) return -1;
				i += 4;
			}
		}
		if (mod == 1) {
			if (i + 1 > maxn) return -1;
			i += 1;
		} else if (mod == 2) {
			if (i + 4 > maxn) return -1;
			i += 4;
		} else if (mod == 0 && !addr32 && rm == 5) {
			if (out) out->rip_relative = 1;
			if (i + 4 > maxn) return -1;
			i += 4;
		}
		if (!two && op == 0xF6 && reg == 0) imm = 1;
		if (!two && op == 0xF7 && reg == 0) imm = opsize16 ? 2 : 4;
	}

	if (i + imm > maxn) return -1;
	i += imm;
	if (out) out->length = i;
	return i;
}

/* Bytes to overwrite so the stolen range ends on an instruction boundary.
   Returns -1 if it cannot do that within 32 bytes without a RIP-relative op. */
static int steal_hook(const uint8_t* p, int avail, int min_bytes)
{
	int total = 0;
	if (min_bytes < 12) min_bytes = 12;
	while (total < min_bytes) {
		struct DecodeResult d;
		int n = decode_one(p + total, avail - total, &d);
		if (n <= 0) return -1;
		if (d.rip_relative) return -1;
		total += n;
		if (total > 32) return -1;
	}
	return total;
}
