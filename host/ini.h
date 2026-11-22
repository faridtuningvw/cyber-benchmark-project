#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>

/* Field defaults match offsets.ini. They are unverified against a local aces.exe.
   See offsets.ini and README.md before treating a number as a current RVA. */

struct WtOffsets {
	uint64_t cgame = 0x7A4B848ull;
	uint64_t localplayer = 0x7A22CB0ull;
	uint64_t viewmatrix = 0x7AA58B8ull;
	int viewmatrix_is_pointer = 0;
	uint64_t unit_list = 0x310;
	uint64_t unit_count = 0x320;
	uint64_t unit_list2 = 0x328;
	uint64_t unit_count2 = 0x338;
	uint64_t unit_list3 = 0x340;
	uint64_t unit_count3 = 0x350;
	uint64_t position = 0xD40;
	uint64_t team = 0x1018;
	uint64_t state = 0xF98;
	uint64_t owned_unit = 0x8E8;
	int state_max_alive = 2;
	int w2s = 0;
	int verified = 0;
	int world_up = 1;
	int max_units = 128;
	int esp = 1;
	int radar = 1;
	float radar_range = 1500.f;
	std::string window_class = "DagorWClass";
	std::string window_title = "War Thunder";
};

inline std::string ini_trim(const std::string& s)
{
	size_t a = 0;
	size_t b = s.size();
	while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r')) ++a;
	while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r')) --b;
	return s.substr(a, b - a);
}

inline int ini_parse(const std::string& text, std::map<std::string, std::string>* out, std::string* error)
{
	size_t i = 0;
	int line_no = 1;
	if (!out) return 0;
	while (i < text.size()) {
		size_t end = text.find('\n', i);
		if (end == std::string::npos) end = text.size();
		std::string line = ini_trim(text.substr(i, end - i));
		i = end + 1;
		if (!line.empty() && line[0] != '#' && line[0] != ';') {
			size_t eq = line.find('=');
			if (eq == std::string::npos) {
				if (error) *error = "line " + std::to_string(line_no) + " has no '='";
				return 0;
			}
			std::string key = ini_trim(line.substr(0, eq));
			std::string val = ini_trim(line.substr(eq + 1));
			if (key.empty()) {
				if (error) *error = "empty key on line " + std::to_string(line_no);
				return 0;
			}
			(*out)[key] = val;
		}
		++line_no;
	}
	return 1;
}

inline int ini_u64(const std::map<std::string, std::string>& kv, const char* key, uint64_t* slot)
{
	auto it = kv.find(key);
	if (it == kv.end()) return 1;
	char* end = 0;
	unsigned long long v = std::strtoull(it->second.c_str(), &end, 0);
	if (!end || end == it->second.c_str() || *end != 0) return 0;
	*slot = (uint64_t)v;
	return 1;
}

inline int ini_i(const std::map<std::string, std::string>& kv, const char* key, int* slot)
{
	uint64_t v = 0;
	auto it = kv.find(key);
	if (it == kv.end()) return 1;
	if (!ini_u64(kv, key, &v)) return 0;
	*slot = (int)v;
	return 1;
}

inline int ini_apply(const std::string& text, WtOffsets* off, std::string* error)
{
	std::map<std::string, std::string> kv;
	if (!off || !ini_parse(text, &kv, error)) return 0;
	if (!ini_u64(kv, "cgame", &off->cgame) ||
		!ini_u64(kv, "localplayer", &off->localplayer) ||
		!ini_u64(kv, "viewmatrix", &off->viewmatrix) ||
		!ini_i(kv, "viewmatrix_is_pointer", &off->viewmatrix_is_pointer) ||
		!ini_u64(kv, "unit_list", &off->unit_list) ||
		!ini_u64(kv, "unit_count", &off->unit_count) ||
		!ini_u64(kv, "unit_list2", &off->unit_list2) ||
		!ini_u64(kv, "unit_count2", &off->unit_count2) ||
		!ini_u64(kv, "unit_list3", &off->unit_list3) ||
		!ini_u64(kv, "unit_count3", &off->unit_count3) ||
		!ini_u64(kv, "position", &off->position) ||
		!ini_u64(kv, "team", &off->team) ||
		!ini_u64(kv, "state", &off->state) ||
		!ini_u64(kv, "owned_unit", &off->owned_unit) ||
		!ini_i(kv, "state_max_alive", &off->state_max_alive) ||
		!ini_i(kv, "w2s", &off->w2s) ||
		!ini_i(kv, "verified", &off->verified) ||
		!ini_i(kv, "world_up", &off->world_up) ||
		!ini_i(kv, "max_units", &off->max_units) ||
		!ini_i(kv, "esp", &off->esp) ||
		!ini_i(kv, "radar", &off->radar)) {
		if (error) *error = "integer offset is not a number";
		return 0;
	}
	auto rr = kv.find("radar_range");
	if (rr != kv.end()) {
		char* end = 0;
		float v = std::strtof(rr->second.c_str(), &end);
		if (!end || end == rr->second.c_str() || *end != 0 || v < 10.f) {
			if (error) *error = "radar_range is invalid";
			return 0;
		}
		off->radar_range = v;
	}
	auto wc = kv.find("window_class");
	if (wc != kv.end() && !wc->second.empty()) off->window_class = wc->second;
	auto wt = kv.find("window_title");
	if (wt != kv.end() && !wt->second.empty()) off->window_title = wt->second;
	if (off->max_units < 1) off->max_units = 1;
	if (off->max_units > 128) off->max_units = 128;
	if (off->world_up < 0 || off->world_up > 2) {
		if (error) *error = "world_up must be 0, 1, or 2";
		return 0;
	}
	if (off->w2s != 0 && off->w2s != 1) {
		if (error) *error = "w2s must be 0 or 1";
		return 0;
	}
	return 1;
}
