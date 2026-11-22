#pragma once

#include "geom.h"
#include "ini.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

struct DrawUnit {
	WtVec3 pos;
	int team;
	int enemy; /* 1 enemy, 0 ally, -1 unknown */
	float dist;
	float sx, sy;
	int on_screen;
};

struct DrawFrame {
	DrawUnit units[128];
	int count;
	int listed;
	int drawn;
	WtVec3 local_pos;
	int have_local;
	int have_game;
	int draw_enabled;
	unsigned pid;
	unsigned long long base;
};

HWND overlay_create(HINSTANCE instance);
void overlay_fit(HWND hwnd, HWND game, int have_game);
void overlay_paint(HWND hwnd, const DrawFrame* frame, const WtOffsets* off);
HWND find_game_window(const WtOffsets* off);
