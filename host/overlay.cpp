#include "overlay.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

HWND g_hwnd = 0;

std::wstring widen(const std::string& s)
{
	if (s.empty()) return L"";
	int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, 0, 0);
	if (n <= 0) return L"";
	std::wstring w(n, 0);
	MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
	if (!w.empty() && w.back() == 0) w.pop_back();
	return w;
}

void dot(HDC dc, int x, int y, int r, COLORREF color)
{
	HBRUSH brush = CreateSolidBrush(color);
	HPEN pen = CreatePen(PS_SOLID, 1, color);
	HGDIOBJ old_b = SelectObject(dc, brush);
	HGDIOBJ old_p = SelectObject(dc, pen);
	Ellipse(dc, x - r, y - r, x + r, y + r);
	SelectObject(dc, old_b);
	SelectObject(dc, old_p);
	DeleteObject(brush);
	DeleteObject(pen);
}

} // namespace

HWND find_game_window(const WtOffsets* off)
{
	struct Want {
		std::wstring cls;
		std::wstring title;
		HWND strict;
		HWND title_only;
	} want;
	want.cls = widen(off->window_class);
	want.title = widen(off->window_title);
	want.strict = 0;
	want.title_only = 0;
	EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
		auto w = (Want*)lp;
		if (!IsWindowVisible(hwnd)) return TRUE;
		wchar_t cls[128] = {};
		wchar_t title[256] = {};
		GetClassNameW(hwnd, cls, 128);
		GetWindowTextW(hwnd, title, 256);
		bool cls_ok = !w->cls.empty() && _wcsicmp(cls, w->cls.c_str()) == 0;
		bool title_ok = !w->title.empty() && wcsstr(title, w->title.c_str()) != 0;
		if (cls_ok && (w->title.empty() || title_ok) && !w->strict) w->strict = hwnd;
		if (title_ok && !w->title_only) w->title_only = hwnd;
		return TRUE;
	}, (LPARAM)&want);
	if (want.strict) return want.strict;
	return want.title_only;
}

HWND overlay_create(HINSTANCE instance)
{
	WNDCLASSW wc = {};
	wc.lpfnWndProc = DefWindowProcW;
	wc.hInstance = instance;
	wc.lpszClassName = L"WtReaderOverlay";
	RegisterClassW(&wc);
	g_hwnd = CreateWindowExW(
		WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
		wc.lpszClassName, L"", WS_POPUP,
		0, 0, 280, 280, 0, 0, instance, 0);
	if (!g_hwnd) return 0;
	SetLayeredWindowAttributes(g_hwnd, RGB(0, 0, 0), 0, LWA_COLORKEY);
	ShowWindow(g_hwnd, SW_SHOWNA);
	return g_hwnd;
}

void overlay_fit(HWND hwnd, HWND game, int have_game)
{
	if (!hwnd) return;
	if (!have_game || !game) {
		SetWindowPos(hwnd, HWND_TOPMOST, 24, 24, 280, 280, SWP_NOACTIVATE);
		return;
	}
	RECT rc = {};
	if (!GetClientRect(game, &rc)) return;
	POINT pt = { rc.left, rc.top };
	ClientToScreen(game, &pt);
	int w = rc.right - rc.left;
	int h = rc.bottom - rc.top;
	if (w < 100 || h < 100) return;
	SetWindowPos(hwnd, HWND_TOPMOST, pt.x, pt.y, w, h, SWP_NOACTIVATE);
}

void overlay_paint(HWND hwnd, const DrawFrame* frame, const WtOffsets* off)
{
	if (!hwnd || !frame || !off) return;
	RECT rc;
	GetClientRect(hwnd, &rc);
	int w = rc.right - rc.left;
	int h = rc.bottom - rc.top;
	if (w < 10 || h < 10) return;
	HDC window_dc = GetDC(hwnd);
	HDC mem = CreateCompatibleDC(window_dc);
	HBITMAP bmp = CreateCompatibleBitmap(window_dc, w, h);
	HGDIOBJ old = SelectObject(mem, bmp);
	HBRUSH black = (HBRUSH)GetStockObject(BLACK_BRUSH);
	FillRect(mem, &rc, black);

	if (frame->draw_enabled && off->radar) {
		int size = 220;
		int left = 16;
		int top = 16;
		RECT box = { left, top, left + size, top + size };
		HBRUSH panel = CreateSolidBrush(RGB(12, 18, 12));
		FillRect(mem, &box, panel);
		DeleteObject(panel);
		HPEN grid = CreatePen(PS_SOLID, 1, RGB(40, 70, 40));
		HGDIOBJ old_pen = SelectObject(mem, grid);
		MoveToEx(mem, left + size / 2, top, 0);
		LineTo(mem, left + size / 2, top + size);
		MoveToEx(mem, left, top + size / 2, 0);
		LineTo(mem, left + size, top + size / 2);
		SelectObject(mem, old_pen);
		DeleteObject(grid);
		dot(mem, left + size / 2, top + size / 2, 3, RGB(220, 220, 220));
		if (frame->have_local) {
			for (int i = 0; i < frame->count; ++i) {
				float ox = 0, oy = 0;
				wt_radar(&frame->local_pos, &frame->units[i].pos, off->world_up, off->radar_range, &ox, &oy);
				if (ox > 1.f) ox = 1.f;
				if (ox < -1.f) ox = -1.f;
				if (oy > 1.f) oy = 1.f;
				if (oy < -1.f) oy = -1.f;
				int x = left + size / 2 + (int)(ox * (size / 2 - 6));
				int y = top + size / 2 - (int)(oy * (size / 2 - 6));
				COLORREF c = RGB(220, 190, 40);
				if (frame->units[i].enemy == 1) c = RGB(220, 50, 50);
				else if (frame->units[i].enemy == 0) c = RGB(70, 160, 70);
				dot(mem, x, y, 3, c);
			}
		}
	}

	if (frame->draw_enabled && off->esp) {
		for (int i = 0; i < frame->count; ++i) {
			if (!frame->units[i].on_screen) continue;
			int x = (int)frame->units[i].sx;
			int y = (int)frame->units[i].sy;
			COLORREF c = RGB(220, 190, 40);
			if (frame->units[i].enemy == 1) c = RGB(220, 50, 50);
			else if (frame->units[i].enemy == 0) c = RGB(70, 180, 70);
			HPEN pen = CreatePen(PS_SOLID, 2, c);
			HGDIOBJ old_pen = SelectObject(mem, pen);
			MoveToEx(mem, x - 8, y - 14, 0);
			LineTo(mem, x - 8, y + 14);
			MoveToEx(mem, x + 8, y - 14, 0);
			LineTo(mem, x + 8, y + 14);
			MoveToEx(mem, x - 8, y - 14, 0);
			LineTo(mem, x - 4, y - 14);
			MoveToEx(mem, x + 4, y - 14, 0);
			LineTo(mem, x + 8, y - 14);
			SelectObject(mem, old_pen);
			DeleteObject(pen);
			char text[32];
			std::snprintf(text, sizeof(text), "%.0fm", frame->units[i].dist);
			SetBkMode(mem, TRANSPARENT);
			SetTextColor(mem, c);
			TextOutA(mem, x + 10, y - 8, text, (int)std::strlen(text));
		}
	}

	char status[160];
	std::snprintf(status, sizeof(status), "listed %d  drawn %d  %s  %s",
		frame->listed, frame->drawn,
		frame->draw_enabled ? "drawing" : "hidden",
		off->verified ? "offsets marked verified" : "offsets UNVERIFIED");
	SetBkMode(mem, TRANSPARENT);
	SetTextColor(mem, RGB(180, 220, 180));
	TextOutA(mem, 16, h > 40 ? h - 28 : 8, status, (int)std::strlen(status));

	BitBlt(window_dc, 0, 0, w, h, mem, 0, 0, SRCCOPY);
	SelectObject(mem, old);
	DeleteObject(bmp);
	DeleteDC(mem);
	ReleaseDC(hwnd, window_dc);
}
