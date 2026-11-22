#pragma once

/* World-to-screen and radar projection.
   w2s mode 0 multiplies a column vector (m[0], m[4], m[8], m[12] is the first column).
   w2s mode 1 multiplies a row vector. Which one aces.exe stores is unverified;
   offsets.ini selects it. */

struct WtVec3 {
	float x, y, z;
};

struct WtMat4 {
	float m[16];
};

inline int wt_w2s(const WtMat4* mat, const WtVec3* p, float screen_w, float screen_h, int mode, float* sx, float* sy)
{
	float x, y, z, cx, cy, cw, nx, ny;
	if (!mat || !p || !sx || !sy || screen_w < 1.f || screen_h < 1.f) return 0;
	x = p->x;
	y = p->y;
	z = p->z;
	if (mode == 0) {
		cx = mat->m[0] * x + mat->m[4] * y + mat->m[8] * z + mat->m[12];
		cy = mat->m[1] * x + mat->m[5] * y + mat->m[9] * z + mat->m[13];
		cw = mat->m[3] * x + mat->m[7] * y + mat->m[11] * z + mat->m[15];
	} else {
		cx = mat->m[0] * x + mat->m[1] * y + mat->m[2] * z + mat->m[3];
		cy = mat->m[4] * x + mat->m[5] * y + mat->m[6] * z + mat->m[7];
		cw = mat->m[12] * x + mat->m[13] * y + mat->m[14] * z + mat->m[15];
	}
	if (cw < 0.1f) return 0;
	nx = cx / cw;
	ny = cy / cw;
	*sx = (screen_w * 0.5f) + (nx * screen_w * 0.5f);
	*sy = (screen_h * 0.5f) - (ny * screen_h * 0.5f);
	return 1;
}

/* Horizontal offset in radar space, -1..1 before clamping.
   world_up: 0 = X is up, 1 = Y is up, 2 = Z is up. Default 1 is unverified. */
inline void wt_radar(const WtVec3* local, const WtVec3* unit, int world_up, float range, float* ox, float* oy)
{
	float dx, dy, dz, hx, hy;
	if (!local || !unit || !ox || !oy || range < 1.f) {
		if (ox) *ox = 0;
		if (oy) *oy = 0;
		return;
	}
	dx = unit->x - local->x;
	dy = unit->y - local->y;
	dz = unit->z - local->z;
	if (world_up == 0) {
		hx = dy;
		hy = dz;
	} else if (world_up == 2) {
		hx = dx;
		hy = dy;
	} else {
		hx = dx;
		hy = dz;
	}
	*ox = hx / range;
	*oy = hy / range;
}

inline float wt_dist2(const WtVec3* a, const WtVec3* b)
{
	float dx, dy, dz;
	if (!a || !b) return 0.f;
	dx = a->x - b->x;
	dy = a->y - b->y;
	dz = a->z - b->z;
	return dx * dx + dy * dy + dz * dz;
}
