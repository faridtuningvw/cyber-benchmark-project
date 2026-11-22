#pragma once

/* Shared layout for the locked user page the payload polls.
   Offsets are part of the ABI. Do not insert fields. */

typedef unsigned int wt_u32;
typedef unsigned long long wt_u64;
typedef unsigned short wt_u16;

#define WT_MAGIC     0x57544831u
#define WT_MAP_MAGIC 0x4D415031u

#define WT_ST_IDLE 0u
#define WT_ST_REQ  1u
#define WT_ST_OK   2u
#define WT_ST_ERR  3u

#define WT_CMD_PING    1u
#define WT_CMD_FIND    2u
#define WT_CMD_READ    3u
#define WT_CMD_SCATTER 4u
#define WT_CMD_STOP    5u

#define WT_IMAGE_MAX 16u
#define WT_READ_MAX  0x1000u
#define WT_SCATTER_MAX 48u
#define WT_SCATTER_OUT 0x800u

typedef struct _WT_COMM {
	volatile wt_u32 magic;     /* 0 */
	volatile wt_u32 status;    /* 4 */
	wt_u32 cmd;                /* 8 */
	wt_u32 pid;                /* 12 */
	wt_u64 address;            /* 16 */
	wt_u64 data_pa;            /* 24 */
	wt_u32 size;               /* 32 */
	wt_u32 pad;                /* 36 */
	wt_u64 result;             /* 40 */
	char image[WT_IMAGE_MAX]; /* 48 */
} WT_COMM;

typedef struct _WT_ITEM {
	wt_u64 address;
	wt_u16 size;
	wt_u16 out_off;
	wt_u32 pad;
} WT_ITEM;

typedef struct _WT_MAP_PARAM {
	wt_u64 comm_pa;
	wt_u64 data_pa;
	wt_u64 legit;
	wt_u32 magic;
	wt_u32 client_pid;
} WT_MAP_PARAM;
