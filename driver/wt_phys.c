#include <ntifs.h>
#include "../shared/protocol.h"

/* Headerless manual-mapped payload.
   Reads War Thunder through the process DTB and physical pages.
   Never attaches, never calls MmCopyVirtualMemory, never opens a handle,
   never writes the game, never creates a device object.

   CR3 walk + MmCopyMemory(PHYSICAL): defeats usermode RPM/OpenProcess hooks
   and the usual KeStackAttachProcess / MmCopyVirtualMemory hooks. Caught by
   executable-PFN scans of pages that belong to no module, and by server-side
   stats if you write the game instead of reading it.

   ETHREAD start swap: defeats thread-list checks that require the start
   address to land inside a loaded image. Caught by a stack sample whose
   return address falls in this unbacked range. Map before BEDaisy loads. */

extern NTKERNELAPI PUCHAR PsGetProcessImageFileName(PEPROCESS Process);
extern NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern NTKERNELAPI PVOID PsGetProcessPeb(PEPROCESS Process);
extern NTKERNELAPI PEPROCESS PsInitialSystemProcess;

static ULONGLONG g_comm_pa;
static ULONGLONG g_data_pa;
static ULONGLONG g_legit;
static ULONGLONG g_cr3;
static ULONGLONG g_base;
static HANDLE g_pid;
static ULONG g_links;
static volatile LONG g_stop;
static PEPROCESS g_proc;

static void MemCopyLocal(void* dst, const void* src, SIZE_T n)
{
	PUCHAR d = (PUCHAR)dst;
	const UCHAR* s = (const UCHAR*)src;
	while (n--) *d++ = *s++;
}
static int CiEq(const char* a, const char* b)
{
	while (*a && *b) {
		char ca = *a;
		char cb = *b;
		if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
		if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
		if (ca != cb) return 0;
		++a;
		++b;
	}
	return *a == 0 && *b == 0;
}

static void DecStr(char* out, const UCHAR* enc, ULONG n)
{
	ULONG i;
	for (i = 0; i < n; ++i) out[i] = (char)(enc[i] ^ 0x5A);
	out[n] = 0;
}

static NTSTATUS ReadPhys(ULONGLONG pa, PVOID dst, SIZE_T len)
{
	MM_COPY_ADDRESS src;
	SIZE_T got = 0;
	if (!pa || !dst || !len) return STATUS_INVALID_PARAMETER;
	src.PhysicalAddress.QuadPart = (LONGLONG)pa;
	return MmCopyMemory(dst, src, len, MM_COPY_MEMORY_PHYSICAL, &got);
}

static NTSTATUS ReadPhysSpan(ULONGLONG pa, PVOID dst, SIZE_T len)
{
	PUCHAR out = (PUCHAR)dst;
	while (len) {
		ULONG off = (ULONG)(pa & 0xFFF);
		SIZE_T chunk = len;
		NTSTATUS st;
		if (chunk > (SIZE_T)(0x1000 - off)) chunk = (SIZE_T)(0x1000 - off);
		st = ReadPhys(pa, out, chunk);
		if (!NT_SUCCESS(st)) return st;
		pa += chunk;
		out += chunk;
		len -= chunk;
	}
	return STATUS_SUCCESS;
}

static NTSTATUS WritePhys(ULONGLONG pa, const void* src, SIZE_T len)
{
	const UCHAR* in = (const UCHAR*)src;
	while (len) {
		ULONG off = (ULONG)(pa & 0xFFF);
		SIZE_T chunk = len;
		PHYSICAL_ADDRESS page;
		PVOID mapped;
		if (chunk > (SIZE_T)(0x1000 - off)) chunk = (SIZE_T)(0x1000 - off);
		page.QuadPart = (LONGLONG)(pa & ~0xFFFULL);
		mapped = MmMapIoSpaceEx(page, PAGE_SIZE, PAGE_READWRITE);
		if (!mapped) return STATUS_INSUFFICIENT_RESOURCES;
		MemCopyLocal((PUCHAR)mapped + off, in, chunk);
		MmUnmapIoSpace(mapped, PAGE_SIZE);
		pa += chunk;
		in += chunk;
		len -= chunk;
	}
	return STATUS_SUCCESS;
}

static ULONGLONG Translate(ULONGLONG cr3, ULONGLONG va)
{
	ULONG pml4, pdpt, pd, pt;
	ULONGLONG e = 0;
	ULONGLONG next;
	if (!cr3 || !va) return 0;
	cr3 &= ~0xFFFULL;
	pml4 = (ULONG)((va >> 39) & 0x1FF);
	pdpt = (ULONG)((va >> 30) & 0x1FF);
	pd = (ULONG)((va >> 21) & 0x1FF);
	pt = (ULONG)((va >> 12) & 0x1FF);
	if (!NT_SUCCESS(ReadPhys(cr3 + (ULONGLONG)pml4 * 8, &e, 8)) || !(e & 1)) return 0;
	next = e & 0x000FFFFFFFFFF000ULL;
	if (!NT_SUCCESS(ReadPhys(next + (ULONGLONG)pdpt * 8, &e, 8)) || !(e & 1)) return 0;
	if (e & 0x80ULL) return (e & 0x000FFFFFC0000000ULL) + (va & 0x3FFFFFFFULL);
	next = e & 0x000FFFFFFFFFF000ULL;
	if (!NT_SUCCESS(ReadPhys(next + (ULONGLONG)pd * 8, &e, 8)) || !(e & 1)) return 0;
	if (e & 0x80ULL) return (e & 0x000FFFFFFFE00000ULL) + (va & 0x1FFFFFULL);
	next = e & 0x000FFFFFFFFFF000ULL;
	if (!NT_SUCCESS(ReadPhys(next + (ULONGLONG)pt * 8, &e, 8)) || !(e & 1)) return 0;
	return (e & 0x000FFFFFFFFFF000ULL) + (va & 0xFFFULL);
}

static NTSTATUS ReadVirtual(ULONGLONG cr3, ULONGLONG va, PVOID dst, SIZE_T len)
{
	PUCHAR out = (PUCHAR)dst;
	while (len) {
		ULONG off = (ULONG)(va & 0xFFF);
		SIZE_T chunk = len;
		ULONGLONG pa;
		NTSTATUS st;
		if (chunk > (SIZE_T)(0x1000 - off)) chunk = (SIZE_T)(0x1000 - off);
		pa = Translate(cr3, va);
		if (!pa) return STATUS_NOT_FOUND;
		st = ReadPhys(pa, out, chunk);
		if (!NT_SUCCESS(st)) return st;
		va += chunk;
		out += chunk;
		len -= chunk;
	}
	return STATUS_SUCCESS;
}

static BOOLEAN ValidPe(ULONGLONG cr3, ULONGLONG base)
{
	USHORT mz = 0;
	ULONG lfanew = 0;
	ULONG sig = 0;
	if (!base) return FALSE;
	if (!NT_SUCCESS(ReadVirtual(cr3, base, &mz, 2)) || mz != 0x5A4D) return FALSE;
	if (!NT_SUCCESS(ReadVirtual(cr3, base + 0x3C, &lfanew, 4))) return FALSE;
	if (lfanew < 0x40 || lfanew > 0x800) return FALSE;
	if (!NT_SUCCESS(ReadVirtual(cr3, base + lfanew, &sig, 4))) return FALSE;
	return sig == 0x00004550;
}

static BOOLEAN DiscoverLinks(void)
{
	PEPROCESS sys;
	ULONG off;
	if (g_links) return TRUE;
	sys = PsInitialSystemProcess;
	if (!sys) return FALSE;
	for (off = 0x200; off < 0x800; off += 8) {
		ULONGLONG pid = *(ULONGLONG*)((PUCHAR)sys + off);
		ULONGLONG flink;
		ULONGLONG blink;
		if (pid != 4) continue;
		flink = *(ULONGLONG*)((PUCHAR)sys + off + 8);
		blink = *(ULONGLONG*)((PUCHAR)sys + off + 16);
		if ((flink >> 48) != 0xFFFF) continue;
		if ((blink >> 48) != 0xFFFF) continue;
		g_links = off + 8;
		return TRUE;
	}
	return FALSE;
}

static ULONGLONG FindCr3(PEPROCESS proc, ULONGLONG base)
{
	ULONGLONG cands[24];
	ULONG n = 0;
	ULONG i;
	ULONG off;
	cands[n++] = *(ULONGLONG*)((PUCHAR)proc + 0x28);
	cands[n++] = *(ULONGLONG*)((PUCHAR)proc + 0x388);
	for (off = 0; off < 0x800 && n < 24; off += 8) {
		ULONGLONG v = *(ULONGLONG*)((PUCHAR)proc + off);
		ULONGLONG pa = v & ~0xFFFULL;
		BOOLEAN dup = FALSE;
		if (pa < 0x1000 || pa > 0x800000000ULL) continue;
		for (i = 0; i < n; ++i)
			if ((cands[i] & ~0xFFFULL) == pa) dup = TRUE;
		if (!dup) cands[n++] = v;
	}
	for (i = 0; i < n; ++i) {
		ULONGLONG cr3 = cands[i] & ~0xFFFULL;
		if (ValidPe(cr3, base)) return cr3;
	}
	return 0;
}

static void ReleaseProc(void)
{
	if (g_proc) {
		ObDereferenceObject(g_proc);
		g_proc = NULL;
	}
	g_cr3 = 0;
	g_base = 0;
	g_pid = NULL;
}

static BOOLEAN RefreshTarget(const char* name)
{
	PEPROCESS sys;
	PLIST_ENTRY head;
	PLIST_ENTRY cur;
	ULONG guard = 0;
	if (!DiscoverLinks()) return FALSE;
	sys = PsInitialSystemProcess;
	head = (PLIST_ENTRY)((PUCHAR)sys + g_links);
	__try {
		for (cur = head->Flink; cur && cur != head && guard < 4096; cur = cur->Flink, ++guard) {
			PEPROCESS proc = (PEPROCESS)((PUCHAR)cur - g_links);
			PUCHAR img = PsGetProcessImageFileName(proc);
			ULONGLONG base;
			ULONGLONG cr3;
			if (!img || !CiEq((const char*)img, name)) continue;
			base = (ULONGLONG)(ULONG_PTR)PsGetProcessSectionBaseAddress(proc);
			if (!base) {
				PVOID peb = PsGetProcessPeb(proc);
				ULONGLONG raw = *(ULONGLONG*)((PUCHAR)proc + 0x28) & ~0xFFFULL;
				if (peb && raw)
					ReadVirtual(raw, (ULONGLONG)(ULONG_PTR)peb + 0x10, &base, sizeof(base));
			}
			if (!base) continue;
			cr3 = FindCr3(proc, base);
			if (!cr3) continue;
			ReleaseProc();
			ObReferenceObject(proc);
			g_proc = proc;
			g_cr3 = cr3;
			g_base = base;
			g_pid = PsGetProcessId(proc);
			return TRUE;
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
	return FALSE;
}

static BOOLEAN EnsureTarget(const char* name)
{
	if (g_cr3 && g_base && ValidPe(g_cr3, g_base)) return TRUE;
	return RefreshTarget(name);
}

static void WriteStatus(wt_u32 st, wt_u64 result, int write_addr, wt_u64 address)
{
	WritePhys(g_comm_pa + 4, &st, sizeof(st));
	WritePhys(g_comm_pa + 40, &result, sizeof(result));
	if (write_addr) WritePhys(g_comm_pa + 16, &address, sizeof(address));
}

static void Handle(const WT_COMM* req, const char* target)
{
	UCHAR stack[0x1000];
	if (req->cmd == WT_CMD_PING) {
		WriteStatus(WT_ST_OK, WT_MAGIC, 0, 0);
		return;
	}
	if (req->cmd == WT_CMD_STOP) {
		InterlockedExchange(&g_stop, 1);
		WriteStatus(WT_ST_OK, 0, 0, 0);
		return;
	}
	if (req->cmd == WT_CMD_FIND) {
		char image[WT_IMAGE_MAX];
		MemCopyLocal(image, req->image, WT_IMAGE_MAX - 1);
		image[WT_IMAGE_MAX - 1] = 0;
		if (!image[0]) {
			ULONG n = 0;
			while (target[n] && n + 1 < WT_IMAGE_MAX) {
				image[n] = target[n];
				++n;
			}
			image[n] = 0;
		}
		if (!RefreshTarget(image)) {
			WriteStatus(WT_ST_ERR, 0, 0, 0);
			return;
		}
		WriteStatus(WT_ST_OK, (wt_u64)(ULONG_PTR)g_pid, 1, g_base);
		return;
	}
	if (!EnsureTarget(target)) {
		WriteStatus(WT_ST_ERR, 0, 0, 0);
		return;
	}
	if (req->cmd == WT_CMD_READ) {
		SIZE_T size = req->size;
		if (!size || size > WT_READ_MAX || !req->address) {
			WriteStatus(WT_ST_ERR, 0, 0, 0);
			return;
		}
		if (!NT_SUCCESS(ReadVirtual(g_cr3, req->address, stack, size))) {
			WriteStatus(WT_ST_ERR, 0, 0, 0);
			return;
		}
		if (!NT_SUCCESS(WritePhys(g_data_pa, stack, size))) {
			WriteStatus(WT_ST_ERR, 0, 0, 0);
			return;
		}
		WriteStatus(WT_ST_OK, size, 0, 0);
		return;
	}
	if (req->cmd == WT_CMD_SCATTER) {
		ULONG count = req->size;
		ULONG i;
		if (!count || count > WT_SCATTER_MAX) {
			WriteStatus(WT_ST_ERR, 0, 0, 0);
			return;
		}
		for (i = 0; i < count; ++i) {
			WT_ITEM item;
			if (!NT_SUCCESS(ReadPhysSpan(g_data_pa + (ULONGLONG)i * sizeof(WT_ITEM), &item, sizeof(item)))) {
				WriteStatus(WT_ST_ERR, 0, 0, 0);
				return;
			}
			if (!item.size || item.size > 256) continue;
			if ((ULONG)item.out_off + item.size > (WT_READ_MAX - WT_SCATTER_OUT)) continue;
			if (!NT_SUCCESS(ReadVirtual(g_cr3, item.address, stack, item.size))) continue;
			WritePhys(g_data_pa + WT_SCATTER_OUT + item.out_off, stack, item.size);
		}
		WriteStatus(WT_ST_OK, count, 0, 0);
		return;
	}
	WriteStatus(WT_ST_ERR, 0, 0, 0);
}

static VOID Worker(PVOID context)
{
	char target[16];
	static const UCHAR enc[] = { 0x3B, 0x39, 0x3F, 0x29, 0x74, 0x3F, 0x22, 0x3F };
	UNREFERENCED_PARAMETER(context);
	DecStr(target, enc, 8);
	for (;;) {
		WT_COMM req;
		if (g_stop) break;
		if (NT_SUCCESS(ReadPhysSpan(g_comm_pa, &req, sizeof(req)))) {
			if (req.magic == WT_MAGIC && req.status == WT_ST_REQ)
				Handle(&req, target);
		}
		{
			LARGE_INTEGER delay;
			delay.QuadPart = -2 * 1000 * 10;
			KeDelayExecutionThread(KernelMode, FALSE, &delay);
		}
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID NTAPI WorkerEntry(PVOID context)
{
	PUCHAR th = (PUCHAR)KeGetCurrentThread();
	PVOID legit = (PVOID)(ULONG_PTR)g_legit;
	ULONG i;
	ULONG hits = 0;
	if (!legit) legit = (PVOID)KeDelayExecutionThread;
	for (i = 0; i < 0xA00 && hits < 4; i += sizeof(PVOID)) {
		PVOID slotv;
		__try { slotv = *(PVOID*)(th + i); }
		__except (EXCEPTION_EXECUTE_HANDLER) { break; }
		if (slotv == (PVOID)WorkerEntry) {
			__try { *(PVOID*)(th + i) = legit; }
			__except (EXCEPTION_EXECUTE_HANDLER) { break; }
			++hits;
		}
	}
	Worker(context);
}

NTSTATUS DriverEntry(WT_MAP_PARAM* param, PVOID unused)
{
	HANDLE thread = NULL;
	NTSTATUS st;
	UNREFERENCED_PARAMETER(unused);
	if (!param) return STATUS_INVALID_PARAMETER;
	if (((ULONG_PTR)param >> 48) != 0xFFFF) return STATUS_INVALID_PARAMETER;
	__try {
		if (param->magic != WT_MAP_MAGIC || !param->comm_pa || !param->data_pa)
			return STATUS_INVALID_PARAMETER;
		g_comm_pa = param->comm_pa;
		g_data_pa = param->data_pa;
		g_legit = param->legit;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_VIOLATION;
	}
	st = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, WorkerEntry, NULL);
	if (!NT_SUCCESS(st)) return st;
	ZwClose(thread);
	return STATUS_SUCCESS;
}
