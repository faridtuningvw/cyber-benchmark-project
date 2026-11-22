#include <ntifs.h>
#include "../shared/protocol.h"
#include "../shared/cleanup_stub.h"

/* Headerless manual-mapped payload.

   Reads War Thunder by translating the process DTB and copying physical pages.
   Never attaches, never calls MmCopyVirtualMemory, never opens a handle, never
   writes the game, never creates a device object.

   There is no system thread. WtGate runs only when the host's own thread
   enters NtAddAtom, and only long enough to serve one request. The host
   installs that gate after DriverEntry returns (the mapper's temporary
   NtAddAtom hook has been restored by then). END restores the prologue and
   queues kCleanupStub, which waits, frees these pages, and frees itself.

   What still sees it: executable PFNs with no owning module, a stack sample
   taken while WtGate is inside a request, a missed trace wipe, PatchGuard or
   BattlEye comparing NtAddAtom to a clean image, and server-side stats if this
   is used as an aimbot. This file does not write the game. */

extern NTKERNELAPI PUCHAR PsGetProcessImageFileName(PEPROCESS Process);
extern NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern NTKERNELAPI PVOID PsGetProcessPeb(PEPROCESS Process);
extern NTKERNELAPI PEPROCESS PsInitialSystemProcess;

typedef PVOID (*WT_ALLOC2)(ULONGLONG Flags, SIZE_T NumberOfBytes, ULONG Tag);

/* wdm.h: POOL_FLAG_NON_PAGED is 0x40 and is NX.
   POOL_FLAG_NON_PAGED_EXECUTE is 0x80. The stub is executed.
   HVCI can refuse executable pool; DriverEntry then fails and the host frees the image. */
#define WT_POOL_FLAG_NON_PAGED_EXECUTE 0x80ull

static ULONGLONG g_comm_va;
static ULONGLONG g_data_va;
static ULONGLONG g_cr3;
static ULONGLONG g_base;
static HANDLE g_pid;
static ULONG g_links;
static volatile LONG g_stop;
static PEPROCESS g_proc;
static HANDLE g_client;
static ULONGLONG g_nt;
static ULONG g_hook_len;
static UCHAR g_original[32];
static ULONGLONG g_image;
static ULONGLONG g_image_size;
static ULONGLONG g_free_pages;
static ULONGLONG g_ex_free;
static ULONGLONG g_delay;
static PVOID g_stub;
static UCHAR g_tramp[48];

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

static NTSTATUS CopyUser(PVOID dst, PVOID src, SIZE_T len, int write)
{
	PVOID user = write ? dst : src;
	if (!dst || !src || !len) return STATUS_INVALID_PARAMETER;
	if (!user || (ULONGLONG)(ULONG_PTR)user > 0x00007FFFFFFFFFFFULL) return STATUS_ACCESS_VIOLATION;
	__try {
		if (write) ProbeForWrite(user, len, 1);
		else ProbeForRead(user, len, 1);
		MemCopyLocal(dst, src, len);
		return STATUS_SUCCESS;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
}

static NTSTATUS WriteStatus(wt_u32 st, wt_u64 result, int write_addr, wt_u64 address)
{
	wt_u64 slot_result = result;
	wt_u64 slot_addr = address;
	wt_u32 slot_st = st;
	NTSTATUS s;
	s = CopyUser((PUCHAR)(ULONG_PTR)g_comm_va + 40, &slot_result, sizeof(slot_result), 1);
	if (!NT_SUCCESS(s)) return s;
	if (write_addr) {
		s = CopyUser((PUCHAR)(ULONG_PTR)g_comm_va + 16, &slot_addr, sizeof(slot_addr), 1);
		if (!NT_SUCCESS(s)) return s;
	}
	return CopyUser((PUCHAR)(ULONG_PTR)g_comm_va + 4, &slot_st, sizeof(slot_st), 1);
}

static int UserRange(ULONGLONG va, SIZE_T len)
{
	if (!va || va > 0x00007FFFFFFFFFFFULL) return 0;
	if (len && va + (ULONGLONG)len < va) return 0;
	if (va + (ULONGLONG)len > 0x0000800000000000ULL) return 0;
	return 1;
}

static void Handle(const WT_COMM* req, const char* target)
{
	UCHAR stack[0x1000];
	if (req->cmd == WT_CMD_PING) {
		WriteStatus(WT_ST_OK, WT_MAGIC, 0, 0);
		return;
	}
	if (req->cmd == WT_CMD_STOP) {
		PHYSICAL_ADDRESS pa;
		UCHAR restored[32];
		if (InterlockedCompareExchange(&g_stop, 1, 0) != 0) {
			WriteStatus(WT_ST_OK, 0, 0, 0);
			return;
		}
		if (!g_nt || !g_hook_len || g_hook_len > sizeof(g_original)) {
			WriteStatus(WT_ST_ERR, 0, 0, 0);
			return;
		}
		MemCopyLocal(restored, g_original, g_hook_len);
		pa = MmGetPhysicalAddress((PVOID)(ULONG_PTR)g_nt);
		if (!pa.QuadPart || !NT_SUCCESS(WritePhys((ULONGLONG)pa.QuadPart, restored, g_hook_len))) {
			InterlockedExchange(&g_stop, 0);
			WriteStatus(WT_ST_ERR, 1, 0, 0);
			return;
		}
		ReleaseProc();
		if (g_stub && g_free_pages && g_ex_free && g_delay && g_image && g_image_size) {
			WT_FREE_INFO* info = (WT_FREE_INFO*)((PUCHAR)g_stub + WT_STUB_INFO);
			PWORK_QUEUE_ITEM item = (PWORK_QUEUE_ITEM)((PUCHAR)g_stub + WT_STUB_ITEM);
			info->free_fn = g_free_pages;
			info->image = g_image;
			info->image_size = g_image_size;
			info->ex_free = g_ex_free;
			info->self = (ULONGLONG)(ULONG_PTR)g_stub;
			info->timeout = -20000000LL; /* 2 seconds, relative */
			info->delay_fn = g_delay;
			item->WorkerRoutine = (PWORKER_THREAD_ROUTINE)g_stub;
			item->Parameter = info;
			ExQueueWorkItem(item, DelayedWorkQueue);
		}
		WriteStatus(WT_ST_OK, g_stub ? 1 : 0, 0, 0);
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
		if (!size || size > WT_READ_MAX || !UserRange(req->address, size)) {
			WriteStatus(WT_ST_ERR, 0, 0, 0);
			return;
		}
		if (!NT_SUCCESS(ReadVirtual(g_cr3, req->address, stack, size))) {
			WriteStatus(WT_ST_ERR, 0, 0, 0);
			return;
		}
		if (!NT_SUCCESS(CopyUser((PVOID)(ULONG_PTR)g_data_va, stack, size, 1))) {
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
			if (!NT_SUCCESS(CopyUser(&item, (PUCHAR)(ULONG_PTR)g_data_va + (ULONGLONG)i * sizeof(WT_ITEM), sizeof(item), 0))) {
				WriteStatus(WT_ST_ERR, 0, 0, 0);
				return;
			}
			if (!item.size || item.size > 256) continue;
			if ((ULONG)item.out_off + item.size > (WT_READ_MAX - WT_SCATTER_OUT)) continue;
			if (!UserRange(item.address, item.size)) continue;
			if (!NT_SUCCESS(ReadVirtual(g_cr3, item.address, stack, item.size))) continue;
			CopyUser((PUCHAR)(ULONG_PTR)g_data_va + WT_SCATTER_OUT + item.out_off, stack, item.size, 1);
		}
		WriteStatus(WT_ST_OK, count, 0, 0);
		return;
	}
	WriteStatus(WT_ST_ERR, 0, 0, 0);
}

typedef NTSTATUS (NTAPI *WT_TRAMP)(ULONGLONG, ULONGLONG, ULONGLONG, ULONGLONG);

NTSTATUS NTAPI WtGate(ULONGLONG a, ULONGLONG b, ULONGLONG c, ULONGLONG d)
{
	WT_COMM req;
	char target[16];
	static const UCHAR enc[] = { 0x3B, 0x39, 0x3F, 0x29, 0x74, 0x3F, 0x22, 0x3F };
	DecStr(target, enc, 8);
	if (PsGetCurrentProcessId() != g_client || g_stop || !g_comm_va) {
		return ((WT_TRAMP)g_tramp)(a, b, c, d);
	}
	if (!NT_SUCCESS(CopyUser(&req, (PVOID)(ULONG_PTR)g_comm_va, sizeof(req), 0))) {
		return ((WT_TRAMP)g_tramp)(a, b, c, d);
	}
	if (req.magic != WT_MAGIC || req.status != WT_ST_REQ) {
		return ((WT_TRAMP)g_tramp)(a, b, c, d);
	}
	Handle(&req, target);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(WT_MAP_PARAM* param, PVOID unused)
{
	UNICODE_STRING alloc_name;
	WT_ALLOC2 alloc2;
	UCHAR* stub;
	UNREFERENCED_PARAMETER(unused);
	if (!param) return STATUS_INVALID_PARAMETER;
	if (((ULONG_PTR)param >> 48) != 0xFFFF) return STATUS_INVALID_PARAMETER;
	__try {
		if (param->magic != WT_MAP_MAGIC) return STATUS_INVALID_PARAMETER;
		if (!param->comm_va || !param->data_va || !param->client_pid) return STATUS_INVALID_PARAMETER;
		if (!param->free_pages || !param->ex_free_pool || !param->delay_fn) return STATUS_INVALID_PARAMETER;
		if (!param->image_base || !param->image_size) return STATUS_INVALID_PARAMETER;
		if (!param->hook_len || param->hook_len > sizeof(g_tramp) || param->hook_len < 12) return STATUS_INVALID_PARAMETER;
		if (!param->tramp[0]) return STATUS_INVALID_PARAMETER;
		g_comm_va = param->comm_va;
		g_data_va = param->data_va;
		g_client = (HANDLE)(ULONG_PTR)param->client_pid;
		g_nt = param->nt_add_atom;
		g_hook_len = param->hook_len;
		g_image = param->image_base;
		g_image_size = param->image_size;
		g_free_pages = param->free_pages;
		g_ex_free = param->ex_free_pool;
		g_delay = param->delay_fn;
		MemCopyLocal(g_original, param->original, param->hook_len);
		MemCopyLocal(g_tramp, param->tramp, sizeof(g_tramp));
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_VIOLATION;
	}
	RtlInitUnicodeString(&alloc_name, L"ExAllocatePool2");
	alloc2 = (WT_ALLOC2)MmGetSystemRoutineAddress(&alloc_name);
	if (!alloc2) return STATUS_PROCEDURE_NOT_FOUND;
	stub = (UCHAR*)alloc2(WT_POOL_FLAG_NON_PAGED_EXECUTE, WT_STUB_ALLOC, 'rWtC');
	if (!stub) return STATUS_INSUFFICIENT_RESOURCES;
	{
		ULONG i;
		for (i = 0; i < WT_STUB_ALLOC; ++i) stub[i] = 0;
	}
	MemCopyLocal(stub + WT_STUB_CODE, kCleanupStub, WT_CLEANUP_STUB_LEN);
	g_stub = stub;
	param->stub = (wt_u64)(ULONG_PTR)stub;
	return STATUS_SUCCESS;
}
