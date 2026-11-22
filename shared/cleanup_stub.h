#pragma once

/* One-shot teardown stub. Runs from NonPagedPoolExecute, not from the mapped image.
   Layout of the pointer passed in RCX (WT_FREE_INFO) is the ABI of these bytes.
   53                   push rbx
   48 83 EC 20          sub rsp, 20h
   48 89 CB             mov rbx, rcx
   33 C9                xor ecx, ecx                 ; KernelMode
   33 D2                xor edx, edx                 ; Alertable = FALSE
   4C 8D 43 28          lea r8, [rbx+28h]            ; &timeout
   48 8B 43 30          mov rax, [rbx+30h]           ; KeDelayExecutionThread
   FF D0                call rax
   48 8B 4B 08          mov rcx, [rbx+8]             ; image
   48 8B 53 10          mov rdx, [rbx+10h]           ; size
   48 8B 03             mov rax, [rbx]               ; MmFreeIndependentPages
   FF D0                call rax
   48 8B 4B 20          mov rcx, [rbx+20h]           ; self
   48 8B 43 18          mov rax, [rbx+18h]           ; ExFreePool
   48 83 C4 20          add rsp, 20h
   5B                   pop rbx
   FF E0                jmp rax
   The delay is so the syscall that queued the item has left the mapped image
   before that image is freed. */

typedef struct _WT_FREE_INFO {
	unsigned long long free_fn;
	unsigned long long image;
	unsigned long long image_size;
	unsigned long long ex_free;
	unsigned long long self;
	long long timeout;
	unsigned long long delay_fn;
} WT_FREE_INFO;

static const unsigned char kCleanupStub[] = {
	0x53,
	0x48, 0x83, 0xEC, 0x20,
	0x48, 0x89, 0xCB,
	0x33, 0xC9,
	0x33, 0xD2,
	0x4C, 0x8D, 0x43, 0x28,
	0x48, 0x8B, 0x43, 0x30,
	0xFF, 0xD0,
	0x48, 0x8B, 0x4B, 0x08,
	0x48, 0x8B, 0x53, 0x10,
	0x48, 0x8B, 0x03,
	0xFF, 0xD0,
	0x48, 0x8B, 0x4B, 0x20,
	0x48, 0x8B, 0x43, 0x18,
	0x48, 0x83, 0xC4, 0x20,
	0x5B,
	0xFF, 0xE0
};

#define WT_CLEANUP_STUB_LEN (sizeof(kCleanupStub))
#define WT_STUB_CODE 0x00u
#define WT_STUB_INFO 0x80u
#define WT_STUB_ITEM 0xC0u
#define WT_STUB_ALLOC 0x100u
