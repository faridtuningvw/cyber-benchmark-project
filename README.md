# wt-phys

External, read-only radar and ESP for War Thunder (`aces.exe`) on Windows x64.
The drawing window is a separate layered, click-through process. Nothing is
injected into the game. The payload never writes game memory, never opens a
handle to `aces.exe`, and never starts a system thread.

This is not a claim that it is undetected. The detection surfaces are listed
below. Offsets are not verified against a local client. The Windows build was
not compiled in the environment that produced this tree.

## What changed relative to the polling thread

`driver/wt_phys.c` on main started `PsCreateSystemThread` and left that thread
executing inside the unmapped image until `WT_CMD_STOP`. That is a long-lived
thread in unbacked memory, so it is gone.

The payload is now entered only when this process calls `NtAddAtom`. `WtGate`
serves one request and returns. Any other caller, and this process when no
request is pending, jumps to a trampoline of the stolen `NtAddAtom` prologue
and then back into the real function. `END` writes the saved prologue back and
queues a 50-byte stub in nonpaged executable pool. The stub waits two seconds,
frees the independent pages, and frees itself. There is no thread whose start
address is the payload.

The physical CR3 walk, the read-only command set, and the refusal to open the
game are unchanged.

## Pieces

| File | Role |
| --- | --- |
| `driver/wt_phys.c` | Headerless payload. CR3 walk, physical reads, scatter, on-demand gate. |
| `driver/wt_phys.def` | Exports `DriverEntry` and `WtGate`. |
| `host/wt_host.cpp` | Overlay loop, unit reads, INSERT / END. |
| `host/nal.cpp` | Loads the caller-supplied `iqvw64e.sys`, then unloads it. |
| `host/mapper.cpp` | Maps the payload, installs the gate, restores it on failure. |
| `host/overlay.cpp` | Click-through GDI radar and brackets. Not inside the game. |
| `host/decode.h` | Prologue length check. Refuses a RIP-relative steal. |
| `offsets.ini` | `aces.exe` RVAs. Unverified. They die on every game patch. |
| `shared/protocol.h` | Command block and map parameter. |
| `shared/cleanup_stub.h` | Teardown stub bytes. |
| `build.bat` | WDK + MSVC x64. |
| `tests/test_logic.cpp` | Host-independent checks for the decoder, ini, and projection. |

## Build

From an x64 VS native-tools prompt, with the WDK installed:

```
build.bat
```

Outputs `wt_phys.sys` and `wt_host.exe` in this directory. Those extensions are
gitignored on purpose. No binary is shipped, because none was linked here.

The logic tests do not need the WDK. From a machine with g++:

```
g++ -std=c++17 -Wall -Wextra -o tests/test_logic tests/test_logic.cpp && ./tests/test_logic
```

## Run

`iqvw64e.sys` is the Intel network diagnostic driver (device `\Device\Nal`,
IOCTL `0x80862007`, cases `0x33` `0x30` `0x25` `0x19` `0x1A`). It is not in
this tree. You pass a copy you already have. The host prints that file's
SHA-256 and `TimeDateStamp`. It does not accept a substitute driver: if
`\\.\Nal` does not appear, it unloads and deletes the temp copy.

Memory Integrity and the Microsoft vulnerable-driver blocklist will refuse
this loader. The host only reads these values. It does not write them.

| Value | Key |
| --- | --- |
| Vulnerable driver blocklist | `HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable` |
| VBS | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity` |
| Memory Integrity | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled` |

If you set either enforcement off, set it back and reboot when you are done.
HVCI off is also required for the unsigned independent pages. Reboot after
changing it. Reboot if War Thunder was already open this boot, so `BEDaisy.sys`
is not already running while the loader is mapped. BattlEye is still the
kernel client War Thunder starts with the game (Eagle's Shadow, November 2026,
still loads `BEDaisy.sys`).

Run as Administrator, from the directory that contains `wt_phys.sys`:

```
wt_host.exe C:\path\to\iqvw64e.sys offsets.ini
```

What the host does, in order:

1. Copies the loader to `%TEMP%\<random>.sys` and starts a temporary service.
2. Resolves `MmAllocateIndependentPagesEx`, `MmFreeIndependentPages`, and
   `MmSetPageProtection` by the published patterns (1803 through the 26100
   PiDDB pattern). The second protect pattern is 20 bytes and its `E8` is the
   last byte (index 19). A circulating kdmapper copy adds 13, which does not
   land on that `E8`. This host reads the byte at the addend and aborts unless
   it is `E8`. A miss aborts. Those patterns were not re-validated on 25H2 or
   26H2 here.
3. Clears the PiDDB row for that temp name and timestamp, the `ci.dll` hash
   bucket entry whose name contains the temp file, and
   `BaseDllName.Length` so unload does not append `MmUnloadedDrivers`.
   Any miss aborts and unloads. It will not zero a name it did not match.
4. Maps `wt_phys.sys` without its PE header, calls `DriverEntry` through a
   temporary `NtAddAtom` hook, and restores those 12 bytes before installing
   the session gate.
5. Pings the payload. On failure it restores `NtAddAtom` and frees the pages
   while the loader is still loaded.
6. Shreds the temp file once, deletes it, unloads the service, and deletes
   the service key. SSD wear-leveling can keep an older copy. The vulnerable
   driver is not left resident.
7. Draws. INSERT toggles drawing. END or Ctrl+C sends `WT_CMD_STOP`, then
   waits three seconds so the stub can free the pages.

Start War Thunder after the "loader is not resident" line.

`listed 0` in the hangar is normal. `listed 0` for more than a few seconds
inside a match means `offsets.ini` is stale, not that the read path failed.
A failed read prints `read failed`.

The radar is north-up in the two horizontal axes. There is no yaw offset in
the ini, so the radar does not rotate with the camera. Brackets are drawn at
the projected position. There is no bone or bounds offset, so the bracket is
a fixed marker plus a distance, not a fitted box. Distance assumes the
position vector is in meters. `world_up=1` (Y up) is unverified.

## Offsets

```
cgame       = 0x7A4B848     UNVERIFIED, UC 2026-11-05, client string 2.59.0.98
localplayer = 0x7A22CB0     same post
viewmatrix  = 0x7AA58B8     same post, then withdrawn in the edit
unit lists  = cgame+0x310/0x320, +0x328/0x338, +0x340/0x350   inherited, unverified
position    = unit+0xD40    inherited, unverified
team        = unit+0x1018   inherited, unverified
state       = unit+0xF98    inherited, unverified; state <= state_max_alive is kept
owned_unit  = localplayer+0x8E8
```

No newer global was substituted. A June 2026 post used a different generation
(`cgame` around `0x6C2A3F0`). A September 2026 post used yet another
(`0x7A15218` / `0x7A252E8` depending on the reply). Those are not this file.

## System state the program changes, and how it is undone

| Change | When it is undone |
| --- | --- |
| Temp copy of the loader | Overwritten once, then deleted, before the overlay loop. |
| Service registry key | `NtUnloadDriver`, then the key is deleted, before the overlay loop. |
| PiDDB / ci hash bucket / `BaseDllName.Length` | Not restored. They describe a driver that has been unloaded. Restoring them would put the loader's name back. |
| Independent RWX pages | Freed by the stub about two seconds after END, if `STOP` is acknowledged. |
| `NtAddAtom` prologue | Restored by the payload on `STOP`, from the bytes saved at map time. |
| Pool tag `rWtC` (256 bytes, `POOL_FLAG_NON_PAGED_EXECUTE` = `0x80`) and `rWtP` (map parameter) | `rWtP` is freed before the loader unloads. `rWtC` is the stub and frees itself after the pages. `0x40` is nonpaged NX and is not used. HVCI can refuse executable pool; `DriverEntry` then fails and the image is freed before the loader unloads. |
| Blocklist / HVCI registry | Never written. You turn those back on yourself if you turned them off. |

If `STOP` is not acknowledged, the host exits without freeing the pages and
says so. Do not start the game again on that boot.

## What still catches it

- Executable physical pages that belong to no module, from map until the stub runs.
- A stack sample whose return address is in that range while a request is inside `WtGate`. `NtAddAtom` is rare, so the window is the request, not a 2 ms poll.
- PatchGuard or BattlEye comparing `NtAddAtom` with a clean image. The hook is a 12-byte `mov rax, imm64; jmp rax` plus nops out to an instruction boundary. Whether `NtAddAtom` is in the PatchGuard set was not established here. kdmapper uses the same instruction only for the duration of one call and then restores it. This build leaves it for the session because that is what lets the loader unload.
- A pattern miss. The host stops instead of pretending the wipe worked. A wipe that matches the wrong build can still corrupt a kernel structure. That is a crash risk, not a stealth feature.
- The EPROCESS list walk is unlocked. A process exit during the walk is caught with SEH and reported as a miss.
- `MmCopyMemory` of a page that is dirty in another CPU's cache can theoretically return a stale line. Positions that flicker are that class of bug. It was not measured here.
- Server-side stats. This build does not write view angles, combat state, or any other game memory.
- The loader is on public vulnerable-driver lists. Loading it while BattlEye is already up is the loud case. The host refuses to continue if `\\.\Nal` is already open.

## What was not done

- No local `aces.exe` was inspected.
- `build.bat` was not executed. This workspace has neither MSVC nor the WDK.
- `build.bat` was not executed. This workspace has neither MSVC nor the WDK.
- `g++ -std=c++17 -Wall -Wextra -o tests/test_logic tests/test_logic.cpp && ./tests/test_logic` was executed and printed `logic tests passed`. That does not compile the driver or the host.
- No live kernel, no BattlEye session, and no match were used.
- `iqvw64e.sys` was not embedded and not hashed against a known-good file in this tree.
