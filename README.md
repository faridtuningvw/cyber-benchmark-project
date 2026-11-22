# wt-phys

External read-only overlay for War Thunder (`aces.exe`). BattlEye (`BEDaisy.sys`) plus the in-process Viking client is the target. The kernel half never opens the game, never attaches to it, and never writes it. The loader image is mapped, used, wiped, and unloaded before you start the game.

A UEFI bootkit is the wrong tool here. BEDaisy loads with the game, not at boot. A pre-OS component means Secure Boot off and a measured-boot mismatch, which is a louder tell than a headerless image that exists only as executable pages.

## Pieces

| File | Role |
| --- | --- |
| `driver/wt_phys.c` | Manual-mapped payload. CR3 walk, physical reads, scatter. No device object. |
| `host/wt_host.cpp` | Loads a vulnerable signed image, maps the payload, clears loader traces, unloads that image, then draws. |
| `offsets.ini` | `aces.exe` RVAs. These die on every game patch. |
| `build.bat` | WDK + MSVC x64 build. |

## What is being avoided

- `OpenProcess` / `ReadProcessMemory` on `aces.exe`. Viking and BE hook those.
- `MmCopyVirtualMemory` and `KeStackAttachProcess`. Same idea, kernel side.
- A named device left behind for `\\Device` enumeration.
- A PE header in the private kernel allocation.
- One tagged pool the size of a driver (`MmAllocateIndependentPages` path).
- Leaving the vulnerable loader's name in PiDDB, the ci.dll hash bucket, or the unloaded-driver list.
- Having that loader still resident when BEDaisy starts. It is on the Microsoft vulnerable-driver blocklist and on BE's copy of the same list.

What still catches it: an executable-page scan of PFNs that belong to no module, a stack sample that lands in the payload while it is inside a request, a stale pattern so a trace wipe silently no-ops, and server-side stats if the overlay is used like an aimbot. This build does not write view angles.

## Build

From an x64 VS native-tools prompt, with the WDK installed:

```
build.bat
```

Outputs `wt_phys.sys` and `wt_host.exe` in this directory.

## Run

Memory Integrity / HVCI has to be off or Windows refuses the loader image. Reboot after changing it. Reboot if War Thunder was already open this boot, so BEDaisy is not watching the map.

```
wt_host.exe C:\path\to\iqvw64e.sys offsets.ini
```

`iqvw64e.sys` is the Intel network diagnostic driver (the public Nal primitive, IOCTL `0x80862007`). It is not shipped here. The host copies it to a temp name, loads it, maps `wt_phys.sys`, pings the payload, clears loader traces, shreds the temp file, and unloads it. Then the overlay is up.

Start War Thunder after that line is printed. INSERT toggles drawing. END tells the payload to stop polling and exits.

The console prints `listed` / `drawn`. `listed 0` for more than a few seconds after you are in a match means `offsets.ini` is stale, not that the driver failed.

## Offsets

Defaults are the 2.59.0.98 numbers posted on UnknownCheats on 2026-11-05:

```
cgame       = 0x7A4B848
localplayer = 0x7A22CB0
viewmatrix  = 0x7AA58B8
unit lists  = cgame+0x310/0x320, +0x328/0x338, +0x340/0x350
position    = unit+0xD40
team        = unit+0x1018
state       = unit+0xF98
```

`w2s=1` if boxes sit off-screen with a sane unit count. That flips the matrix multiply.
