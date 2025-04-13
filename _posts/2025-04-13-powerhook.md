---
layout: post
title:  "Code execution inside PID 0"
date:   2025-04-13 22:18:00 +0200
---

A few days ago, a seemingly random thought came up in the back of my mind. On every system, there's a process whose Process ID is ``0``. This process is called the ``System Idle Process``, and contains threads that execute when no other thread is ready to run on a given processor.

The question is simple. ***Can I somehow get code execution inside of this process?***

## Initial probing
Trying to do anything with the process from user-mode is quickly met by failure. My initial attempt was simply calling [``OpenProcess``](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) with the ``dwProcessId`` parameter specified as ``0``.

Unsurprisingly, the function didn't like that, as it didn't give me a valid handle, and set the last error as ``ERROR_INVALID_PARAMETER`` instead. In retrospect, I should've read the documentation first, as it explicitly mentions this particular case. 

Wanting to get the exact error code, I turned to [``NtOpenProcess``](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess). With both members of the ``ClientId`` set to zero, the function returned ``STATUS_INVALID_CID``.  

Tracing the call via a kernel debugger reveals the exact reason. The call to ``PspReferenceCidTableEntry`` inside ``PsLookupProcessByProcessId`` returns 0.

## Turning to the kernel
At this point, it's obvious that we're not dealing with an ordinary process. Turning to existing literature, I checked out  [the first part of Windows Internals](https://a.co/d/68rZWih), which had the following to say:
> The idle process and idle threads are special cases in many ways. They are, of course, represented by ``EPROCESS`` and ``ETHREAD`` structures, but they are not executive manager processes and thread objects. Nor is the idle process on the system process list. 
> (This is why it does not appear in the output of the kernel debugger’s !process 0 0 command.) 

Reading all this led me to the conclusion that I needed to rethink my approach. Instead of trying to spawn a thread inside a non-existing process, I looked for ways of simply gaining code execution inside ``nt!KiIdleLoop``. There's only a few functions being invoked on each iteration of the loop inside, so by process of elimination, I ended up looking deeper into ``nt!PoIdle``. 

This function is, from my understanding, only called when the thread is truly idle. I didn't have to go far to find my first possible hook point. There are several calls made to ``HalPrivateDispatchTable`` routines, all of which can be potentially hooked to gain execution.

While I could spend the rest of this article rambling about ``HalPrivateDispatchTable`` and how it's possible to simply swap a function pointer inside it, I will not. To actually make me dig further, I self-imposed a restriction: **no widely-known hook points are allowed.**.

While there exist some dispatch table methods that do fit this criteria, their hooking is still easily detected by simply scanning the entire structure for addresses outside of known system modules. A closer look at the ``nt!PoIdle`` function reveals that it calls multiple power management functions, which are responsible for switching the processor into a lower-power state. 

The [Windows Internals](https://a.co/d/68rZWih) book actually highlights this step as well:
> The idle thread calls the registered power-management processor idle routine (in case any power-management functions need to be performed), which is either in the processor power driver (such as intelppm.sys) or in the HAL if such a driver is unavailable.

## Power management hook
Knowing that the so-called processor idle routine is overridable by third-party drivers, it was pretty obvious that a function pointer must exist somewhere. Since there aren't that many functions being called from ``nt!PoIdle`` (the ``Po`` being short for ``Power``, affirming that we're looking in the right place), I decided to go through them one by one until I found it.

Upon a high-level overview of the method, one call immediately stood out to me. From its name, ``nt!PpmIdleSelectStates`` does exactly what we're interested in. Sure enough, buried deep inside the function is the following piece of code:
```cpp
// A lot of code has been omitted, this snippet is near
// the middle of the function's body.
PPM_IDLE_STATES* idle_states = KeGetCurrentPrcb()->PowerState.IdleStates;

if (idle_states->IdlePreselect)
{
    idle_states->IdlePreselect(
        idle_states->PrepareInfo->Context, 
        &idle_states->PrepareInfo.Constraints
    );
}
```
Perfect. All that's left is to swap the pointer inside any ``_KPRCB`` we desire, and we're off to the races. 

## Detection
The detection is actually not as simple as one might think. Due to the process and thread not being valid kernel objects, traditional APIs like ``ObOpenObjectByPointer`` and ``PsLookupThreadByThreadId`` will fail. Manual lookup via ``PspCidTable`` will also fail, as neither the thread nor the process actually have valid entries. 

The most obvious detection method is simply checking the pointer inside the ``_KPRCB``. To do so, the anti-cheat would need to run on the same logical processor, or use undocumented functions like ``KeQueryPrcbAddress``. Another detection may come from an interrupt coming from an external source - [NMIs](https://en.wikipedia.org/wiki/Non-maskable_interrupt) from [EasyAntiCheat](https://easy.ac/en-US) come to mind. I won't confirm nor deny that queuing APCs on the thread may or may not be effective, as that remains to be tested.

## Proof of concept
The proof of concept code, tested on Windows 11 24H2 (26100.3775), is available [here](https://github.com/Archie-osu/PowerHook). Keep in mind that ``_KPRCB`` offsets change often, so double-check everything is correct before running the driver!
