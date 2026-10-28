# What was done to GhidraMCP

A plain summary. `CAPABILITIES.md` is the how-to; `CHANGES.md` is the full history with
reasoning. This is the overview.

## Where it started

Stock LaurieWired GhidraMCP: **30 endpoints**. It could list functions, decompile one,
rename things, and read xrefs. Enough to look around a small binary, not enough to work on
a large one.

## Where it ended

**87 endpoints** (build 4.9), in six rounds of work, all verified against real Chivalry binaries.

## Things it can do now that it couldn't

**Find things**
- Search for a typed value — `90.0f`, `0x2710` — instead of hand-encoding bytes, with each
  hit's reference count returned so live constants are separable from coincidences
- Regex over disassembly, which beats byte patterns because it can't match mid-instruction
- Find which instructions touch a given struct offset
- Strings plus the functions that reference them, in one call

**Understand code**
- Everything about a function in one call, rather than four or five
- Trace where a value came from or where it goes, through the decompiler's dataflow and
  across function calls, ending with a list of what it couldn't follow
- Show a function's branch structure, and break down a single instruction with ready-made
  patch bytes
- Spot and repair functions wrongly flagged as never returning, which silently cut their
  callers' decompiles short
- Read the constant arguments at every call site of a function, which recovers whole tables
  at once, like every field a property registrar declares
- Gather transitive evidence about a function with no strings of its own — the imports it
  reaches, what its callees touch
- Resolve indirect calls to a vtable slot, and find which vtables contain a function
- Recover C++ class names and inheritance chains from RTTI

**Work with types**
- Parse a block of C straight into the type manager — unions, typedefs, enums, and types
  referencing each other
- Infer a struct from how a pointer is actually used, flagging which fields are called
  through and which feed float maths
- Create enums and name constants, so `if (state == 3)` can read as something meaningful

**Carry work forward**
- Read back its own renames and comments, so an earlier session's conclusions aren't lost
- Match functions between two builds of the same program by code shape, so names survive a
  game patch
- Undo and redo, per program, with a readable log of what changed

**Share the view**
- Move your Ghidra window to whatever is being discussed
- Leave findings as bookmarks in Ghidra's Bookmarks window, read back next session

**Drive Ghidra**
- Import a binary, run analysis, poll progress, save — without touching the GUI
- Open and close programs already in the project
- Work with several binaries at once, with every response saying which one answered

**Patch**
- Emit a verified Python patcher: checks the bytes are what you think, backs up, re-reads
  after writing, restores on mismatch, and refuses to run on a different build
- Convert between addresses and file offsets properly, instead of PE header arithmetic

## What was fixed in what already existed

The original bound its server to every network interface with no authentication, started a
new decompiler process per request, timed out after 5 seconds — shorter than one decompile
of a large function — returned HTTP 200 for errors, and listed functions without
pagination. All addressed early on. Later rounds added bounded waits so a modal dialog in
Ghidra can't wedge the server, and a `version` endpoint after a stale component wasted an
hour by behaving exactly like a working one. A `selftest` endpoint now checks the whole
set against the open program after each install.

## How it was verified

Every endpoint was run against real binaries — not just compiled and shipped. **40 defects
were found and fixed**, plus five in new code that only a live run exposed.

The ones worth noting returned confidently wrong *numbers* rather than errors: a vtable
slot index of 68 where the truth was 80, a second endpoint saying 16 for the same slot, and
an analysis command that reported success while doing nothing at all for three rounds. None
of them looked wrong. They were caught by checking against answers that were already known
from the frame-rate writeup, and by noticing two endpoints disagreeing with each other.

Where external ground truth existed, it was used: the writeup's documented addresses, bytes
read directly off the executables, and the published DirectShow class hierarchy, which the
RTTI recovery reproduced exactly including multiple-inheritance offsets.

## The files

| file | what it is |
|---|---|
| `bridge_mcp_ghidra.py` | the MCP bridge — point the client at this |
| `src/main/java/com/lauriewired/GhidraMCPPlugin.java` | plugin source |
| `docs/CAPABILITIES.md` | reference guide: what to reach for, and the environment's quirks |
| `docs/CHANGES.md` | full history, with the reasoning behind each change |
| `docs/SUMMARY.md` | this file |

The extension zip is built by `mvn clean package assembly:single` (see the README) or by the
GitHub Actions workflow.

Installing: uninstall the old extension, restart Ghidra, install the zip, restart again —
Ghidra only completes an uninstall at startup. Then restart the MCP client so it re-reads
the bridge. `version` will confirm both halves match.
