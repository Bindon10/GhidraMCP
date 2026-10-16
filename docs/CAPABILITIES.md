# GhidraMCP — capabilities and operating notes

A customised build of GhidraMCP (4.6). 86 endpoints against stock's 30. Written for a session
that has no memory of how it was built: what exists, what to reach for, and the things that
cost real time to rediscover.

`CHANGES.md` alongside this file is the history; this file is the reference.

---

## 1. Confirm what is running, first

```
version
```

Reports `plugin_build`, `bridge_build`, endpoint count, Ghidra version and current program,
and prints **MISMATCH** when the two halves disagree. They are separate processes updated
separately, and a stale half behaves exactly like a working one.

Do not infer the build from tool descriptions — the MCP client caches them and they lag the
running bridge. `version` is the only authority.

```
selftest
```

About 50 consistency checks against whatever program is open: name lookup (including
thunks), file-offset round trips, instruction bytes against memory, basic blocks tiling each
function, call-graph symmetry, `search_constant` re-finding a known immediate, decompile,
both trace directions, case-exact type lookup, `find_rtti` giving identical output at 16 MB
and 4 KB read pieces, and that a rolled-back write leaves nothing. Run it after every install.
It also fails on a build mismatch. The one write it makes is rolled back. Whole-program checks
run first; the whole run has a hard 40 s budget, and samples that do not fit are reported as
SKIP rather than overrunning the client's 60 s timeout.

## 2. Orientation

```
list_open_programs      what is loaded now, with the current one marked
list_project_files      what exists in the project, open or not
get_program_info        arch, pointer size, image base, counts, SHA-256
```

**Every response is prefixed `# program: <name>`.** With more than one binary open, reading
the wrong one produces answers that are internally consistent and completely wrong. Pass
`program=` explicitly rather than trusting the default; the prefix is there so the mistake
announces itself.

Three verbs, easy to confuse:
- `import_file` — brings a binary in from disk
- `open_program` — opens one already in the project but closed
- `select_program` — switches which open program is the default

---

## 3. Getting into an unknown binary

| want | use |
|---|---|
| a string names the code that handles it | `find_string_xrefs` |
| a magic number is all you have | `search_constant` |
| an instruction shape, encoding unknown | `search_instructions` |
| a known byte signature | `search_bytes` |
| who touches struct offset +0xNN | `find_field_accesses` |
| what has already been worked out here | `list_annotations`, `list_bookmarks` |

`search_constant` takes a typed value — `90.0f`, `0x2710`, `120` — encodes it to every
plausible width, searches data *and* instruction immediates, and returns each hit with its
containing function and reference count. **A hit with zero references is almost always
coincidental byte alignment.** That count is usually the whole answer.

`search_instructions` takes a regex over disassembly text and beats a byte pattern on its
own ground: byte patterns match mid-instruction and produce false positives that a
semantic search does not.

`list_annotations` is the resume-work call. Renames and comments written by an earlier
session are invisible to everything else in the API.

## 4. Understanding a function

| want | use |
|---|---|
| everything about one function | `get_function_context` |
| what it is, when the body says nothing | `function_evidence` |
| where a value came from, or where it goes | `trace_value` |
| its branch structure | `get_basic_blocks` |
| one instruction in full | `inspect_instruction` |
| what callers pass in | `get_call_sites` |
| decompiled C with addresses per line | `decompile_with_addresses` |
| notes left last time | `get_comments` |

`get_call_sites` with `with_args` is the strongest single call in the set. Pointed at a
registration helper it recovers a whole table at once — every field a property registrar
declares, every command a console registers — with strings and symbols resolved.

`function_evidence` walks *outward*: imported APIs reached within N hops, strings the
callees touch, already-named callers. For a leaf function with no strings of its own, the
identity is two or three hops away.

`trace_value` crosses function boundaries (`cross`, default 1). Backward, a call result
continues inside the callee's return statements, and a parameter continues at its callers'
call sites. Forward, an argument continues inside the callee and comes back out at *that*
call site's result. When a callee's parameter is missing from Ghidra's stored signature (the
usual case for `FUN_` functions), the caller's decompile drops the argument; the trace then
reads the caller's disassembly back to where the register is set, stepping over `__chkstk`.
Offsets appear inline as `[0x700]`. **Always read the closing `# not followed:` list** —
indirect calls, externals, memory writes, call sites past the cap. Those are open questions,
not empty answers.

Large functions: pass `decompile=False` for the cheap summary, then page the body with
`start_line` / `max_lines`. One 3,000-line function will otherwise fill the context.

## 5. Virtual dispatch and classes

```
resolve_virtual_call      CALL [RAX+0x280] -> slot offset, index, and target when static
find_vtables_containing   which tables hold this function, and at what index
get_vtable                walk a table, resolve each slot
find_rtti                 recover C++ class names and pair them with vtables
demangle                  RTTI names and mangled symbols
```

`find_rtti(with_bases=true)` gives the inheritance chain with each base's offset in the
object. Naming a vtable is worth more than naming a function — it labels every slot at once.

`resolve_virtual_call` reports a `this-0xNN` offset when the vtable pointer comes from a
base sub-object; that means the table reached is that base's, not the most-derived one.

## 6. Types

```
parse_c_header      a block of C straight into the type manager
create_struct       explicit offsets, "0x64:int:health;0x70:float:posX"
auto_create_struct  infer a struct from how a pointer is used
create_enum         name constants
set_equate          apply a name to a constant operand
get_type_info       read a type back
```

`parse_c_header` handles unions, typedefs, enums and mutually-referencing types, which
`create_struct` cannot. It is the fast path when SDK headers exist.

`auto_create_struct` walks the decompiler's p-code and reports every offset loaded, stored
or called through — flagging which are called through (vtable slots) and which feed float
math, neither knowable from access size. `apply=false` is a true dry run.

**If it finds nothing on a parameter**, the object pointer is usually not what the
decompiler models as that parameter — with an unset prototype the accesses flow through a
local such as `lVar1`. The error lists the function's variables; retry with `variable=`.

## 6a. Showing the user

```
goto_address      move the user's listing and decompiler to an address
set_bookmark      leave a note in Ghidra's Bookmarks window, category "Claude"
list_bookmarks    read them back - do this at the start of a session
remove_bookmark
```

Bookmarks are the shared notebook: the user sees them in Window → Bookmarks, and the next
session reads them back. They live in memory until `save_program`.

## 7. Across builds

```
match_functions   carry names from an analysed binary to a new one
```

Hashes each function by mnemonic sequence and operand *kinds*, ignoring addresses and
immediates so the hash survives rebasing. Only unique-in-both shapes are matched; ambiguous
ones are skipped rather than guessed. Both programs must be open.

This is what makes analysis survive a game patch. A low match count on an inlining-heavy
build is the safe failure. Raise `min_instructions` if a match looks wrong; never lower it.

## 8. Writing, and getting back

```
batch_rename        many renames, one transaction, one undo step
list_undo_stack     read what changed before reversing anything
undo / redo         per-program, correctly scoped
save_program        renames and types live in memory until this is called
```

Every write endpoint names its transaction, so the undo stack reads as a log. It includes
GUI edits too, not just API ones — read it before undoing.

`suggest_names_from_strings` mines assert and log strings for `Class::Method` identifiers
and proposes names for the single unnamed function referencing each. It proposes by default;
read the evidence string before applying, because a function that merely *logs* another
subsystem's name gets named wrongly, and a wrong name is worse than `FUN_140463f20`.

## 9. Patching

```
inspect_instruction     bytes, operands, flows, file offset, and same-length patch options
generate_patch_script   emit a verified Python patcher
file_offset             VA <-> file offset, both directions
```

`inspect_instruction` on an x86 conditional jump gives never-jump (NOPs), always-jump
(`EB rel8`, or `90 E9 rel32` for the six-byte form) and inverted bytes, plus the
`addr:old->` prefix for `generate_patch_script`. On a call it gives NOPs, with the warning
that the return register then keeps whatever it held.

Every edit is checked against the program before the script is written — the address must
hold exactly the stated old bytes, and lengths must match. The emitted script verifies a
byte window and the file's SHA-256, backs up, re-reads from disk, restores on failure, and
supports `--check` / `--revert` / `--force`. `--force` skips the whole-file hash but never
the local byte windows, so a partially patched build is still refused.

The embedded hash is the program's **import-time** SHA-256. Patching a file that has changed
since import will be refused, which is the intent.

---

## 10. Environment, and what wastes a session

**The plugin lives inside a tool, not the project.** No CodeBrowser open means no plugin
instance and no HTTP server — connection refused on 8080 is correct behaviour at the project
window, not a fault. A program need not be loaded; the tool does.

**After reinstalling the extension, check File → Configure → Miscellaneous.** Uninstalling
removes the plugin class and Ghidra drops it from the tool's saved configuration; installing
it again does not put it back.

**If the plugin does not answer after an install even with a program open**, Ghidra may have
restored its saved tool state from before the install. Check Help → Show Log for
`GhidraMCP HTTP server started`; if it is missing, reinstall once more and restart.

**Uninstall completes at the next startup.** Ghidra renames `extension.properties` to
`.uninstalled` and removes it on restart, so installing over an existing copy in the same
session does nothing. Uncheck → restart → install → restart.

**On Windows, extensions live under `%APPDATA%\ghidra\ghidra_<version>_PUBLIC\Extensions\`**, not
`~/.ghidra`, which Ghidra stopped using at 11.0.

**Restarting the bridge means restarting the MCP server process**, which usually means fully
quitting and reopening the MCP client. An in-app reconnect may not respawn it.

**Modal dialogs block writes.** "Analyze?" and Analysis Options are modal; imports open
programs *hidden* to avoid them, and `start_analysis` drives the analysis manager directly
rather than through the prompt. The **Auto Analysis Summary** at the end is *not* modal and
blocks nothing. Any call that needs Ghidra's UI thread gives up after 40s with a message
naming a dialog as the likely cause rather than hanging.

**The MCP client gives up at 60s** regardless of what the bridge allows, so `import_file`
and `start_analysis` return immediately and report through `analysis_status`.

**`analyzed` vs function count.** `analysis_status` reads the live program;
`list_project_files` reads disk. Between analysis finishing and `save_program` they
disagree, and both are right.

---

## 11. Known-answer anchors

For re-validating the toolset rather than trusting it. All from Chivalry: Medieval Warfare
`CMW.exe`, SHA-256 `bb7b1f52e49bf647e9ec24c5745d36427f725a18442355cd77335c7481facdaa`:

| check | expected |
|---|---|
| `file_offset 0x140463f4f` | `0x46334f` (and `VA - 0x140000000 - 0xC00`) |
| `search_constant 90.0f` block `.rdata` | 3 hits; only `0x1411E4EF8` referenced, 5 referrers |
| `find_string_xrefs UNCAPFPS` | one string at `0x14130AFE0`, one ref from `UEngine_Exec` |
| `search_bytes B8 78 00 00 00 3B C8 0F 4C C1` | exactly 1 hit, at `+0x15D` into `GetMaxTickRate` |
| `resolve_virtual_call 0x1404793a7` | slot `0x280`, index 80, vtable ptr from `this-0x60` |
| `find_vtables_containing UGameEngine_GetMaxTickRate` | base `0x141311950`, index 80 |
| `find_rtti CSource with_bases` | `CBaseFilter <- CUnknown <- ... <- IAMovieSetup+0x20`; 52 classes total |
| `inspect_instruction 0x140463f4f` | `0f 84 43 01 00 00`; always jump `90 e9 43 01 00 00` (the shipped patch) |
| `inspect_instruction 0x1404438D8` | `73 0a`; always jump `eb 0a` (the shipped patch) |
| `get_basic_blocks 0x140463f20` | 35 blocks covering 429 of 429 bytes; `MOV EAX,0x78` block at `+0x15D` |
| `trace_value 0x140463f20 param_1 forward` | into `UEngine_GetMaxTickRate`: `[0x3f8]` `& 0x100`, `[0x700]`, `[0x704]` |
| `trace_value 0x140441780 param_1` | caller `FUN_140471cb0` passes its own parameter 0 (from disassembly) |
| `selftest` | all pass, including `BOOL / bool` and thunk `OutputDebugStringW` |

From Mirage's `TBLServer.exe` (SHA-256 `d315619393baff933fca7306749faecaa4320cb933425d2f21e6b212a2c226eb`,
546k functions, PDB loaded):

| check | expected |
|---|---|
| `find_rtti` | 536 classes, COLs `0x145f623e0`–`0x145f75248`; matches an independent whole-file scan |
| `selftest samples=1` | all pass, including the 16 MB / 4 KB `find_rtti` comparison |

The `+0x15D` and `+0x139` offsets inside `GetMaxTickRate` hold across the MW client, the DW
client and the DW dedicated server — three different binaries built from the same engine
source. Useful as a cross-build sanity check.

## 12. Limits worth knowing

- **UE3 ships with RTTI disabled.** `find_rtti` on a Chivalry binary returns only
  statically-linked third-party classes (DirectShow, FaceFX). The engine's own structure
  comes from its `UProperty` registrar instead — reachable via `get_call_sites`.
- **Slot counts from `find_rtti` are a lower bound**; they stop at the first entry that is
  not a code pointer. Template classes are reported mangled rather than guessed at.
- **`set_local_variable_type` cannot resize a hash-storage variable** — one the decompiler
  synthesised with no fixed register or stack location. Register and stack variables resize
  fine. A same-sized type is the way through.
- **`auto_create_struct` does not follow a loaded pointer into a second struct**, by design;
  otherwise `player->weapon->damage` would be filed as a field of `player`. Run it again on
  the inner pointer.
- **Function names can repeat.** Lookup by name refuses an ambiguous name and lists the
  candidates; pass an address or a qualified name. Import thunks qualify by their DLL:
  `MSVCR100.DLL::memset`.
- **`trace_value` treats a value passing a call as unchanged** (the decompiler's `INDIRECT`
  marker) and says so in `not followed`. Its disassembly fallback only walks straight-line
  code; at a join point or an intervening call it stops and says why.
- **`search_decompiled` matches comments too**, since decompiled output includes them.
- **`find_vtables_containing` finds a table's base by walking back** while preceding entries
  point into executable memory. A table whose leading entries are not code pointers can
  still report a base too high; cross-check against a known call site when the index matters.

## 13. Working discipline

The build history is instructive: 31 defects in the inherited and earlier code, plus three
in the 4.2 additions that only a live run exposed, and the ones that mattered returned
*confidently wrong numbers* rather than errors — a slot index of 68 where the truth was 80,
an analysis that reported success while doing nothing. None looked wrong.

So: check answers against something external where one exists — a writeup, published
headers, bytes read off the file — and cross-check endpoints against each other where one
does not. Two tools disagreeing is a signal available without an oracle. A call returning
successfully is not evidence that it did anything.
