# GhidraMCP improvements

Built against Ghidra 12.1.2 (matches `extension.properties`). Baseline was stock
LaurieWired GhidraMCP — 30 endpoints / 27 MCP tools. Round 1 took it to 45 endpoints /
45 tools; round 2 to 58 / 58; round 3 to 73 / 73; 4.x to 87 / 87 (current build 4.9).

## Install

1. Ghidra → File → Install Extensions → remove the old GhidraMCP → add `GhidraMCP.zip` → restart.
2. Replace `bridge_mcp_ghidra.py` with the new one (same CLI args, plus `--timeout` / `--slow-timeout`).

Existing tool names and signatures are unchanged except `list_functions`, which is now
paginated and takes an optional `filter`.

---

## Fixes to existing behaviour

**The HTTP server bound to `0.0.0.0`.** `new InetSocketAddress(port)` binds every
interface, and the API can rename functions, rewrite prototypes and edit data types
with no authentication — anyone on your network could modify an open project. Now binds
`127.0.0.1` by default, with a `Bind To Localhost Only` tool option to opt out.

**A new decompiler process per request.** Every decompile built a fresh `DecompInterface`,
called `openProgram`, and never disposed it. Now one cached interface per program,
serialized behind a lock and disposed on unload. This is the difference between a
several-second and a sub-second decompile on a warm cache.

**5-second client timeout.** Shorter than a single decompile of a large function, so big
binaries produced spurious `Request failed` errors that looked like the server was down.
Now 60s default / 300s for decompile and search endpoints, both configurable.

**Single-threaded executor.** `server.setExecutor(null)` serialized every request behind
the slowest one. Now a 4-thread pool; decompiler access stays serialized internally.

**Every response was HTTP 200.** `"No function found"` and actual results were
indistinguishable to the client. Failures now map to 400 / 404 / 409 / 500, so the bridge
surfaces them as `Error <code>: ...`.

**`list_functions` was unbounded.** It streamed every function in the program with no
pagination — unusable on anything real. Now paginated with a name filter, and returns
`address<TAB>name<TAB>size` instead of just names, so you don't need a second lookup to
get an address.

**Duplicate names resolved silently.** `decompile_function(name)` took the first
`.equals()` match, so C++ overloads and thunks decompiled the wrong body without warning.
It now returns the list of candidate addresses instead of guessing.

---

## New endpoints

### Fewer round trips

- **`get_function_context`** — signature, calling convention, params, locals, callers,
  callees, referenced strings, and decompiled C with a source address on every line, in
  one call. Replaces the usual 4–5 call sequence for reading a function.
- **`decompile_with_addresses`** — decompiled C as `0x140001a2c | if (iVar1 == 0) {`.
  The comment endpoints need an address; plain decompiled output has none, so placing a
  decompiler comment on the right line previously involved guessing.
- **`batch_rename`** — many `address=NewName` pairs in one request and one transaction.
  Renaming 40 functions was 40 round trips and 40 undo steps.
- **`program_info`** — architecture, endianness, pointer size, image base, compiler spec,
  counts. One call that replaces inferring bitness from address widths.

### Game reversing

- **`search_bytes`** — AOB search with wildcards (`48 8B ?? ?? 89 05`, `4c8d05????????`,
  `\x48\x8b`). Returns block and `function+offset` per hit, so you can check signature
  uniqueness in the same call.
- **`get_vtable`** — walks a pointer table, resolves each slot to a function, stops at the
  first null or unmapped entry. Pair with `list_symbols(filter="vftable")`.
- **`create_struct`** — build a type from `0x64:int:health;0x70:float:posX`, explicit
  offsets with gaps or sequential layout. This is what turns
  `*(int *)(param_1 + 0x64)` into `player->health` across every function that touches it.
- **`apply_data_type`** — lay a type (or array of it) over an address.
- **`get_type_info`** — full struct layout: offset, size, type, field name.
- **`list_data_types`** — search the type manager. `set_local_variable_type` fails silently
  on a type that doesn't exist; check here first.
- **`read_bytes`** — hex dump, for headers, jump tables and packed data.

### Navigation

- **`get_callers`** / **`get_callees`** — direct call relationships without walking xrefs.
- **`call_graph`** — indented call tree, up or down, depth-limited. Walking *up* is how you
  find how execution reaches an interesting leaf function.
- **`list_symbols`** — all symbol types, substring or `/regex/`. Finds vtable symbols,
  RTTI descriptors and class namespaces that `search_functions_by_name` cannot.
- **`search_decompiled`** — grep decompiled C across functions. Finds magic constants and
  comparison patterns that no name or byte search will. Scope it with `name_filter`.
- **`disassemble_range`** — N instructions from any address, no function required.
- **`create_function`** — define a function where auto-analysis left loose code.

---

## Verified

- Compiles clean against Ghidra 12.1.2 jars; all 16 new contexts present in the built jar.
- Byte-pattern parser tested across spaced, unspaced, escaped and wildcard forms, plus
  rejection of malformed tokens.
- Status-code mapping tested against representative success and failure strings.
- Bridge imports and registers 45 tools.

Not verified end-to-end against a live Ghidra instance — Ghidra was not running
(port 8080 refused) while this round was built. The Ghidra API calls are compiler-checked, but
the write endpoints (`create_struct`, `apply_data_type`, `create_function`, `batch_rename`)
should get one smoke test on a scratch project before you trust them on real work.

---

# Round 2 — comprehension, cross-referencing, recall

13 more endpoints: 45 → 58 HTTP contexts, 45 → 58 MCP tools (round 1's "46 endpoints"
header was an overcount — the actual `createContext` count was 45). Nothing existing changed, so an
in-progress project keeps working. Same install steps as above.

The theme is different from round 1. That round was about round trips and correctness.
This one is about the three things that actually consume a session on a stripped game
binary: finding a thing, working out what a function does, and not losing what you
already learned.

## Recall

Analysis notes were write-only. `set_decompiler_comment` and `rename_function` could
write them; nothing could read them back, so the next session started blind and
re-derived conclusions it had already reached.

- **`list_annotations`** — every `USER_DEFINED` symbol and every comment in the program,
  filterable. Auto-analysis names are excluded by construction, so what comes back is
  exactly the human (or agent) contribution. Call it first when resuming a binary.
- **`get_comments`** — the same thing scoped to one function, in address order.

## Finding things

- **`search_constant`** — takes `90.0f`, `0x2710`, `120`, and searches for it as float,
  double, int32, int64 and instruction immediate, whichever apply. Each hit comes back
  with block, containing function and reference count already resolved. Replaces the
  encode-IEEE-754-by-hand → `search_bytes` → `get_xrefs_to`-per-hit sequence, and the
  reference count is what separates the live constant from pooled duplicates in the
  same call. (`00 00 B4 42` for 90.0f is now something you never type.)
- **`search_instructions`** — regex over disassembly text. `MOV dword ptr \[.*\+0x700\],`
  finds every immediate write to a field without guessing an opcode encoding, and
  without missing the encodings the guess would have missed.
- **`find_field_accesses`** — every instruction using a given offset off a register
  base. Reads operands rather than decompiling, so it is fast, and it works before any
  type has been applied — which is when offset discovery actually happens.

## Working out what a function does

- **`get_call_sites`** — every call site with its constant arguments decoded: strings
  resolved to text, addresses to symbol names, immediates to hex. This is the highest
  yield call in the set. Pointed at a property or command registrar it recovers the
  whole table in one request — name, offset and flags for every field — instead of one
  offset per manual read.
- **`resolve_virtual_call`** — `CALL qword ptr [RAX + 0x280]` to a slot index, and to
  the concrete target when the table is statically known.
- **`find_vtables_containing`** — the inverse: which tables hold this function, at what
  index. Turns one interesting function into the same slot across every sibling class.

## Types

- **`parse_c_header`** — a block of C straight into the program's type manager, through
  Ghidra's own preprocessor and parser. Structs, unions, enums, typedefs, and types
  that reference each other — none of which `create_struct` can express. Paste a dumped
  SDK header and stop building types one field at a time.
- **`auto_create_struct`** — infers a struct from how a pointer is *used*. Walks the
  decompiler's p-code from a parameter or local, collects every offset loaded, stored
  or called through, and builds the type. Flags which offsets are called through (vtable
  slots) and which feed float math — neither is knowable from access size alone.
- **`create_enum`** + **`set_equate`** — name constants. `if (state == 3)` becomes
  `if (state == EState_Dying)` at every site the equate is placed. Structs name offsets;
  this names values, and there was previously no path to it at all.

## Patching

- **`file_offset`** — VA ↔ file offset in both directions, from the loader's section
  mapping rather than PE header arithmetic. Uninitialized sections are reported as
  having no file bytes instead of being given a plausible wrong answer.

---

## Verified (round 2)

- Compiles clean against the Ghidra 12.1.2 jars in `ghidra_12.1.2_PUBLIC`; all 13 new
  contexts confirmed present in the built jar's constant pool.
- Endpoint parity checked mechanically: 58 HTTP contexts, 58 bridge tools, no endpoint
  in one and missing from the other.
- The value encoder was unit-tested against the shipped bytecode via reflection —
  90.0f, 120.0f, 10.0f, 0.003333f, 0.2 as double, 0x2710, 0x78 and a 64-bit pointer,
  little- and big-endian — and cross-checked against Python's `struct.pack`. The three
  constants from the frame-rate writeup encode to the bytes that writeup used.
- Bridge byte-compiles and registers 58 tools.

Same caveat as round 1, and it applies harder here because more of these write:
**not verified against a live Ghidra instance.** The API calls are compiler-checked, but
`parse_c_header`, `create_enum`, `set_equate` and `auto_create_struct` all modify the
program. Give them one run on a scratch copy before pointing them at CDW.

Two known limits, by design rather than accident:

- `auto_create_struct` deliberately does not follow a loaded pointer into a second
  struct — otherwise `player->weapon->damage` would file `damage` as a field of
  `player`. Run it again on the inner pointer instead.
- `find_vtables_containing` locates a table's base by walking backwards while the
  preceding pointers still resolve to functions. A table whose leading entries are
  undefined code will report a base that is too high, and an index that is too low.

---

# Round 3 — the wrong-binary problem, recovery, and getting work in and out

15 more endpoints: 58 → 73 contexts, 58 → 73 tools. Two changes affect existing tools
(both additive, no signature breaks):

- **Every tool now takes an optional `program` argument**, and **every response is
  prefixed with `# program: <name>`**. The prefix matters more than the argument. With
  two binaries open, reading the wrong one produces answers that are internally
  consistent and completely wrong, and nothing in the previous API made that visible.
  Now it is stated on every response whether you asked for it or not.
- **`decompile_function`, `decompile_with_addresses` and `get_function_context` accept
  `start_line` / `max_lines`.** One 3,000-line function could previously fill a caller's
  entire context with no way to sip it.

`get_xrefs_to`, `get_xrefs_from` and `get_function_xrefs` now report `function+0xNN`
rather than just a function name, and `get_xrefs_from` resolves string targets to their
text. That was owed from round 2 — the new endpoints did it, the existing ones didn't.

## Program selection

- **`list_open_programs`** — index, name, architecture, function count, unsaved-changes
  and analysis state for everything open, with the current program marked.
- **`select_program`** — change the default for calls that don't pass `program=`.

## Import and analysis

Ghidra can be driven end to end now, without touching the GUI.

- **`import_file`** — import a binary from a path on the machine running Ghidra, save it
  into the project and open it. Paths are resolved by Ghidra, so they are that machine's
  paths.
- **`start_analysis`** — queued through the tool's own background-command mechanism, so
  transactions, the progress bar and the GUI's analysis state all behave exactly as they
  do for an analysis started from the menu. Returns immediately.
- **`analysis_status`** — whether analysis is running and how many functions exist so
  far. A rising count between calls means it is still doing useful work.
- **`save_program`** — write the program back to the project.

## Recovery

- **`undo`** / **`redo`** / **`list_undo_stack`** — every write endpoint names its
  transaction, so the stack reads as a log of what changed. Round 2 added four write
  endpoints with no way back; this is the matching half. The stack includes GUI edits
  too, so read it before reversing anything.

## Identification

- **`find_string_xrefs`** — strings matching a pattern together with the functions that
  reference them, in one call instead of `list_strings` plus one `get_xrefs_to` per hit.
- **`function_evidence`** — transitive evidence for what a function is: imported APIs
  reached within N hops, strings its callees touch, already-named callers and callees.
  For a leaf function with no strings of its own — which is most of them — the identity
  is two or three hops out, and nothing previously reached it.
- **`suggest_names_from_strings`** — mines assert and log format strings for
  `Class::Method` and `Name()` identifiers and proposes names for the single unnamed
  function that references each one. Proposes by default rather than applying; output is
  `address=Name` so a reviewed subset can go to `batch_rename`.
- **`trace_value`** — a backward slice through the decompiler's definition chain.
  Answers "where did this come from", which decompiled text cannot: the C shows `uVar3`
  and stops. Stops at call boundaries by design.

## Cross-binary

- **`match_functions`** — hashes each function by mnemonic sequence and operand *kinds*,
  deliberately ignoring addresses and immediates so the hash survives rebasing and
  constant changes. Matches shapes unique in both programs, and carries names from the
  analysed binary to the new one. This is what makes analysis survive a game patch, and
  what ports work between two builds of the same engine. Ambiguous shapes are skipped
  rather than guessed.

## Patching

- **`generate_patch_script`** — emits a verified Python patcher. Every edit is checked
  against the program in Ghidra first: the address must contain exactly the stated old
  bytes and lengths must match, or nothing is emitted. The generated script verifies a
  window of surrounding bytes and the file's SHA-256 before writing, backs up, re-reads
  from disk afterwards, restores the backup if verification fails, and supports
  `--check` / `--revert` / `--force`.

  Chosen over a `write_bytes` endpoint deliberately: the artifact is reviewable, works
  after Ghidra is closed, and fails closed on a build it doesn't recognise. `--force`
  skips the whole-file hash but never the local byte windows.

---

## Verified (round 3)

- Compiles clean against the Ghidra 12.1.2 jars; all 15 new contexts confirmed present
  in the built jar.
- Parity: 73 HTTP contexts, 73 bridge tools, no endpoint in one and missing from the
  other. All 58 pre-existing tools mechanically rewritten to pass `program` through, and
  the rewrite verified by count (58 signatures, 58 call sites) and by inspection of the
  awkward cases — the raw-body POST, the multi-line calls.
- Unit tests against the shipped bytecode via reflection: byte-list parsing across
  spaced, unspaced, escaped and comma forms plus rejection of malformed input; line
  windowing including the past-the-end case; symbol-name sanitising; default-name
  detection; hash order-sensitivity and determinism; Python string quoting. Plus the
  round-2 encoder suite, still passing.
- **The generated patcher is tested end to end.** The script body is extracted from the
  compiled jar — not retyped — wrapped in the same preamble `generate_patch_script`
  emits, and run against a synthetic binary: check on a clean file, apply, byte-exact
  verification that nothing outside the edits moved, refusal to double-apply, revert,
  restoration to the original bytes, refusal on a corrupted edit window, refusal on an
  unrecognised build, and `--force` applying when the windows still match while still
  refusing when they don't. 18 assertions, all passing.

Still not verified against a live Ghidra instance, and round 3 adds the most
consequential writes yet — `import_file`, `start_analysis` and `match_functions --apply`
all change project state. Worth exercising in this order on something disposable:
`list_open_programs` → `import_file` on a small binary → `start_analysis` →
`analysis_status` → `list_undo_stack` → a rename → `undo`.

One design note worth knowing: `match_functions` hashes operand *kinds*, not operand
values, so a function whose only difference between builds is a changed constant still
matches. The cost is that two functions differing only in a constant are also
indistinguishable to it — which is why ambiguous hashes are dropped rather than
resolved, and why `min_instructions` defaults to 8 rather than lower.

---

# Round 3.1 — six defects found by running it

First live run, against the analysed CMW.exe project (105,398 functions). The endpoints
were checked against the frame-rate writeup, which gave independently-known answers
rather than "looks plausible". Everything below was found that way, and fixed.

## What was right

- `file_offset 0x140463f4f` → `0x46334f`, matching hand-computed PE arithmetic exactly.
- `search_constant 90.0f` in `.rdata` → three hits, the live one at `0x1411E4EF8` with its
  five referrers resolved and the other two flagged as unreferenced, in one call.
- `find_string_xrefs UNCAPFPS` → `0x14130AFE0`, one reference, `UEngine_Exec @ 0x1404793D2`.
- `list_annotations` → the four renames from that session; `get_comments` → the five
  decompiler notes, which is the read-back path that did not exist before.
- `find_field_accesses 0x6d8` → the `DIVSS` at `UGameEngine_GetMaxTickRate+0x10f`, with
  read/write classification separating it from the `CALL qword ptr [RAX + 0x6d8]` noise.
- `create_enum` → `list_undo_stack` → `undo` round-tripped, with the type confirmed gone.
- `suggest_names_from_strings` proposed twelve real UE3 names — `FExec::Exec`,
  `UProperty::GetCPPType`, `FConfigFile::Dump` — mined out of log strings.

`search_instructions` beat the byte pattern it replaces. The writeup's
`C7 ?? 00 07 00 00` returns two `.text` hits; the regex returns one. The extra byte hit is
at `0x140C55DEB`, one byte inside `MOV dword ptr [R13],0x7` at `0x140C55DEA` — a
mid-instruction false positive. So the writeup's "two hits, one unrelated" was one real
site plus an artifact, and its conclusion is stronger than it claimed.

## Defects fixed

**`resolve_virtual_call` reported the wrong slot.** For `CALL qword ptr [RAX + 0x280]` it
returned offset `0x220`, index 68. The real answer is `0x280`, index 80. Two dereferences
are involved — one loads the function pointer out of the vtable, one loads the vtable
pointer out of the object — and offsets from both were being summed. Here the object side
contributed `-0x60` (`LEA RCX,[RDI + -0x60]`, a base sub-object), and `0x280 - 0x60` is a
perfectly plausible slot number. Now the accumulation stops at the second dereference, and
the object-side offset is reported separately as what it is: a base sub-object, so the
table reached is that base's, not the most-derived one.

**`find_vtables_containing` reported index 16 instead of 80.** It walked backwards while
the preceding entries were *defined functions*, and stopped at `0x141311B48` because
`0x140004EF0` is a code pointer auto-analysis never turned into a function. The true base
is `0x141311950` — verified by reading it directly, where the preceding bytes are not
pointers. Now the walk accepts any pointer into executable memory. Both fixes independently
land on index 80, agreeing with the writeup's `0x280`.

**`trace_value` traced the wrong value.** Asked about `DIVSS XMM6,[RAX + 0x6d8]` it
returned the `INT_ADD` that computes the operand address. One instruction lowers to several
p-code operations and it took the first with an output; it now takes the last, which is the
instruction's result, and names the other operations so the choice is visible.

**`suggest_names_from_strings` could propose two names for one address.** `0x140035300`
came back as both `GConfig::LoadFile` and `FConfigCacheIni::LoadFile`, from two strings it
references. Applied, that renames the function twice with the last one silently winning.
Candidates are now grouped by address; a name the string *opens with* wins over one merely
mentioned; genuine ties are reported for a human instead of being guessed.

**`auto_create_struct` failed uninformatively.** On a function whose signature is still the
analyser's default it found nothing and said so without saying what to do. It now prints the
prototype, says when the signature is a default guess, and lists the function's variables so
the retry is obvious.

**The instruction-scan cap silently truncated.** `.text` here holds more than four million
instructions, so the default cap was hit on the first real search. Raised to twenty million,
server and bridge together.

**Bridge output formatting.** Twenty-four tools returned a list rather than a joined string,
so the new `# program:` line could render glued to the first line of content. All tools now
return one newline-joined string.

## Still unverified

`import_file`, `start_analysis`, `match_functions` and `generate_patch_script` have not been
run — they need a second program open, which the session did not get to.

---

# Round 3.2 — three more from the second live run

3.1 fixed the two wrong slot numbers: `resolve_virtual_call` now reports slot `0x280`,
index 80, and names the `this-0x60` base sub-object; `find_vtables_containing` reports
base `0x141311950` index 80, and a second table at `0x14155EC78` index 81. Both bases were
confirmed by reading the preceding bytes, which are not code pointers in either case — the
two tables genuinely hold the function at different indexes, which is a class-layout
difference rather than an error. `suggest_names_from_strings` now reports
`0x140035300`'s competing candidates instead of silently proposing both, and
`auto_create_struct` explains itself and lists the function's variables.

**`trace_value` was still picking the wrong operation.** 3.1 changed "first p-code op with
an output" to "last", which was also wrong: position in the list is not dataflow order. On
`DIVSS XMM6,[RAX + 0x6d8]` the last was a `CAST` of the operand *address*, so the trace
still described address arithmetic. It now selects the operation whose output nothing else
at that address consumes — the one whose value escapes the instruction — which is the
result by construction, and falls back to the last op only if every candidate is consumed.

**`parse_c_header` filed its types under a random category.** The parser names the category
after the file it read, and the file was `createTempFile("ghidramcp_", ".h")`, so a parse
landed in `/ghidramcp_1426894785594633918.h`. Every call produced a different category.
Now written as `ghidramcp.h` inside a throwaway directory, so the category is stable.

**`get_call_sites` printed `UNNAMED` for un-named locals.** That is Ghidra's placeholder,
not information. Those arguments are now described by storage — the register name, or
`stack[-0x80]` — so an argument you cannot name is at least located.

Confirmed working in the same run: `parse_c_header` created `FVector`, `ENetMode` and a
padded `UNNAMED`-free struct, and `undo` removed all four types in one step;
`find_string_xrefs "NetServerMaxTickRate"` found the client's registrar at
`FUN_1409DE6A0 @ 0x1409DEC45`; `get_call_sites` on the FName constructor enumerated 3,578
call sites and resolved string literals such as `"PIXELSHADER"` at each one.

---

# Round 3.3 — the deadlock

`import_file` hung, and then every other endpoint stopped answering too. The cause was
visible in one screenshot: opening a freshly imported program makes it current, Ghidra asks
"sample.exe has not been analyzed. Would you like to analyze it now?", and after
Yes it raises the Analysis Options dialog. Both are modal.

`import_file` finished by calling `openProgram` through `SwingUtilities.invokeAndWait`.
The UI thread was waiting on the user, the HTTP worker was waiting on the UI thread, and
retries consumed the rest of the four-thread pool — which is why `list_open_programs`, an
endpoint that never touches the UI thread, also stopped responding. The import itself had
already succeeded; only the open step was stuck.

Three changes, because there were three separate mistakes.

**Nothing waits on the UI thread indefinitely any more.** All thirteen `invokeAndWait`
call sites now go through a bounded wait that gives up after 40 seconds and returns
`Ghidra's UI thread did not respond within 40s. A modal dialog waiting for input in the
Ghidra window is the usual cause`. Deliberately under the ~60s an MCP client allows, so
the failure surfaces as a message rather than a client-side timeout. The pool also went
from four threads to eight, so one stuck operation has less leverage.

**`import_file` is asynchronous.** It validates the path, starts a background thread and
returns at once. A 20 MB binary takes longer to load and save than any MCP client will
wait, so a synchronous import was unusable regardless of the deadlock. Progress is
reported through `analysis_status`, which now has an imports section.

**Imported programs open hidden.** `openProgram(df, -1, OPEN_HIDDEN)` opens the program
without making it current, and it is *activation* that triggers the prompt chain. So an
unattended import raises no dialogs at all. Use `select_program` when you actually want to
look at it. `start_analysis` was never affected — it drives `AutoAnalysisManager` through
the tool's background-command queue, which is why it raises neither dialog.

## Verified in the same run

`generate_patch_script` was exercised end to end against the real binary. Given the
writeup's two edits it verified both against the program, resolved `0x140463F4F -> file
0x46334F` and `0x1404438D8 -> file 0x442CD8`, captured twelve context bytes either side,
and embedded the import-time SHA-256. The context bytes were then compared against the
file on disk and matched exactly, including the `C7 83 00 07 00 00 00 00 F0 42` that
follows the second edit — the `MOV [RBX+0x700], 120.0f` the patch skips.

The emitted script was then run against three real files:

| Target | Result |
|---|---|
| pristine `CMW.exe.bak` | `All 2 site(s) match the expected original bytes` — exit 0 |
| live, half-patched `CMW.exe` | refuses on SHA-256, prints both hashes — exit 2 |
| same file with `--force` | window check still catches it, naming the one differing byte — exit 3 |

That third case is the one worth having: `--force` skips the whole-file hash but not the
local byte windows, so a partially patched build is still refused, with the specific edit
identified.

`trace_value` now reconstructs the whole netspeed chain from one call — `FLOAT_DIV` ←
`INT2FLOAT` ← load of `[+0x70]` ← load of `[+0x80]`, divided by `[GetWorldInfo() + 0x6d8]`
— which is the dataflow section 3 of the writeup derived by hand.

## Known rough edge

`get_call_sites` describes a stack pointer computed by `PTRSUB` as `<ptrsub result>`.
Accurate but not helpful; it should render as `stack[-0x80]`. Left for the next build
rather than spending an install cycle on cosmetics.

---

# Round 3.4 — the missing verb

Asked whether the test import should be deleted first, and the answer surfaced a real gap:
`CDW.exe` was already in the project the whole time. There was no way to open it.

`import_file` brings a binary in from disk. `select_program` switches between programs
already open. Nothing opened a program that exists in the project but is closed — which is
the state of every binary analysed in an earlier session, and precisely what
`match_functions` needs on both sides. The feature was unreachable through the API for a
reason that had nothing to do with the feature.

- **`list_project_files`** — every program in the project, open or not, with an OPEN marker
  and the analysed flag. `list_open_programs` says what is loaded; this says what exists.
- **`open_program`** — open one by project path, or by a unique name. Hidden by default,
  since activation is what raises the modal prompt chain; `make_current=true` when you
  want it as the default target.
- **`close_program`** — put back what you opened. Refuses a program with unsaved changes
  unless `save=true`, rather than silently discarding work.

76 contexts, 76 tools, parity checked.

## Round 3.4 verified on two live binaries

`open_program /CDW.exe` opened it hidden — 105,182 functions, no dialogs, no deadlock.
`list_project_files` showed all four project programs with only CMW marked OPEN.

`match_functions CMW.exe -> CDW.exe` compared 25,850 distinct shapes against 26,308 and
returned three confident matches, skipping 2,615 ambiguous shapes rather than guessing:

| name | CMW | CDW | size |
|---|---|---|---|
| `UGameEngine_GetMaxTickRate` | `0x140463F20` | `0x1404632B0` | 106 instrs |
| `UEngine_Exec` | `0x140478100` | `0x140477B10` | 2916 instrs |
| `UEngine_GetMaxTickRate` | `0x14042B920` | `0x14042B6A0` | 58 instrs |

Each was then confirmed by a route that has nothing to do with the hash:

- The 120-clamp signature `B8 78 00 00 00 3B C8 0F 4C C1` occurs exactly once in CDW, at
  `0x14046340D` — **`+0x15D`** into the proposed function, the same offset it sits at in CMW.
- 90.0f in CDW's `.rdata` has one referenced instance out of seven, at `0x141207C58` with
  five referrers, one of them `0x1404633E9` — **`+0x139`** into the proposed function, again
  the same offset as in CMW, and the same referrer count.
- `"UNCAPFPS"` in CDW is referenced once, from `0x140478DE2` — **`+0x12D2`** into the
  proposed `UEngine_Exec`, identical to its offset in CMW.

Three independent methods, three identical intra-function offsets. The matches are real,
and the premise the endpoint was built on — that analysis survives a rebuild — held on two
binaries that were never analysed together.

The fourth name in CMW, `EngineConfigValidate_ClampRates`, did not carry: its shape is
either ambiguous or changed between builds. Skipping it is the designed behaviour.

---

# Round 3.5 — the systematic pass

Ran the endpoints that had never been exercised. Six more defects, one of them serious.

## Confirmed working

`get_vtable`, `call_graph`, `get_callers`, `get_callees`, `get_xrefs_from`, `list_segments`,
`get_current_function` (correctly 404s when the cursor is not in a function), `list_symbols`,
`get_type_info`, `search_decompiled`, `select_program`, `close_program`, `redo`,
`set_function_prototype`, `create_struct`, `apply_data_type`, `batch_rename`, `set_equate`,
and the `start_line` / `max_lines` windowing (`# lines 1-12 of 411; continue with start_line=13`).

A ten-transaction `undo` reversed the entire write sweep exactly, including the two
`Auto Analysis` transactions Ghidra queued of its own accord, and `list_annotations`
confirmed the program was back to its original four names with no leftover types.

**`import_file`'s async path works.** The rewrite returns immediately, raises no dialog,
opens hidden and reports through `analysis_status`. The deadlock is gone.

**The provenance header earned its place.** After `select_program CDW.exe`, a
`get_function_context` on a CMW address returned `FUN_140463AB0` — a real function at that
address in the *other* binary. Entirely correct behaviour, and precisely the mistake the
header exists to make visible: the response said `# program: CDW.exe`, so the wrong answer
announced itself instead of being plausible.

**`auto_create_struct` finally did its job.** Pointed at `lVar1` it inferred `+0x80` (2
loads), `+0xbc` and `+0xc0` — `ServerConnection`, `NetServerMaxTickRate` and
`bClampListenServerTickRate`, matching the writeup's field table, derived from access
patterns alone. On `lVar3` it added `+0x6d8` tagged *used in float math* — the divisor.

## Defects fixed

**`start_analysis` never analysed anything.** It reported success, finished instantly and
left an empty undo stack on a program it claimed to have analysed. Switching to the tool's
background-command queue in round 3, I dropped the `reAnalyzeAll(null)` call that *schedules*
the analyzers, so the command ran against an empty queue. A silent no-op reporting success
is the worst failure mode in the whole set, and it survived three rounds because nothing
checked whether the work actually happened.

**`auto_create_struct` silently dropped its first field.** An empty `StructureDataType`
reports `getLength() == 1`, so growing it incrementally left the first field one byte short
and it was discarded with a note. That field is usually the vtable pointer or the most
significant one. The structure is now sized up front from the collected offsets.

**`apply=false` was not a dry run.** It skipped retyping the variable but still wrote the
type into the program, contradicting a docstring that promised no modification. It now
returns the layout and writes nothing.

**Equates were listed as variables.** `LocalSymbolMap` includes equate symbols, so
`NETSPEED_UNCAPPED_THRESHOLD` appeared three times in the "retry with variable=" list. Only
symbols with a p-code variable are listed now, deduplicated.

**Windows line endings leaked into tables.** Ten `String.format` calls used `%n`, which is
`\r\n` on Windows, putting a stray carriage return at the end of header and evidence rows.
Now `\n` explicitly.

**`get_call_sites` still said `<ptrsub result>`.** Stack pointers computed by `PTRSUB` now
render as `&RSP+0x80`.

## Coverage after this pass

Roughly 40 of 76 endpoints exercised against real binaries. Still untested: `save_program`
(deliberately - it writes to the project), `create_function`, `rename_variable`,
`rename_data`, `set_local_variable_type`, `list_data_items`, `list_namespaces`,
`list_methods`, `list_classes`, `list_exports`, `disassemble_function`, and
`suggest_names_from_strings` with `apply=true`.

## Round 3.5 verified

- **`start_analysis` now analyses.** `list_undo_stack` shows an `Auto Analysis` transaction
  and the function count on `sample.exe` went 111 → **212**. The missing
  transaction was the signal that exposed the no-op, so its presence is the proof.
- **The dropped first field is back.** `get_type_info` on an auto-created struct lists
  `0x80` alongside `0xBC` and `0xC0`; previously `0x80` was discarded with a placement
  error while the later fields survived.
- **`apply=false` writes nothing.** Returns the evidence table and
  `# Not created: apply=false is a dry run`, with no type added.
- **No carriage returns** left in table output.
- **`close_program` guard works**: refused while `sample.exe` had unsaved analysis,
  closed cleanly once the analysis was undone.
- `undo` targets each program independently — reversing the struct on CMW and the analysis
  on sample.exe were separate, correctly-scoped operations.

Note for the next build: the running bridge was still the 3.4 Python, since 3.5's only
bridge changes were docstrings and every fix lives in the plugin. Behaviour was unaffected,
but a restart that reloads the extension does not necessarily reload the bridge process.

### The Auto Analysis Summary dialog

It appears after every `start_analysis` on a real binary, and it is worth knowing exactly
what it does and does not do.

`AutoAnalysisPlugin.analysisEnded` is unconditional: if the analysis message log has any
content it writes the log and shows a `MultiLineMessageDialog` titled "Auto Analysis
Summary". For a stripped game binary the log always has content — "PDB Universal> Warning:
Could not find an appropriate PDB file", "MinGW pseudo-relocation list not found" — so the
dialog always appears. There is no tool option to suppress it.

It is **not** modal. The constructor's fifth argument is the modality flag and the plugin
passes `false`; `MultiLineMessageDialog` has separate `showModalMessageDialog` and
`showMessageDialog` helpers, and this path uses the non-modal one. So it does not block
the UI thread and would not have caused a timeout — unlike the "Analyze?" prompt and the
Analysis Options dialog, both of which are modal and both of which the round-3.3/3.4
changes route around by opening imported programs hidden.

Empirically consistent with the run: `undo` and `close_program`, which both need the UI
thread, worked while it was on screen.

---

# Round 3.6 — version identification, and RTTI

79 contexts, 79 tools.

## Knowing what is running

Five times in this session the running build had to be inferred by grepping tool
descriptions or hashing files on disk, and once — `start_analysis` — a stale component
behaved exactly like a working one. That is a category of confusion worth retiring rather
than navigating.

- **`version`** — reports the plugin build, the bridge build, the endpoint count, the
  Ghidra version and the current program, and says **MISMATCH** explicitly when the two
  halves disagree. The bridge sends its own build string with the request, so one call
  covers both processes.

Both halves are stamped `3.6`. If they ever disagree, the response says which.

## RTTI

- **`find_rtti`** — recovers C++ class names from MSVC RTTI and pairs each with its vtable.
  Scans for Complete Object Locators, validated by the self-referencing RVA at `+0x14`
  which x64 COLs carry, resolves the type descriptor name, demangles it, then locates the
  vtable as the address immediately following a pointer to the COL. Two linear passes over
  the data blocks, no per-class searching.

  Naming a vtable is worth more than naming a function: it labels every slot at once. With
  `find_vtables_containing` this turns "an interesting function" into "virtual method N of
  a named class". `apply=true` labels each table `<Class>::vftable`, leaving existing
  user-defined labels alone.

- **`demangle`** — RTTI type-descriptor names handled directly, everything else through
  Ghidra's demangler.

Deliberate limits: slot counts stop at the first entry that is not a code pointer, so they
are a lower bound; template classes are reported in their mangled form rather than guessed
at; and a class with no vftable found is reported as such rather than omitted.

## Verified

Unit tests against the shipped bytecode: RTTI name demangling across class, struct,
single- and multi-level namespace forms, `type_info` itself, and a template left
recognisably mangled; plus the little-endian int and pointer readers the COL scan depends
on. The round-2 encoder suite, the round-3 suite and the patch-script end-to-end test all
still pass.

`find_rtti` has **not** been run against a binary yet — that is the first thing to do after
installing, and `find_rtti(filter="NetDriver")` on CMW is the check with a known answer.

## Round 3.6 verified, and what RTTI actually found

`version` reports `plugin_build: 3.6 / bridge_build: 3.6 / endpoints: 79 / ghidra: 12.1.2`.
Both halves agree, and there is no longer any need to infer a build from docstrings.

**`find_rtti` works, and its answer about this binary is a useful negative.** It recovered
52 classes with correct names and namespaces — `OC3Ent::Face::FxAnimCurve`,
`OC3Ent::Face::FxArchiveStoreMemoryNoCopy`, `CSourceStream`, `type_info`. Confirmed
independently: Ghidra's own RTTI analyzer had already labelled `CSource::vftable` at
`0x141568888`, and the scan lands on exactly that address without consulting it. A `.?AV`
byte search finds 60 type-descriptor names against 52 recovered classes, the difference
being descriptors used only for exception handling, which have no object locator.

But there is no `UObject`, no `UNetDriver`, nothing from the engine at all. The 52 are
entirely third-party static libraries: DirectShow base classes and FaceFX. **UE3 is built
with RTTI disabled**, so for Chivalry this is a dead end — worth knowing definitively
rather than suspecting. The structural source in this binary is UE3's own reflection: the
property registrar at `FUN_1409DE6A0`, reachable through `get_call_sites`.

One detail worth noting: `CSource` appears three times with `vtable_offset` `0x0`, `0x18`
and `0x20` — the sub-object vtables of a multiply-inherited class, correctly distinguished.
That is the same structure `resolve_virtual_call` reported as `this-0x60` earlier.

# Round 3.7 — searching for what you can see

`list_symbols` displayed namespace-qualified names but filtered on short ones, so the
`CSource::vftable` sitting in its own output matched nothing when searched for. It now
matches against the qualified name. Both builds stamped 3.7.

Nothing depends on this; install it whenever the next reason to reinstall comes along.

---

# Round 3.8 — the rest of the sweep

Ran every remaining endpoint. Five more defects, none dangerous, all of the same family:
the tool did something other than what it said.

## Confirmed working

`list_methods`, `list_functions`, `search_functions_by_name`, `list_strings`,
`list_data_items`, `list_exports`, `list_namespaces`, `get_current_address`,
`get_function_by_address`, `get_function_xrefs` (now with `+0x182`-style offsets),
`disassemble_function`, `rename_function_by_address`, `rename_variable`, `rename_data`,
`create_function`, and `suggest_names_from_strings` with `apply=true`, which renamed three
`UProperty::` functions and reversed cleanly.

`disassemble_function` on `UEngine_GetMaxTickRate` prints the whole smoothing path the
writeup describes: `TEST dword ptr [RCX + 0x3f8],0x100`, the `DIVSS` of `1.0f` by the
smoothed delta, and the clamp between `[RBX + 0x700]` and `[RBX + 0x704]`.

`create_function` does disassemble undefined bytes — proven on unanalysed
`sample.exe`, where it defined a function at `0x140001198` in a region
`disassemble_range` reported as having no instructions.

## Defects fixed

**`list_classes` was `list_namespaces` under another name.** Both collected every
non-global parent namespace, so both returned `.PEAX`, `ADVAPI32.DLL` and
`APEXFRAMEWORK_X64.DLL` — import namespaces and demangler artefacts, not classes. It now
returns only `GhidraClass` namespaces, and says so plainly when there are none rather than
returning a list of the wrong thing.

**`rename_data` always answered "Rename data attempted".** It worked — the label was
there when checked — but the endpoint never said whether it had. It now reports the old and
new names, and says explicitly when the address holds no defined data instead of silently
doing nothing.

**`set_local_variable_type` failed without a reason.** Retyping an 8-byte `longlong` to
`int` returned "Failed to set variable type" and nothing else; `void *` on the same
variable succeeded. The cause is a storage size mismatch, which the exception knew about
and threw away. The message now carries the exception and both sizes.

**`create_function` blamed the wrong thing.** On an address inside an existing function it
said "are the bytes disassembled?", which sends you to check the one thing that was fine.
It now reports the containing function and its entry point.

**A failed `create_function` still left an undo entry.** The command returning false is not
an exception, so the transaction committed anyway and "GhidraMCP create function" appeared
on the undo stack of a program where nothing had been created. Failed commands now roll
back. An undo stack is only useful as a log of what changed if everything on it changed
something.

## Coverage

78 of 79 endpoints have now been run against a real binary. `save_program` is the
exception - deliberately skipped, since it writes to the user's project - and an earlier
version of this line claimed all 79, which was wrong. 25 defects found and fixed across
the session, 20 of them by running the code rather than reading it.

## Round 3.8 verified, and one fix that had not been applied

`version` reports `3.8 / 3.8`. Confirmed on the binary:

- **`list_classes`** returns 99 real classes — `CBaseFilter`, `CBaseOutputPin`, `CAMThread`,
  `CEnumMediaTypes` — with the import namespaces gone. More than `find_rtti`'s 52, because
  Ghidra also creates class namespaces from demangled symbols. Two demangler artefacts
  (`.PEAX`, `.PEA_W`) remain, since Ghidra does register them as classes.
- **`create_function`** on an address inside a function now says
  `140463f30 is already inside UGameEngine_GetMaxTickRate (entry 140463f20)` instead of
  blaming disassembly, and returns 400.
- **The failed attempt left the undo stack empty** and the program still marked saved. The
  phantom transaction is gone.

**`set_local_variable_type` still gave no reason, because that fix never made it into 3.8.**
The patch matched on `"Result: Failed to set variable type"`, but the string in the source
is assembled from a ternary and a separate `append`, so the replacement found nothing — and
that particular edit was the one where I had not asserted the match count. It reported
success and changed nothing.

That is precisely the defect class this session has been about, committed by the tooling
used to fix it. Now applied against the real anchor and verified present in the built jar:
a failed retype appends `Reason: <exception> (the variable is currently longlong, 8 bytes;
INT is 4. A differently-sized type usually cannot replace a register variable in place.)`

## A correction on how to tell builds apart

Tool descriptions returned by the client are cached and can lag the running bridge. At one
point `version` reported `3.8 / 3.8` while the descriptions still showed 3.7 text, and the
file on disk had the 3.8 text — the descriptions were stale, not the bridge. Earlier in the
session the opposite inference happened to be right, but only because a *parameter default*
had changed too, which is structural rather than documentation.

So: `version` is authoritative. Descriptions are not evidence about the running build.

---

# Round 4.0 — read from the source rather than inferred

With the Ghidra source available, two things that had been guessed became known.

## RTTI inheritance chains

`RTTI3DataType` and `RTTI1DataType` document the layout exactly:

```
ClassHierarchyDescriptor  +0x00 signature  +0x04 attributes
                          +0x08 numBaseClasses  +0x0c pBaseClassArray (RVA)
BaseClassArray            numBaseClasses x 4-byte RVA -> BaseClassDescriptor
BaseClassDescriptor       +0x00 pTypeDescriptor (RVA)  +0x04 numContainedBases
                          +0x08 pmd { mdisp, pdisp, vdisp }  +0x14 attributes
```

`find_rtti` previously read only `numBaseClasses` and reported it as a number. It can now
walk the array: **`with_bases=true`** adds the inheritance chain per class, each base with
its `mdisp` offset within the object. Entry zero of the array is the class itself and is
skipped. Off by default, since it costs a line and several reads per class.

`bases: 11` becomes an actual hierarchy, which is what makes a vtable label worth having.

## Why a variable will not retype

`HighFunctionDBUtil.updateDBVariable` refuses a resize in exactly one case:

```java
if (resized) {
    if (usesHashStorage) {
        throw new InvalidInputException("Variable size (" + highSymbol.getSize() +
            ") may not be changed: type '" + dataType.getName() + "' length is " + ...);
    }
    storage = VariableUtilities.resizeStorage(storage, dataType, true, function);
}
```

So resizing is only rejected for **hash storage** — variables the decompiler synthesised
with no fixed register or stack location. Register and stack variables resize fine.

3.9 guessed "a differently-sized type usually cannot replace a register variable in place",
which is wrong in both directions: register variables *can* be resized, and the real
constraint is a storage class 3.9 never mentioned. The message now says which case you are
in and carries Ghidra's own exception text. There is no fix to make hash-storage resizing
work — it is a genuine constraint — but "explain accurately" beats "explain plausibly".

## A note on the source

The source consulted was Ghidra's **12.2 development** branch; the plugin runs against
**12.1.2**. Both facts above are layout and control flow that have been stable for years,
and the RTTI offsets are checkable against the binary itself, which is how they were verified. Anything more version-sensitive
should be confirmed against the 12.1.2 jars rather than trusted from this source.

## Round 4.0 verified against published headers

`version` reports `4.0 / 4.0`. `find_rtti(filter="CSource", with_bases=true)` recovers:

```
CSource        bases: CBaseFilter <- CUnknown <- INonDelegatingUnknown <- CBaseObject+0x8
                      <- IBaseFilter+0x18 <- IMediaFilter+0x18 <- IPersist+0x18
                      <- IUnknown+0x18 <- IAMovieSetup+0x20 <- IUnknown+0x20
CSourceStream  bases: CAMThread <- CBaseOutputPin+0x78 <- CBasePin+0x78 <- CUnknown+0x78
                      <- INonDelegatingUnknown+0x78 <- CBaseObject+0x80 <- IPin+0x90
                      <- IUnknown+0x90 <- IQualityControl+0x98 <- IUnknown+0x98
```

Against the DirectShow base classes as published: `CSource : CBaseFilter`;
`CBaseFilter : CUnknown, IBaseFilter, IAMovieSetup`; `CUnknown : INonDelegatingUnknown`
with `CBaseObject`; `IBaseFilter : IMediaFilter : IPersist : IUnknown`;
`IAMovieSetup : IUnknown`; `CSourceStream : CAMThread, CBaseOutputPin`;
`CBaseOutputPin : CBasePin`; `CBasePin : CUnknown, IPin, IQualityControl`. Every edge
matches, in order.

The offsets match too, and they cross-check *within* the output. The `vtable_offset` column
for the three `CSource` tables reads `0x0`, `0x18`, `0x20`; the base list independently puts
`IBaseFilter` at `+0x18` and `IAMovieSetup` at `+0x20`. Those two numbers come from
different structures — the Complete Object Locator's own offset field, and each Base Class
Descriptor's `pmd.mdisp` — and they agree. Same for `CSourceStream`'s four tables at `0x0`,
`0x78`, `0x90`, `0x98` against `CAMThread` at 0, `CBaseOutputPin` at `+0x78`, `IPin` at
`+0x90`, `IQualityControl` at `+0x98`.

Multiple inheritance layout is not something a plausible-looking bug reproduces by accident.

`set_local_variable_type` now returns Ghidra's own reason:

```
Reason: InvalidInputException: Variable size (8) may not be changed: type 'INT' length is 4
        (currently longlong, 8 bytes; INT is 4. Ghidra only refuses a resize for variables
        in hash storage ...)
```

---

# Round 4.1 — the full pipeline, and what it caught

Run in a fresh project containing only `CMW.exe`, so the whole chain could be driven from
nothing: import a second binary, analyse it, verify it, save it.

## The pipeline

- **`save_program`** — the one endpoint never previously run, and the fresh project made it
  checkable rather than merely runnable. Before: `analyzed: ?`, `changed: unsaved`. After:
  `analyzed: true`, `changed: saved`. A second call correctly answered
  `CMW.exe has no unsaved changes`. That takes coverage to 79 of 79.
- **`import_file`** on the 20 MB `CDW.exe` dedicated-server binary returned immediately,
  raised no dialog, and reported `done` through `analysis_status` with 38,527 functions
  from the loader alone.
- **`start_analysis`** took it 38,527 → 75,810 → 76,313 functions over several minutes,
  with `analyzing: YES` throughout — the rising count between polls being exactly the
  signal the endpoint exists to give.
- The **Auto Analysis Summary** dialog appeared on completion and, as the bytecode said,
  did not block anything: `analysis_status` answered normally while it sat on screen.

## Verified against known answers

`sha256` came back as `31e6b1c3b7c419ea92d16a6b7416db8f258377cb1dba491cbef9e0e2878bf128`,
matching the hash taken off disk earlier — so Ghidra imported the intended file.

On a binary analysed entirely by this tooling, from scratch:

- The 120-clamp signature `B8 78 00 00 00 3B C8 0F 4C C1` occurs **exactly once**, at
  `0x140408C8D` = `FUN_140408B30+0x15D`. That `+0x15D` is identical to the same site in
  `CMW.exe` and in the previously analysed client `CDW.exe`.
- 90.0f in `.rdata` has **one referenced instance** out of four, with **five referrers**,
  one of them `0x140408C69` = `FUN_140408B30+0x139` — again identical to both other
  binaries, and the same referrer count.
- `"UNCAPFPS"` appears once with one reference.
- `file_offset` round-trips: `0x140408C8D -> file 0x40808D -> 0x140408C8D`, and
  `0x140408C8D - 0x140000000 - 0xC00 = 0x40808D` by hand.

Three separate binaries, three different `Exec` layouts, and the same two intra-function
offsets in `GetMaxTickRate` every time. Consistent with the writeup's claim that client and
server were built from the same engine source.

## Defect fixed

**`start_analysis` never marked the program as analysed.** `list_project_files` reported
`analyzed: false` for `CDW.exe` immediately after a completed analysis and an explicit save.
`AnalysisBackgroundCommand` only runs the analyzers; the "has been analyzed" property is set
separately, by `GhidraProgramUtilities.markProgramAnalyzed`, which nothing was calling.

The consequence is not cosmetic: `shouldAskToAnalyze` reads that property, so Ghidra would
raise its modal *"has not been analyzed. Would you like to analyze it now?"* prompt the next
time the program was activated — the precise dialog that round 3.4's hidden-open exists to
avoid, reintroduced one step later in the same workflow.

Now set when analysis completes, and `analysis_status` reports the flag in a new `analyzed`
column so the discrepancy is visible rather than inferred.

This was only findable by running the whole chain in a clean project and then looking at the
project's own record of what happened, rather than at the endpoint's return value. Every
individual call had reported success.

## Round 4.1 verified

`version` reports `4.1 / 4.1`, and `analysis_status` carries the new `analyzed` column.

Re-opening `CDW.exe` showed the discrepancy the column exists for: **76,313 functions and
`analyzed: NO`** — fully analysed under 4.0, with Ghidra's own flag still saying otherwise.
Nothing in the previous output could have shown that.

Re-running `start_analysis` under 4.1: `analyzing: YES` with the count creeping 76,313 →
76,333 → 76,400, then `analyzing: no / analyzed: yes / finished: 76400 functions`. The flag
flipped exactly when analysis completed.

One detail worth recording: immediately after that, `list_project_files` still reported
`analyzed: false`. The flag is a program property, so it lives in memory until the program
is written back — `save_program` then flipped the project record to `true`. The two views
disagree between analysis finishing and the save, and that is correct rather than a bug:
`analysis_status` reads the live program, `list_project_files` reads what is on disk.

---

# Round 4.2 / 4.3 — ideas from REA, and a review pass

Prompted by comparing against REA (github.com/morluto/rea), an agent-facing RE toolkit. REA
itself does not fit this work: on Windows it is an experimental, read-only, Ghidra-12.1.4-only
mode that re-imports and re-analyses the binary every session. One idea was worth taking:
following a value across function boundaries, with an explicit list of what was *not*
followed. The rest of this round came from re-reading the plugin source.

86 endpoints / 86 tools (was 79).

## New

**`trace_value` crosses calls.** New `direction` (`backward`/`forward`), `cross` (call levels,
default 1, max 4) and `max_functions` (decompile budget, default 8). Backward: a call result
continues inside the callee's returns; a parameter continues at its callers' call sites.
Forward: an argument continues inside the callee, and its `return` resumes at the call site
it came through. Every trace ends with `# not followed:`: indirect calls, externals, memory
writes, call sites past the cap, budget exhaustion. Offsets show inline (`[0x700]`).

When the callee's parameter is not in Ghidra's stored signature — normal for `FUN_`
functions — the caller's decompiled call has no argument for it. The trace then walks the
caller's disassembly back from the call to the instruction that sets the register, stepping
over `__chkstk`, and stops with a reason at a join point or an intervening call.

**`inspect_instruction`** — bytes, length, file offset, operands split into
registers/scalars/addresses, flow type, targets, references; says when an address is
mid-instruction, data, or undisassembled. On x86, same-length patch bytes: never jump, always
jump, inverted condition, NOP'd call.

**`get_basic_blocks`** — a function's control-flow graph: block ranges, last instruction,
successors (fall/cond/jump), predecessor count, the block containing a given address marked,
and a warning if the blocks do not tile the body.

**`goto_address`, `set_bookmark`, `list_bookmarks`, `remove_bookmark`** — findings land in
the user's own Ghidra window. Bookmarks use category "Claude" and persist with the program.

**`selftest`** — invariants against the open program, generic enough for any binary, so a
broken build shows up as FAIL rather than as a plausible wrong answer later.

## Defects fixed in existing code

**28. A plugin exception looked like Ghidra being down.** An uncaught exception closed the
connection without a response, and the bridge reported *"Cannot reach Ghidra — is it
running?"*, sending debugging the wrong way. Every endpoint now returns the exception and its
location as a 500. The 400 path through the same wrapper is verified live; the 500 path is
compile-checked only, since no endpoint could be made to throw on demand.

**29. Name-based writes hit the first match.** `rename_function`, `rename_variable` and every
endpoint taking a function `name` silently used the first function with that name.
`decompile_function` had already been fixed to refuse; the others had not. All now refuse
an ambiguous name and list the candidates. `Namespace::name` disambiguates. Lookup goes
through the symbol table rather than a scan of every function.

**30. Type lookup could return the wrong-case type.** A case-insensitive match returned as
soon as it was seen, so `bool` could resolve to `BOOL` (1 byte versus 4) depending on
iteration order. CMW has exactly that pair, with `BOOL` iterated first — under 4.1,
retyping something to `bool` would have applied `BOOL`. Exact matches now win.

**31. `find_rtti` skipped any data block over 64 MB without saying so.** Now read in 16 MB
chunks with overlap; unreadable blocks are named in a warning.

## Defects in the 4.2 additions, found by running them

**Thunks were invisible to the new name lookup.** A thunk like `memset` shows its target's
name but has no symbol of that name, so the symbol-table lookup missed it. Shown by
renaming a function to `memset`: 4.2 did not see the clash, and `rename_function memset`
renamed the wrong one on a false premise. 4.1's slow scan never had this problem — the
speed-up introduced it. Undone; `selftest` now checks thunk lookup.

**Forward trace returned to every caller** rather than the one it came through, and listed
the call's return value as a use of the argument. Fixed with an explicit return site.

**`INDIRECT` noise.** Ghidra's "a call might change this" markers tripled trace length. Now
followed silently and noted once under `not followed`.

## Verified (4.3, CMW.exe)

- `version` reported `4.3 / 4.2` with MISMATCH after the plugin was reinstalled and the
  bridge not yet restarted; `selftest` failed exactly its build check, and passed all 52 others.
- Known anchors unchanged: `file_offset 0x140463f4f` → `0x46334f`; `UNCAPFPS` one ref from
  `UEngine_Exec`; virtual call slot `0x280`/80 via `this-0x60`; `CSource` RTTI chain; 52
  RTTI classes, the same count as before the chunked read.
- `inspect_instruction 0x140463f4f` gave always-jump `90 e9 43 01 00 00` and
  `0x1404438D8` gave `eb 0a` — the two edits of the shipped FPS patch, independently.
- `get_basic_blocks` on `GetMaxTickRate`: 35 blocks, 429 of 429 bytes, `MOV EAX,0x78` at
  `+0x15D` as recorded.
- Backward trace of the `Super::GetMaxTickRate` result: inside the callee, 0,
  `1/SmoothedDelta`, `this+0x700`, `this+0x704` — the `Clamp(…, Min, Max)` shape in the writeup.
- Forward trace of `this`: into `UEngine_GetMaxTickRate` at `[0x3f8] & 0x100`
  (`bSmoothFrameRate`), `[0x700]`, `[0x704]`.
- Backward trace of `EngineConfigValidate_ClampRates`'s parameter: caller `FUN_140471cb0`
  (the writeup's single caller) passes its own parameter 0, read from disassembly past
  `__chkstk`. `FUN_140471cb0` itself has no direct callers, correctly reported.
- Duplicate `memset` created on purpose: `rename_function`, `get_basic_blocks` and
  `decompile_function` all refused with both candidates; `MSVCR100.DLL::memset` resolved
  uniquely; nothing was renamed; the test rename was undone.
- Bookmarks set, replaced (old text reported), removed, listed; a remove with nothing to
  remove left no undo entry; saved.

## Still unverified

- The generic 500 exception path (see 28).
- `find_rtti` across a chunk boundary specifically — CMW has no data block over 16 MB, so
  the chunking ran as one piece per block. Equal class counts show nothing regressed, not
  that the boundary case works.

---

# Round 4.4 / 4.5 — closing the RTTI boundary question

4.3 left `find_rtti`'s chunked reading unverified: CMW has no data block over 16 MB. Mirage's
`TBLServer.exe` has a 21.3 MB `.rdata`, so it was the test.

**The plain run proved less than it seemed.** `find_rtti` found 536 classes; an independent
Python scan of the raw file (same SHA-256 as the Ghidra program, each section read whole, no
chunking) found the same 536 COLs with the same first and last addresses. But all of them lie
in the first 16 MB piece — they end at `0x145f75248`, the boundary is `0x146026000`. Nothing
was on the far side to lose.

**4.4: a piece size small enough to matter.** `find_rtti` takes `chunk_kb` (testing only, min
4). At 4 KB, about 20 piece boundaries fall inside TBLServer's COL range, and two COLs straddle
one: `0x145f6cff0` (`icu_53::PluralFormat`) and `0x145f6fff8` (`IlmThread::ThreadPool`).
`selftest` now compares full `find_rtti` output at 16 MB and 4 KB pieces, on any binary.

**The check can fail.** The same piece-by-piece scan, simulated on the raw file: with the
32-byte overlap, 536 found; without it, 534 — exactly those two missing.

**4.5: `selftest` skipped a check without saying so.** On TBLServer (546k functions) the
per-function samples used the whole 45 s budget, and the RTTI comparison, which ran after them
behind the same deadline, simply did not appear in the output. Whole-program checks now run
first and are not subject to the sample budget; skipped samples are reported as `SKIP` with a
count.

## Verified

- 4.4 on TBLServer: `version` 4.4 / 4.4. `selftest samples=1`: 14 passed, 0 failed, including
  `find_rtti identical at 16 MB and 4 KB pieces (536 RTTI class(es) found)`. Default
  `selftest`: 46 passed, but the RTTI check absent — the defect fixed in 4.5.
- 4.5 on TBLServer: `version` 4.5 / 4.5. Default `selftest`: 55 passed, 0 failed; the RTTI
  comparison now runs first. All six samples fit, so the SKIP line did not appear.

## 4.6: the budget was not a budget

Asking for 20 samples to force the SKIP path instead hit the client's 60 s timeout. The 45 s
deadline only stopped *new* samples from starting; a sample begun just before it could still
run a 30 s decompile and two traces with their own fresh 40 s allowances each. Now the whole
run has one 40 s deadline that every step draws from: decompiles get the time left, traces
inherit the deadline, the full-program constant search is skipped under 10 s left, and no
sample starts with under 5 s. The plugin kept answering during the overrun, and the work
it finished in the background was read-only.

- 4.6 on TBLServer: `version` 4.6 / 4.6. `selftest samples=20` returned inside the client
  timeout: 15 passed, 0 failed, `SKIP 19 of 20 function sample(s)`, and the rollback check
  still ran after the skip. The whole-program constant search on the first sample (546k
  functions) took most of the budget, which is why only one sample fit. That is the expected
  trade-off, and it is reported rather than hidden.

---

# Round 4.7 – 4.9 — a second pass over REA and upstream GhidraMCP

Sources: REA's Ghidra bridge (58 commits since the last review) and upstream GhidraMCP's 2.0
rewrite plus its 78 open pull requests. Each finding was checked against this code before
being acted on; the live tests below ran on Mirage's TBLServer.exe (with PDB) and a fresh,
stripped CMW.exe import.

87 endpoints / 87 tools (was 86).

## Defects fixed

**32. The decompiler was never configured** (upstream PR #56). No `DecompileOptions` were ever
sent, so the native decompiler ran on bare defaults: read-only constants were not folded and
the user's Decompiler settings were ignored. TBLServer's `FPlayerState::IsDefault` printed
`__real@42b40000 == (this->ViewPoint).FOV`; it now prints `FOV == 90.0`, as Ghidra's own
window does. Options come from `DecompilerUtils.getDecompileOptions`, the call the GUI uses,
and are re-read on every request so changes apply at once.

**33. Decompile failures were indistinguishable from dropped calls.** A 60 s decompile timeout
matched the client's own 60 s limit. The timeout is now a tool option, "Decompile Timeout
Seconds" (default 45), and a timeout is reported as one with the option to raise, not as
"Decompilation failed".

**34. `set_function_prototype` overwrote the plate comment** with "Setting prototype: …" on
every call, in its own committed transaction, even when the prototype then failed to parse.
Removed.

**35. `set_function_prototype` dropped the name** in the prototype unless the function still
had a `FUN_` name (upstream 24ff903): the 3-argument `ApplyFunctionSignatureCmd` passes
`RENAME_IF_DEFAULT`. Now `RENAME`, reported as "Renamed old -> new".

**36. `rename_variable` reported success on failure**: `endTransaction` in `finally` overwrote
the failure flag and committed. It now commits only on success and returns Ghidra's reason.

**37. `set_local_variable_type` decompiled on Ghidra's UI thread**, freezing the window for up
to 60 s and able to apply after the caller had been told it failed. Decompiling now happens on
the worker; only the commit runs on the UI thread. A shared error field that concurrent
requests could overwrite is gone.

**38. A fresh bridge install crashed on import** (upstream PR #176): `requirements.txt` pinned
`mcp==1.5.0`, which fails against current pydantic. Now `mcp>=1.30,<2`.

**39. Qualified new names became literal names.** `rename_function("UObject::Foo")` produced a
global function literally named `UObject::Foo` — and `batch_rename`'s own example used that
form. Function renames now split at top-level `::` (template arguments and quoted compiler
names kept whole) and move the function into that namespace, creating it if needed.

**40. Smaller ones.** Name lookup now also finds names Ghidra keeps as extra labels on a
function's entry (identical functions folded by the linker). `get_call_sites` includes callers
that reach the function through jump thunks. `list_data_items` reads data in one pass rather
than once per memory block.

## Added

**`fix_noreturn`.** Auto-analysis sometimes marks a function no-return although it returns;
every caller is then cut short at the call. Lists functions flagged no-return whose body has a
reachable return, and with `apply=true` clears the flags, re-disassembles after each affected
call, refits the callers and repeats for callers that inherited the flag — one undo step.
Decompiles, `get_function_context` and `get_callees` warn when a function is affected.

**Tool hints.** Every tool is marked read-only, edit (undoable) or destructive (`save_program`,
`undo`, `redo`, `close_program`). Older mcp releases lack hints; the bridge then registers plain
tools rather than failing, and `version` reports the SDK version and whether hints are on.

**`inspect_instruction` shows flow overrides**, e.g. `flow_override: CALL_RETURN`.

## Defects in the new code, found by running it

**`__report_gsfailure` listed as a false no-return (4.7).** Its body ends with
`TerminateProcess(GetCurrentProcess(), 0xC0000409)` and then a dead `RET`. "Contains a return"
— REA's test too — said it returns; applying would have cleared a correct flag. 4.8: a return
only counts when no call on the straight-line path before it ends the process (TerminateProcess,
ExitProcess, abort, __fastfail …, including calls through the import table).

**The repair erased thunk overrides (4.8).** A thunk's tail `JMP`, and every MSVC `Unwind@`
funclet's, carries a `CALL_RETURN` flow override, so it looks like a call to a no-return
function. 4.8 re-disassembled `thunk_FUN_14001e5d0` and would have done the same to 13 funclets,
wiping the overrides. 4.9 repairs genuine `CALL` instructions only. The same confusion made
`inspect_instruction` offer "remove call" bytes for a thunk's `JMP`; fixed, with a unit test.

## Verified

- `version` 4.9 / 4.9, `mcp_sdk: 1.28.1 (tool hints on)`; on mcp 1.6 the bridge starts with
  hints off and all tools present; on 1.30 all 87 register (56 read, 27 edit, 4 destructive).
- `selftest` on TBLServer: all pass, including the two new checks (decompiler uses Ghidra's
  options with read-only respected; qualified-name splitting).
- `IsDefault` decompiles to `FOV == 90.0`.
- A prototype the parser rejects leaves no comment and no undo entry.
- On `FUN_1402a43c0`: `MCPTest::Probe` created the namespace; a prototype with a new name
  renamed it; a variable rename to `bad name` failed with Ghidra's reason and no undo entry;
  the valid rename and retype worked; undo restored everything.
- `get_call_sites FUN_1400393e0` on CMW: 22,274 sites, including 834 through its thunk.
- No-return, CMW: dry run clean once `__report_gsfailure` was handled. A planted flag on
  `FUN_14001e5d0` (Edit Function → No Return) made auto-analysis cut its callers short —
  `FEngineLoop::PreInit`'s second call site fell outside any function. Warnings appeared in the
  decompile and `get_function_context`. `apply=true` re-disassembled the 6 cut-short `CALL`s and
  refit 5 callers; the call site rejoined `FEngineLoop::PreInit`, the destructor at
  `1401ce790` decompiled whole again, and the thunk and `Unwind@` funclets kept `CALL_RETURN`.

## Considered and left

Upstream 2.0's headless mode, JSON output and test suite need the plugin split into separate
layers. REA's switch-table recovery, analyzer control and PDB details remain candidates.
