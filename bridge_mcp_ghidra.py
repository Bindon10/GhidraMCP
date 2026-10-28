# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.30,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

# The original 5s timeout is shorter than a single Ghidra decompile of a large
# function, so any real binary produced spurious "Request failed" results.
DEFAULT_TIMEOUT = 60
SLOW_TIMEOUT = 300

BRIDGE_BUILD = "4.9"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Hints let a client tell lookups from edits. Older mcp releases lack them; fall back to
# plain tools there rather than failing to start.
try:
    import inspect
    from mcp.types import ToolAnnotations
    _HINTS = "annotations" in inspect.signature(FastMCP.tool).parameters
except ImportError:
    _HINTS = False

if _HINTS:
    _ANNOTATIONS = {
        "read": ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        "edit": ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False),
        "destructive": ToolAnnotations(readOnlyHint=False, destructiveHint=True,
                                       openWorldHint=False),
    }


def tool(kind: str = "read"):
    """Register a tool. read: no changes. edit: undoable changes. destructive: not undoable."""
    return mcp.tool(annotations=_ANNOTATIONS[kind]) if _HINTS else mcp.tool()

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def _tag(response) -> list:
    """
    Prefix a response with the program that produced it.

    With more than one binary open, silently reading the wrong one is a mistake the
    caller cannot otherwise detect, so the server names the answering program on every
    response and it is surfaced here rather than left in a header nobody reads.
    """
    name = response.headers.get("X-Ghidra-Program")
    return [f"# program: {name}"] if name and name != "none" else []


def safe_get(endpoint: str, params: dict = None, timeout: int = None,
             program: str = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}
    if program:
        params = {**params, "program": program}
    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return _tag(response) + response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except requests.exceptions.ConnectionError:
        return [f"Cannot reach Ghidra at {ghidra_server_url} - is Ghidra running with "
                f"the GhidraMCP plugin enabled and a program open?"]
    except requests.exceptions.Timeout:
        return [f"Timed out after {timeout}s calling {endpoint}. Retry with a narrower "
                f"range, or the program may still be analyzing."]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str, timeout: int = None,
              program: str = None) -> str:
    if timeout is None:
        timeout = DEFAULT_TIMEOUT
    try:
        url = urljoin(ghidra_server_url, endpoint)
        # program travels in the query string even for POST: the server must know which
        # program a request is about before it reads the body.
        query = {"program": program} if program else None
        if isinstance(data, dict):
            response = requests.post(url, data=data, params=query, timeout=timeout)
        else:
            response = requests.post(url, data=data.encode("utf-8"), params=query,
                                     timeout=timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return "\n".join(_tag(response) + [response.text.strip()])
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except requests.exceptions.ConnectionError:
        return (f"Cannot reach Ghidra at {ghidra_server_url} - is Ghidra running with "
                f"the GhidraMCP plugin enabled and a program open?")
    except requests.exceptions.Timeout:
        return f"Timed out after {timeout}s calling {endpoint}."
    except Exception as e:
        return f"Request failed: {str(e)}"

@tool()
def list_methods(offset: int = 0, limit: int = 100, program: str = None) -> str:
    """
    List all function names in the program with pagination.
    """
    return "\n".join(safe_get("methods", {"offset": offset, "limit": limit}, program=program))

@tool()
def list_classes(offset: int = 0, limit: int = 100, program: str = None) -> str:
    """
    List C++ classes in the program.

    Only real classes - namespaces Ghidra created from RTTI or from demangled symbols.
    For every namespace including import libraries and demangler artefacts, use
    list_namespaces. A stripped binary built without RTTI has no classes at all; find_rtti
    says whether there are any to find.
    """
    return "\n".join(safe_get("classes", {"offset": offset, "limit": limit}, program=program))

@tool()
def decompile_function(name: str, program: str = None) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name, timeout=SLOW_TIMEOUT, program=program)

@tool("edit")
def rename_function(old_name: str, new_name: str, program: str = None) -> str:
    """
    Rename a function by its current name to a new user-defined name. A qualified
    new_name ("UObject::Tick") moves it into that namespace, creating it if needed.

    Reports old -> new and the address. If several functions share the name it refuses
    and lists them; use a qualified Class::name or rename_function_by_address.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name}, program=program)

@tool("edit")
def rename_data(address: str, new_name: str, program: str = None) -> str:
    """
    Rename the label on defined data, reporting the old and new names.

    The address must hold *defined* data. If it does not, that is said rather than being
    silently ignored - apply_data_type first, or use batch_rename(kind="label").
    """
    return safe_post("renameData", {"address": address, "newName": new_name}, program=program)

@tool()
def list_segments(offset: int = 0, limit: int = 100, program: str = None) -> str:
    """
    List all memory segments in the program with pagination.
    """
    return "\n".join(safe_get("segments", {"offset": offset, "limit": limit}, program=program))

@tool()
def list_imports(offset: int = 0, limit: int = 100, program: str = None) -> str:
    """
    List imported symbols in the program with pagination.
    """
    return "\n".join(safe_get("imports", {"offset": offset, "limit": limit}, program=program))

@tool()
def list_exports(offset: int = 0, limit: int = 100, program: str = None) -> str:
    """
    List exported functions/symbols with pagination.
    """
    return "\n".join(safe_get("exports", {"offset": offset, "limit": limit}, program=program))

@tool()
def list_namespaces(offset: int = 0, limit: int = 100, program: str = None) -> str:
    """
    List all non-global namespaces in the program with pagination.
    """
    return "\n".join(safe_get("namespaces", {"offset": offset, "limit": limit}, program=program))

@tool()
def list_data_items(offset: int = 0, limit: int = 100, program: str = None) -> str:
    """
    List defined data labels and their values with pagination.
    """
    return "\n".join(safe_get("data", {"offset": offset, "limit": limit}, program=program))

@tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100, program: str = None) -> str:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return "\n".join(safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit}, program=program))

@tool("edit")
def rename_variable(function_name: str, old_name: str, new_name: str, program: str = None) -> str:
    """
    Rename a local variable within a function. Reports old -> new, or Ghidra's reason
    when the rename is refused (for example a name that already exists).
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    }, timeout=SLOW_TIMEOUT, program=program)

@tool()
def get_function_by_address(address: str, program: str = None) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}, program=program))

@tool()
def get_current_address(program: str = None) -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address", program=program))

@tool()
def get_current_function(program: str = None) -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function", program=program))

@tool()
def list_functions(offset: int = 0, limit: int = 500, filter: str = None, program: str = None) -> str:
    """
    List functions as "address<TAB>name<TAB>size". Paginated - a real binary has tens
    of thousands of functions, so always pass a filter or page through with offset.

    Args:
        offset: Pagination offset
        limit: Max functions per page
        filter: Case-insensitive substring of the function name (e.g. "FUN_" for
                undefined functions, "Player" for candidates worth reading)
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return "\n".join(safe_get("list_functions", params, program=program))

@tool()
def decompile_function_by_address(address: str, start_line: int = 1, max_lines: int = 0,
                                  program: str = None) -> str:
    """
    Decompile a function at the given address. Prefer get_function_context for a first
    look at a function - it returns the same C plus callers, callees and strings.
    """
    return "\n".join(safe_get("decompile_function",
                              {"address": address, "start_line": start_line,
                               "max_lines": max_lines},
                              timeout=SLOW_TIMEOUT, program=program))

@tool()
def disassemble_function(address: str, program: str = None) -> str:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return "\n".join(safe_get("disassemble_function", {"address": address}, program=program))

@tool("edit")
def set_decompiler_comment(address: str, comment: str, program: str = None) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment}, program=program)

@tool("edit")
def set_disassembly_comment(address: str, comment: str, program: str = None) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment}, program=program)

@tool("edit")
def rename_function_by_address(function_address: str, new_name: str, program: str = None) -> str:
    """
    Rename a function by its address. Reports old -> new.

    A qualified name such as "UObject::Tick" moves the function into that namespace,
    creating it if needed; template arguments may contain "::".
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name}, program=program)

@tool("edit")
def set_function_prototype(function_address: str, prototype: str, program: str = None) -> str:
    """
    Set a function's prototype, e.g. "int __thiscall Tick(void *this, float dt)".

    The name in the prototype is applied too, so it renames the function when it
    differs (reported as "Renamed old -> new"). The function's plate comment is left alone.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype}, program=program)

@tool("edit")
def set_local_variable_type(function_address: str, variable_name: str, new_type: str, program: str = None) -> str:
    """
    Set a local variable's type.

    Resizing is only refused for variables in *hash storage* - ones the decompiler
    synthesised with no fixed register or stack location. Register and stack variables
    resize fine. On a refusal the message carries Ghidra's own reason and both sizes, so
    you can tell which case you are in.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type}, timeout=SLOW_TIMEOUT, program=program)

@tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100, program: str = None) -> str:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return "\n".join(safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit}, program=program))

@tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100, program: str = None) -> str:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return "\n".join(safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit}, program=program))

@tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100, program: str = None) -> str:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return "\n".join(safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit}, program=program))

@tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None, program: str = None) -> str:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return "\n".join(safe_get("strings", params, program=program))


# ======================================================================================
# Added tools
# ======================================================================================

@tool()
def get_program_info(program: str = None) -> str:
    """
    Orientation for the currently open program: architecture, endianness, pointer size,
    image base, compiler spec, address range, function and symbol counts.

    Call this FIRST in a new session. Pointer size and image base determine how to read
    vtables and interpret addresses, and guessing them from address widths is unreliable.
    """
    return "\n".join(safe_get("program_info", program=program))

@tool()
def get_function_context(address: str = None, name: str = None,
                         decompile: bool = True, disassemble: bool = False,
                         max_refs: int = 40, start_line: int = 1, max_lines: int = 0,
                         program: str = None) -> str:
    """
    Everything about one function in a single call: signature, calling convention,
    parameters, locals, callers, callees, referenced strings, and the decompiled body
    with a source address on every line.

    This is the preferred entry point for understanding a function. It replaces the
    sequence decompile_function_by_address + get_function_xrefs + get_xrefs_from +
    list_strings that would otherwise be needed.

    Args:
        address: Function entry (or any address inside it), e.g. "0x140001a20"
        name: Function name, used only when address is omitted
        decompile: Include decompiled C with per-line addresses (default True)
        disassemble: Also include the raw disassembly (default False)
        max_refs: Cap on callers/callees/strings listed
        start_line, max_lines: Return only a window of the response. On a very large
            function pass decompile=False first for the cheap summary, then page the
            body with max_lines rather than pulling thousands of lines at once.
    """
    params = {"decompile": str(decompile).lower(), "disassemble": str(disassemble).lower(),
              "max_refs": max_refs, "start_line": start_line, "max_lines": max_lines}
    if address:
        params["address"] = address
    if name:
        params["name"] = name
    return "\n".join(safe_get("function_context", params, timeout=SLOW_TIMEOUT, program=program))

@tool()
def decompile_with_addresses(address: str, start_line: int = 1, max_lines: int = 0,
                             program: str = None) -> str:
    """
    Decompile a function with each line prefixed by the address it maps to
    ("0x140001a2c | if (iVar1 == 0) {").

    Use this whenever you intend to call set_decompiler_comment or set_disassembly_comment:
    plain decompiled output carries no addresses, so there is no way to anchor a comment
    to the right line without this mapping.
    """
    return "\n".join(safe_get("decompile_with_addresses",
                              {"address": address, "start_line": start_line,
                               "max_lines": max_lines},
                              timeout=SLOW_TIMEOUT, program=program))

@tool()
def search_bytes(pattern: str, start: str = None, end: str = None, limit: int = 50, program: str = None) -> str:
    """
    Byte-pattern (AOB) search with wildcards. Returns address, memory block and
    containing function+offset for each hit.

    Args:
        pattern: "48 8B ?? ?? 89 05", "48 8b ? 89", or "488B??8905". ?? / ? / * are wildcards.
        start: Optional start address (defaults to program min)
        end: Optional end address (defaults to program max)
        limit: Max hits to return

    Use this to locate a known signature, find every site matching an instruction shape,
    or check how unique a candidate signature is before relying on it.
    """
    params = {"pattern": pattern, "limit": limit}
    if start:
        params["start"] = start
    if end:
        params["end"] = end
    return "\n".join(safe_get("search_bytes", params, timeout=SLOW_TIMEOUT, program=program))

@tool()
def read_bytes(address: str, length: int = 64, program: str = None) -> str:
    """
    Hex dump of raw memory at an address (max 4096 bytes). Use when the listing view
    is not enough - inspecting a header, a jump table, packed data, or an encrypted blob.
    """
    return "\n".join(safe_get("read_bytes", {"address": address, "length": length}, program=program))

@tool()
def disassemble_range(address: str, count: int = 40, program: str = None) -> str:
    """
    Disassemble N instructions starting at an address, whether or not a function is
    defined there. Use this for code Ghidra has not turned into a function yet;
    disassemble_function requires an existing function.
    """
    return "\n".join(safe_get("disassemble_range", {"address": address, "count": count}, program=program))

@tool()
def get_callers(address: str, offset: int = 0, limit: int = 100, program: str = None) -> str:
    """
    Functions that call the function at this address ("address<TAB>name").
    """
    return "\n".join(safe_get("get_callers", {"address": address, "offset": offset, "limit": limit}, program=program))

@tool()
def get_callees(address: str, offset: int = 0, limit: int = 100, program: str = None) -> str:
    """
    Functions called by the function at this address ("address<TAB>name").
    """
    return "\n".join(safe_get("get_callees", {"address": address, "offset": offset, "limit": limit}, program=program))

@tool()
def call_graph(address: str, depth: int = 2, direction: str = "callees",
               max_nodes: int = 200, program: str = None) -> str:
    """
    Indented call tree rooted at a function, up to `depth` levels (max 5).

    Args:
        address: Root function address
        depth: How many levels to expand
        direction: "callees" to walk down, "callers" to walk up toward entry points
        max_nodes: Safety cap on tree size

    Use "callers" to work out how execution reaches an interesting function, and
    "callees" to see what a large function delegates to before reading it.
    """
    return "\n".join(safe_get("call_graph", {"address": address, "depth": depth,
                                   "direction": direction, "max_nodes": max_nodes},
                    timeout=SLOW_TIMEOUT, program=program))

@tool()
def list_symbols(filter: str = None, type: str = "any", offset: int = 0,
                 limit: int = 200, program: str = None) -> str:
    """
    Search all symbols, not just functions ("address<TAB>type<TAB>name").

    Args:
        filter: Substring, or a regex when wrapped in slashes: "/^\\?\\?_7/". Matched
                against the namespace-qualified name, the one shown in the output, so
                "CSource::vftable" finds what it looks like it should.
        type: "function", "label", "class", "global", or "any"
        offset, limit: Pagination

    Finds things search_functions_by_name cannot: vtable symbols (filter "vftable" or
    "??_7"), RTTI descriptors, global data labels, class namespaces.
    """
    params = {"offset": offset, "limit": limit, "type": type}
    if filter:
        params["filter"] = filter
    return "\n".join(safe_get("list_symbols", params, program=program))

@tool()
def list_data_types(filter: str = None, offset: int = 0, limit: int = 200, program: str = None) -> str:
    """
    List data types known to the program ("name<TAB>size<TAB>path"). Check here before
    calling set_local_variable_type or apply_data_type - those need a type that exists.
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return "\n".join(safe_get("list_data_types", params, program=program))

@tool()
def get_type_info(name: str, program: str = None) -> str:
    """
    Full layout of a struct or union: offset, size, type and name of every field.
    Use this to read back a struct you built, or to inspect an imported type before
    applying it to memory.
    """
    return "\n".join(safe_get("get_type_info", {"name": name}, program=program))

@tool()
def get_vtable(address: str, count: int = 32, program: str = None) -> str:
    """
    Walk a pointer table and resolve each slot to a function
    ("index<TAB>slot_addr<TAB>target<TAB>name"). Stops at the first null or unmapped
    entry, which is usually the end of the table.

    Find the table first with list_symbols(filter="vftable") or by following the first
    member of an object, then use this to enumerate the virtual methods in order.
    """
    return "\n".join(safe_get("get_vtable", {"address": address, "count": count}, program=program))

@tool()
def search_decompiled(query: str, name_filter: str = None, max_functions: int = 300,
                      limit: int = 50, program: str = None) -> str:
    """
    Grep the decompiled C of many functions at once ("address<TAB>function<TAB>line").

    Finds things no name or byte search can: a magic constant, a specific comparison,
    a call pattern. Decompiling is expensive - always narrow with name_filter or
    max_functions on a large binary.

    Args:
        query: Case-insensitive substring to find in decompiled output
        name_filter: Only examine functions whose name contains this
        max_functions: Cap on how many functions get decompiled
        limit: Max matching lines to return
    """
    params = {"query": query, "max_functions": max_functions, "limit": limit}
    if name_filter:
        params["name_filter"] = name_filter
    return "\n".join(safe_get("search_decompiled", params, timeout=SLOW_TIMEOUT, program=program))

@tool("edit")
def create_struct(name: str, fields: str, packed: bool = False, program: str = None) -> str:
    """
    Create a named structure in the program's data type manager.

    Args:
        name: Struct name, e.g. "CBaseEntity"
        fields: ";"-separated. Either "type:name" for sequential layout, or
                "offset:type:name" for explicit offsets with gaps, e.g.
                "0x0:pointer:vtable;0x64:int:health;0x70:float:posX"
        packed: Enable packing (default False - explicit offsets usually want False)

    After creating, use apply_data_type to lay it over memory, or
    set_local_variable_type to type a decompiled variable with it. This is how you turn
    a pile of "*(int *)(param_1 + 0x64)" expressions into readable field accesses.
    """
    return safe_post("create_struct", {"name": name, "fields": fields,
                                       "packed": str(packed).lower()}, program=program)

@tool("edit")
def apply_data_type(address: str, type_name: str, count: int = 1, program: str = None) -> str:
    """
    Define data of a named type at an address, clearing whatever was there.
    Pass count > 1 to lay down an array.
    """
    return safe_post("apply_data_type", {"address": address, "type_name": type_name,
                                         "count": count}, program=program)

@tool("edit")
def create_function(address: str, name: str = None, program: str = None) -> str:
    """
    Create a function at an address Ghidra left as loose code, optionally naming it.
    Useful after finding a call target that auto-analysis missed. Undefined bytes are
    disassembled as part of creating it.

    An address already inside another function is reported as such, and a failed attempt
    rolls back rather than leaving an empty entry on the undo stack.
    """
    data = {"address": address}
    if name:
        data["name"] = name
    return safe_post("create_function", data, timeout=SLOW_TIMEOUT, program=program)

@tool("edit")
def batch_rename(entries: str, kind: str = "function", program: str = None) -> str:
    """
    Rename many symbols in one request and one undo-able transaction.

    Args:
        entries: Newline- or ";"-separated "address=NewName" pairs, e.g.
                 "0x140001a20=CBaseEntity::GetHealth\\n0x140001b40=CBaseEntity::SetHealth"
        kind: "function" (default) or "label" for data/labels

    Strongly preferred over calling rename_function_by_address in a loop: one round trip
    and one undo step instead of dozens. Qualified function names ("Class::Method") put
    the function in that namespace, creating it if needed.
    """
    return safe_post("batch_rename", {"kind": kind, "entries": entries},
                     timeout=SLOW_TIMEOUT, program=program)



@tool()
def list_annotations(filter: str = None, kind: str = "all",
                     offset: int = 0, limit: int = 200, program: str = None) -> str:
    """
    Read back every user-defined symbol and every comment in the program.

    This is the "what has already been worked out here" query. Renames and comments
    written by an earlier session are otherwise invisible - nothing else in this API
    reports them - so call this FIRST when resuming work on a binary you have touched
    before, and again after a long analysis run to check your own trail.

    Args:
        filter: Only lines containing this substring (case-insensitive)
        kind: "all" (default), "symbols" for renames only, "comments" for notes only
        offset, limit: Pagination

    Returns "address<TAB>kind<TAB>context<TAB>value". Symbols are those with source
    USER_DEFINED, so auto-analysis names (FUN_*, DAT_*) are excluded by construction.
    """
    params = {"kind": kind, "offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return "\n".join(safe_get("list_annotations", params, timeout=SLOW_TIMEOUT, program=program))


@tool()
def get_comments(address: str = None, name: str = None, program: str = None) -> str:
    """
    Every comment attached to one function, in address order.

    Use before re-analysing a function you have annotated: the decompiled output does
    not carry your notes, so without this you re-derive conclusions you already reached.

    Args:
        address: Function entry, or any address inside it
        name: Function name, used only when address is omitted
    """
    params = {}
    if address:
        params["address"] = address
    if name:
        params["name"] = name
    return "\n".join(safe_get("get_comments", params, program=program))


@tool("edit")
def parse_c_header(source: str, args: str = None, program: str = None) -> str:
    """
    Parse a block of C declarations straight into the program's type manager.

    Handles structs, unions, enums, typedefs and types that reference each other -
    none of which create_struct can express. This is the fast path for game binaries:
    paste a dumped SDK header, or the engine structs you already know, and every
    variable you then type gets real field names.

    Args:
        source: C source text. Preprocessor directives are honoured, so #define and
                conditional blocks work. #include of files that are not on disk will
                not resolve - strip those first.
        args: Optional preprocessor arguments, space-separated, e.g. "-D_WIN64 -DNDEBUG"

    Returns a list of the types that were added, plus any parser messages. Parse errors
    are reported rather than thrown, and partial success is normal on a large header -
    check the returned list for the types you actually needed.
    """
    data = {"source": source}
    if args:
        data["args"] = args
    return safe_post("parse_c_header", data, timeout=SLOW_TIMEOUT, program=program)


@tool("edit")
def create_enum(name: str, values: str, size: int = 4, category: str = None, program: str = None) -> str:
    """
    Create an enum data type.

    Complements create_struct: structs name offsets, enums name constants. Apply one
    with set_equate and "if (state == 3)" becomes "if (state == EState_Dying)" at every
    site the equate is placed, which no amount of renaming achieves.

    Args:
        name: Enum type name, e.g. "EWeaponType"
        values: ";"-separated members, "Name=Value" or bare "Name" to continue the
                previous value + 1. Values may be decimal or 0x-prefixed.
                e.g. "None=0;Sword=1;Bow=2;Siege=0x10"
        size: Storage size in bytes - 1, 2, 4 (default) or 8
        category: Optional category path, e.g. "/Chivalry"
    """
    data = {"name": name, "values": values, "size": size}
    if category:
        data["category"] = category
    return safe_post("create_enum", data, program=program)


@tool("edit")
def set_equate(address: str, operand_index: int = 1, name: str = None,
               value: str = None, enum_name: str = None, program: str = None) -> str:
    """
    Give a constant operand a name, in both the listing and the decompiler.

    Two ways to call it: pass `name` for a one-off label, or pass `enum_name` and let
    the member matching that operand's value supply the name.

    Args:
        address: Address of the instruction
        operand_index: Which operand carries the constant (default 1, the usual source
                       operand for "CMP EAX, 3"-style comparisons)
        name: Explicit equate name
        value: Optional explicit value; by default the scalar is read from the operand
        enum_name: Enum to take the name from, e.g. "EWeaponType"
    """
    data = {"address": address, "operand_index": operand_index}
    for key, val in (("name", name), ("value", value), ("enum_name", enum_name)):
        if val:
            data[key] = val
    return safe_post("set_equate", data, program=program)


@tool("edit")
def auto_create_struct(address: str = None, function: str = None,
                       variable: str = None, param_index: int = 0,
                       struct_name: str = None, apply: bool = True, program: str = None) -> str:
    """
    Infer a struct from how a pointer is actually used, and create it.

    Walks the decompiler's p-code from a parameter or local, collecting every offset
    that is loaded, stored or called through, then builds a type from the result and
    (by default) applies it to that variable.

    Use this INSTEAD of reading a decompiled body and hand-recording every
    "*(int *)(param_1 + 0x64)". It also flags which offsets are called through - those
    are vtable slots or function pointers - and which feed float math, which load size
    alone cannot tell you.

    Args:
        address: Function entry, or any address inside it
        function: Function name, used only when address is omitted
        variable: Name of the variable to profile, e.g. "param_1" or "this"
        param_index: Parameter to profile when `variable` is omitted (0 = first)
        struct_name: Name for the new type; defaults to <function>_<variable>_t
        apply: Create the type and retype the variable as <struct> * (default True).
               apply=False is a true dry run - it reports the inferred layout and writes
               nothing at all, not even the type.

    Returns the evidence table (offset, size, type, load/store counts, notes) followed
    by the created type. Offsets it never sees stay as gaps - the result is a starting
    point to refine, not a finished type. Run it on several functions that take the
    same pointer and merge what you learn.

    If it reports no field accesses, the object pointer is often not the parameter the
    decompiler models: with an unset prototype the accesses usually flow through a local
    such as lVar1. The error lists the function's variables - retry with variable=<one>.
    """
    data = {"param_index": param_index, "apply": str(apply).lower()}
    for key, val in (("address", address), ("function", function),
                     ("variable", variable), ("struct_name", struct_name)):
        if val:
            data[key] = val
    return safe_post("auto_create_struct", data, timeout=SLOW_TIMEOUT, program=program)


@tool()
def find_field_accesses(offset: str, block: str = None, limit: int = 100,
                        max_instructions: int = 20000000, program: str = None) -> str:
    """
    Find every instruction that uses a given structure offset off a register base -
    "who touches +0x64".

    Works before any type has been applied, which is exactly when offset discovery
    happens. Far more precise than searching decompiled text for "+ 0x64", and much
    faster, since it reads operands rather than decompiling.

    Args:
        offset: The field offset, e.g. "0x64" or "1636"
        block: Restrict to one memory block, e.g. ".text" (recommended on big binaries)
        limit: Max hits to return
        max_instructions: Scan cap; the response says so when the cap was hit

    Returns "addr<TAB>function+off<TAB>reftype<TAB>instruction".
    """
    params = {"offset": offset, "limit": limit, "max_instructions": max_instructions}
    if block:
        params["block"] = block
    return "\n".join(safe_get("find_field_accesses", params, timeout=SLOW_TIMEOUT, program=program))


@tool()
def search_constant(value: str, kinds: str = "auto", block: str = None,
                    limit: int = 50, program: str = None) -> str:
    """
    Search for a typed value rather than a byte pattern.

    "90.0f" is encoded to its IEEE-754 bytes for you; integers are searched at each
    plausible width and as instruction immediates. Every hit comes back with its block,
    containing function and reference count already resolved, so you can tell a live
    constant from a pooled duplicate in one call rather than chasing each hit with
    get_xrefs_to.

    This is the entry point when a magic number is all you have: a frame-rate cap, a
    packet size, a version number, a timeout.

    Args:
        value: "90.0f", "120", "0x2710", "3.14159". A "." or an f/d suffix means float.
        kinds: "auto" (default) picks encodings from the literal's form. Otherwise any
               combination of "float", "double", "int32", "int64", "imm" - where "imm"
               scans instruction immediates rather than data.
        block: Restrict to one memory block, e.g. ".rdata"
        limit: Max hits per encoding

    Hits with zero references are almost always coincidental byte alignment, not the
    constant you are looking for.
    """
    params = {"value": value, "kinds": kinds, "limit": limit}
    if block:
        params["block"] = block
    return "\n".join(safe_get("search_constant", params, timeout=SLOW_TIMEOUT, program=program))


@tool()
def search_instructions(regex: str, block: str = None, limit: int = 100,
                        max_instructions: int = 20000000, program: str = None) -> str:
    """
    Regex over disassembly text across the whole program.

    Catches what a byte search cannot, because you no longer have to guess an encoding.
    "every immediate write to +0x700" is
        MOV dword ptr \\[.*\\+0x700\\],
    rather than a hand-built "C7 ?? 00 07 00 00" that misses other encodings of the
    same instruction.

    Args:
        regex: Java regex, case-insensitive, matched against the instruction text
        block: Restrict to one memory block, e.g. ".text" (recommended)
        limit: Max hits
        max_instructions: Scan cap; the response says so when the cap was hit

    Returns "addr<TAB>function+off<TAB>instruction".
    """
    params = {"regex": regex, "limit": limit, "max_instructions": max_instructions}
    if block:
        params["block"] = block
    return "\n".join(safe_get("search_instructions", params, timeout=SLOW_TIMEOUT, program=program))


@tool()
def get_call_sites(address: str = None, name: str = None, with_args: bool = True,
                   limit: int = 50, program: str = None) -> str:
    """
    Every call site of a function, with the constant arguments at each one resolved -
    strings, global symbols, function names and immediates.

    This is the strongest single move for identifying what an unknown function does,
    and for recovering tables. Pointed at a registration helper it yields the whole
    table at once: the name, offset and flags of every field a property registrar
    declares, or every command a console registers - hundreds of facts in one call.

    Args:
        address: Callee entry, or any address inside it
        name: Callee name, used only when address is omitted
        with_args: Decode arguments (default True). This decompiles each caller, so
                   pass False for a fast list of call sites on a hot function.
        limit: Max call sites (default 50). Keep it modest with with_args on.

    Returns "addr<TAB>caller<TAB>arguments".
    """
    params = {"with_args": str(with_args).lower(), "limit": limit}
    if address:
        params["address"] = address
    if name:
        params["name"] = name
    return "\n".join(safe_get("get_call_sites", params, timeout=SLOW_TIMEOUT, program=program))


@tool()
def resolve_virtual_call(address: str, program: str = None) -> str:
    """
    Work out what an indirect call goes to.

    Recovers the vtable slot offset and index from "CALL qword ptr [RAX + 0x280]", and
    resolves the actual target when the table is known statically. When it is not, the
    slot index is still the useful half: pair it with find_vtables_containing or
    get_vtable on a vftable symbol.

    Args:
        address: Address of the CALL instruction itself
    """
    return "\n".join(safe_get("resolve_virtual_call", {"address": address},
                              timeout=SLOW_TIMEOUT, program=program))


@tool()
def find_vtables_containing(address: str = None, name: str = None,
                            limit: int = 25, program: str = None) -> str:
    """
    Reverse vtable lookup: which pointer tables contain this function, and at what index.

    Turns "I found an interesting function" into "this is virtual method N of these
    classes", which then names the same slot across every sibling vtable. The inverse
    of get_vtable.

    Args:
        address: Function entry, or any address inside it
        name: Function name, used only when address is omitted
        limit: Max tables to report

    Returns "table_base<TAB>slot_index<TAB>symbol<TAB>block". The base is found by walking
    backwards while the preceding entries still point into executable memory, so slots
    auto-analysis never turned into functions no longer truncate the walk. A table whose
    leading entries are not code pointers at all can still report a base that is too high
    and an index that is too low - cross-check against a known call site when the index
    matters.
    """
    params = {"limit": limit}
    if address:
        params["address"] = address
    if name:
        params["name"] = name
    return "\n".join(safe_get("find_vtables_containing", params, timeout=SLOW_TIMEOUT, program=program))


@tool()
def file_offset(address: str = None, file_offset: str = None, program: str = None) -> str:
    """
    Convert between virtual address and file offset, both directions.

    Uses the loader's own section mapping rather than PE header arithmetic done by
    hand. Needed whenever an external tool has to touch the same bytes - a patcher, a
    hex editor, a signature scanner that works on the file rather than the image.

    Args:
        address: VA to convert to a file offset, e.g. "0x140463f4f"
        file_offset: File offset to convert back to a VA, e.g. "0x46334f"

    Pass exactly one. Uninitialized sections (.bss and friends) have no file bytes and
    are reported as such rather than given a bogus offset.
    """
    params = {}
    if address:
        params["address"] = address
    if file_offset:
        params["file_offset"] = file_offset
    return "\n".join(safe_get("file_offset", params, program=program))



# ======================================================================================
# Program selection, import and analysis
#
# Every tool above accepts an optional `program` argument, and every response is
# prefixed with "# program: <name>" naming the binary that answered it.
# ======================================================================================

@tool()
def list_open_programs() -> str:
    """
    List every program open in Ghidra, with the current one marked.

    CALL THIS FIRST in any session where more than one binary might be open. Every other
    tool defaults to whichever program Ghidra considers current, and analysing the wrong
    binary produces answers that look completely valid. Once you know the names, pass
    `program=` explicitly rather than relying on the default.

    Returns index, current marker, name, architecture, function count, unsaved-changes
    flag, analysis state and project path.
    """
    return "\n".join(safe_get("list_open_programs"))


@tool("edit")
def select_program(name: str) -> str:
    """
    Change which program is current for calls that do not pass `program=`.

    Args:
        name: Program name, project path, or "#0"-style index from list_open_programs
    """
    return safe_post("select_program", {"name": name})


@tool("edit")
def import_file(path: str, folder: str = None, analyze: bool = False) -> str:
    """
    Import a binary into the open Ghidra project and open it in the tool.

    The path is resolved by Ghidra, on the machine Ghidra is running on - not by this
    bridge and not in any sandbox. Give a full local path to that machine.

    Args:
        path: Full path to the binary, e.g. "C:\\\\Games\\\\Chivalry\\\\Binaries\\\\Win64\\\\CDW.exe"
        folder: Destination folder inside the Ghidra project (default "/")
        analyze: Start auto-analysis immediately (default False)

    Returns immediately: the import runs in the background, because a large binary takes
    longer than the ~60s an MCP client allows a tool call. Poll analysis_status, which
    reports imports as well as analysis.

    The program is opened *hidden* rather than made current. Activating a newly imported
    program is what raises Ghidra's "analyze now?" prompt and then the Analysis Options
    dialog, both modal - an unattended import must not put a dialog in front of the user.
    Call select_program once the import reports done, then start_analysis, which drives
    the analysis manager directly and raises no dialogs.

    Nothing but loader symbols exists until analysis has run, so a function count of 0
    right after import is expected rather than a failure.
    """
    data = {"path": path, "analyze": str(analyze).lower()}
    if folder:
        data["folder"] = folder
    return safe_post("import_file", data, timeout=SLOW_TIMEOUT)


@tool("edit")
def start_analysis(name: str = None) -> str:
    """
    Run Ghidra's auto-analysis on a program, in the background.

    Returns immediately. On a large game binary this takes many minutes and every
    result you read before it finishes is incomplete - functions will be missing,
    strings undefined, xrefs absent. Poll analysis_status and wait for "no" before
    drawing conclusions.

    Args:
        name: Program to analyse; defaults to the current one
    """
    data = {}
    if name:
        data["name"] = name
    return safe_post("start_analysis", data, timeout=SLOW_TIMEOUT)


@tool()
def analysis_status(name: str = None) -> str:
    """
    Whether analysis is running, and how many functions exist so far.

    A rising function count between two calls means analysis is still doing useful work.
    The `analyzed` column is Ghidra's own flag: NO means it will raise its modal "would you
    like to analyze it now?" prompt when the program is next activated. start_analysis sets
    the flag when it finishes. Also reports any imports started this session.

    Args:
        name: Restrict to one program; default reports all open programs
    """
    params = {}
    if name:
        params["name"] = name
    return "\n".join(safe_get("analysis_status", params))


@tool("destructive")
def save_program(program: str = None) -> str:
    """
    Write the program back to the Ghidra project.

    Renames, comments and types live in memory until this is called or the user saves
    in the GUI. Worth calling after a batch of analysis work so it survives a crash.
    """
    return safe_post("save_program", {}, program=program)


# ======================================================================================
# Undo
# ======================================================================================

@tool()
def list_undo_stack(limit: int = 30, program: str = None) -> str:
    """
    Show the program's undo and redo stacks, most recent first.

    Every write endpoint names its transaction, so this reads as a log of what has been
    changed. Check it before undoing anything - the stack includes edits made in the
    Ghidra GUI, not just ones made through this API.
    """
    return "\n".join(safe_get("list_undo_stack", {"limit": limit}, program=program))


@tool("destructive")
def undo(count: int = 1, program: str = None) -> str:
    """
    Undo the last N program transactions.

    The recovery path when a write goes wrong - a bad prototype, a struct applied to the
    wrong variable, a batch rename built on a mistaken premise. Call list_undo_stack
    first and read what you are about to reverse: undo does not distinguish between your
    changes and the user's.

    Args:
        count: How many transactions to reverse (default 1)
    """
    return safe_post("undo", {"count": count}, program=program)


@tool("destructive")
def redo(count: int = 1, program: str = None) -> str:
    """
    Redo transactions previously undone.

    Args:
        count: How many to reapply (default 1)
    """
    return safe_post("redo", {"count": count}, program=program)


# ======================================================================================
# Identification
# ======================================================================================

@tool()
def find_string_xrefs(pattern: str, regex: bool = False, limit: int = 50,
                      max_refs: int = 10, program: str = None) -> str:
    """
    Strings matching a pattern, together with the functions that reference them.

    The standard way into an unfamiliar binary: a console command, an error message or a
    config key names the code that handles it. Replaces list_strings followed by one
    get_xrefs_to per hit.

    Args:
        pattern: Substring, or a regex when regex=True
        regex: Treat pattern as a regular expression
        limit: Max strings to return
        max_refs: Max referrers listed per string

    A string with zero references is still informative - the absence of a config-key
    string is evidence that the value is compiled in rather than read from an ini.
    """
    params = {"pattern": pattern, "regex": str(regex).lower(),
              "limit": limit, "max_refs": max_refs}
    return "\n".join(safe_get("find_string_xrefs", params, timeout=SLOW_TIMEOUT,
                              program=program))


@tool()
def function_evidence(address: str = None, name: str = None, depth: int = 2,
                      max_nodes: int = 400, program: str = None) -> str:
    """
    Transitive evidence for what a function does.

    get_function_context reports what a function touches *directly*, which for a leaf
    function is often nothing identifying. This walks outward instead: the imported APIs
    it eventually reaches, the strings its callees reference, and which already-named
    functions call it.

    Use it when a function's own body tells you nothing - no strings, no imports, just
    arithmetic. The identity is usually two or three hops away.

    Args:
        address: Function entry, or any address inside it
        name: Function name, used only when address is omitted
        depth: Call-graph hops to walk (default 2, max 4)
        max_nodes: Cap on functions visited

    Reaching WSARecv and a "packet" string at depth 2 is evidence, not proof - a shared
    utility called from everywhere will reach a lot of things that say nothing about it.
    Weigh it against the caller list.
    """
    params = {"depth": depth, "max_nodes": max_nodes}
    if address:
        params["address"] = address
    if name:
        params["name"] = name
    return "\n".join(safe_get("function_evidence", params, timeout=SLOW_TIMEOUT,
                              program=program))


@tool("edit")
def suggest_names_from_strings(filter: str = None, limit: int = 100, min_length: int = 4,
                               apply: bool = False, program: str = None) -> str:
    """
    Mine identifier-shaped strings for function names.

    Engine builds carry assert and log format strings containing the real name of the
    code that emits them - "Class::Method" or "SomeFunction()". Where such a string is
    referenced from exactly one unnamed function, that is a strong naming candidate.
    In a stripped binary this can name a large number of functions mechanically.

    Args:
        filter: Only consider strings containing this substring, e.g. "Assertion failed"
        limit: Max candidates
        min_length: Minimum identifier length, to suppress noise
        apply: Actually rename (default False)

    Defaults to proposing rather than applying, and the output is "address=Name" so you
    can hand the reviewed subset to batch_rename. Read the evidence string on each line
    before applying: a function that merely *logs* another subsystem's name will be
    named wrongly, and a wrong name is worse than FUN_140463f20 because it stops you
    looking.
    """
    data = {"limit": limit, "min_length": min_length, "apply": str(apply).lower()}
    if filter:
        data["filter"] = filter
    return safe_post("suggest_names_from_strings", data, timeout=SLOW_TIMEOUT,
                     program=program)


@tool()
def trace_value(address: str, variable: str = None, depth: int = 8,
                direction: str = "backward", cross: int = 1, max_functions: int = 8,
                program: str = None) -> str:
    """
    Follow a value through the decompiler's data flow, across function boundaries.

    backward: where did this value come from - loads, arithmetic, constants, and with
    cross > 0 it continues into a callee's return statements when the value is a call
    result, and into callers' arguments when it is a parameter.
    forward: where does this value go - uses, stores, branches it decides, arguments it is
    passed as (continuing inside the callee), and returns (continuing in the caller).

    Args:
        address: An address inside the function. With `variable` omitted, starts from the
                 instruction's result at this address.
        variable: Name of a decompiler variable to start from instead
        depth: Maximum chain depth within a function (default 8)
        direction: "backward" (default) or "forward"
        cross: How many call levels to cross (0 = stay in this function, max 4, default 1)
        max_functions: Cap on extra functions decompiled (default 8, max 32)

    Ends with "# not followed:" listing what it could not follow: indirect calls,
    externals, memory writes, call sites past the cap, budget limits. Treat those as open
    questions, not as "nothing there". Edges come from decompiler output, not execution.
    """
    params = {"address": address, "depth": depth, "direction": direction,
              "cross": cross, "max_functions": max_functions}
    if variable:
        params["variable"] = variable
    return "\n".join(safe_get("trace_value", params, timeout=SLOW_TIMEOUT, program=program))


@tool()
def inspect_instruction(address: str, program: str = None) -> str:
    """
    Everything about one instruction: bytes, length, file offset, operands broken into
    registers/scalars/addresses, flow type, targets, fall-through and references.

    On x86 also gives same-length patch bytes: never/always jump and invert for
    conditional jumps, NOPs for calls and other instructions - ready for
    generate_patch_script. Says so when the address is mid-instruction, data, or not
    disassembled.
    """
    return "\n".join(safe_get("inspect_instruction", {"address": address}, program=program))


@tool()
def get_basic_blocks(address: str = None, name: str = None, program: str = None) -> str:
    """
    Control-flow graph of a function: each basic block's range, instruction count, last
    instruction, successors (fall/cond/jump) and predecessor count.

    Use it to see which branch guards what before patching a condition. When `address` is
    inside the function, its block is marked with ">". Warns when blocks do not cover the
    function body exactly.
    """
    params = {}
    if address:
        params["address"] = address
    if name:
        params["name"] = name
    return "\n".join(safe_get("get_basic_blocks", params, timeout=SLOW_TIMEOUT, program=program))


@tool("edit")
def goto_address(address: str, program: str = None) -> str:
    """
    Move the user's Ghidra window (listing and decompiler) to an address.

    Use when pointing the user at something, so they see it without searching. Changes
    only the view, not the program.
    """
    return safe_post("goto_address", {"address": address}, program=program)


@tool("edit")
def set_bookmark(address: str, comment: str, category: str = "Claude",
                 program: str = None) -> str:
    """
    Leave a note bookmark the user can see in Ghidra's Bookmarks window (Window >
    Bookmarks, filter by category). Use for findings worth coming back to. One bookmark
    per address and category; setting again replaces it and reports the old text.
    Undoable.
    """
    return safe_post("set_bookmark", {"address": address, "comment": comment,
                                      "category": category}, program=program)


@tool()
def list_bookmarks(category: str = "Claude", filter: str = None, all: bool = False,
                   limit: int = 200, program: str = None) -> str:
    """
    List note bookmarks in a category (default "Claude"), with the containing function.

    all=true lists every category the user has used, except Ghidra's own analysis
    bookmarks unless a filter is given. Read this at the start of a session to pick up
    earlier findings.
    """
    params = {"category": category, "all": str(all).lower(), "limit": limit}
    if filter:
        params["filter"] = filter
    return "\n".join(safe_get("list_bookmarks", params, program=program))


@tool("edit")
def remove_bookmark(address: str, category: str = "Claude", program: str = None) -> str:
    """Remove the note bookmark at an address in a category (default "Claude")."""
    return safe_post("remove_bookmark", {"address": address, "category": category},
                     program=program)


@tool("edit")
def fix_noreturn(apply: bool = False, limit: int = 100, program: str = None) -> str:
    """
    Find, and optionally repair, functions wrongly flagged as never returning.

    Auto-analysis sometimes marks a function no-return although its body contains a real
    return. Every call to it is then treated as the end of the caller: the code after the
    call is never disassembled and decompiles silently stop there. Decompile output,
    get_function_context and get_callees warn when a function is affected.

    Lists functions flagged no-return whose body contains a return instruction, with how
    many calls each has cut short. apply=true clears those flags, re-disassembles after
    each affected call, refits the callers' bodies, and repeats for callers that inherited
    the flag - all in one undo step. A return only counts when no call on the
    straight-line path before it ends the process (TerminateProcess, ExitProcess, abort,
    __fastfail ...), so handlers like __report_gsfailure, whose trailing RET is dead code,
    are left alone.
    """
    return safe_post("fix_noreturn", {"apply": str(apply).lower(), "limit": limit},
                     timeout=SLOW_TIMEOUT, program=program)


@tool()
def selftest(samples: int = 6, program: str = None) -> str:
    """
    Check the toolset against the open program: build match, name lookup, file-offset
    round trips, instruction bytes against memory, basic blocks covering each function,
    call-graph symmetry, search_constant finding a known immediate, decompile, forward and
    backward trace, and that a rolled-back write leaves nothing behind.

    Run after installing a new build, or when results look wrong. Read-only: the one write
    it makes is rolled back. Hard-capped near 40s; samples that do not fit are reported as SKIP.
    """
    return "\n".join(safe_get("selftest", {"bridge": BRIDGE_BUILD, "samples": samples},
                               timeout=SLOW_TIMEOUT, program=program))


# ======================================================================================
# Cross-binary and patching
# ======================================================================================

@tool("edit")
def match_functions(from_program: str, to_program: str, min_instructions: int = 8,
                    apply: bool = False, limit: int = 500) -> str:
    """
    Carry function names from one binary to another by structural matching.

    Hashes each function by its mnemonic sequence and operand kinds - deliberately
    ignoring addresses and immediates, which change between builds - and matches shapes
    that are unique in both programs. Only names that already exist in the source and
    are absent in the target are proposed.

    This is what makes analysis survive a game patch, and what ports work between two
    builds of the same engine. Both programs must be open; see list_open_programs.

    Args:
        from_program: Program to take names from (the one you have analysed)
        to_program: Program to apply names to
        min_instructions: Skip functions smaller than this - short functions collide
                          constantly and produce false matches (default 8)
        apply: Rename in the target (default False)
        limit: Max matches to report

    Ambiguous shapes are skipped rather than guessed, so a low match count on an
    inlining-heavy build is expected and is the safe failure. Raise min_instructions if
    any match looks wrong; do not lower it.
    """
    data = {"from": from_program, "to": to_program,
            "min_instructions": min_instructions,
            "apply": str(apply).lower(), "limit": limit}
    return safe_post("match_functions", data, timeout=SLOW_TIMEOUT)


@tool()
def generate_patch_script(edits: str, script_name: str = None, window: int = 12,
                          program: str = None) -> str:
    """
    Emit a verified Python patcher for a set of byte edits.

    Every edit is checked against the program in Ghidra before the script is written:
    the address must contain exactly the "old" bytes given, and old and new must be the
    same length. Mismatches are refused rather than emitted, so a script only exists if
    its premise held.

    The generated script verifies a window of surrounding bytes and the file's SHA-256
    before touching anything, backs the file up, re-reads from disk afterwards, restores
    the backup if verification fails, and supports --check and --revert. It refuses to
    run on a build it does not recognise.

    Args:
        edits: "VA:old_bytes->new_bytes", separated by newlines or ";", e.g.
               "0x140463F4F:0F 84->90 E9; 0x1404438D8:73->EB"
        script_name: Name to suggest for the saved file (default "patch.py")
        window: Context bytes captured either side of each edit (default 12)

    Preferred over writing bytes into the program: the artifact is reviewable, keeps
    working after Ghidra is closed, and fails closed on the wrong build. To pad a
    shortened instruction use explicit 0x90 NOPs so lengths still match.
    """
    data = {"edits": edits, "window": window}
    if script_name:
        data["script_name"] = script_name
    return safe_post("generate_patch_script", data, timeout=SLOW_TIMEOUT, program=program)



@tool()
def list_project_files(filter: str = None, limit: int = 200) -> str:
    """
    Every program in the open Ghidra project, whether or not it is currently open.

    list_open_programs shows what is loaded in the tool right now; this shows what exists.
    A binary analysed in an earlier session is in the project but closed, and until it is
    opened no other tool can see it.

    Args:
        filter: Substring of the path, e.g. "CDW"
        limit: Max files

    Returns "open<TAB>path<TAB>type<TAB>analyzed", with OPEN marking the ones already loaded.
    """
    params = {"limit": limit}
    if filter:
        params["filter"] = filter
    return "\n".join(safe_get("list_project_files", params))


@tool("edit")
def open_program(path: str, make_current: bool = False) -> str:
    """
    Open a program that is already in the project.

    The missing third verb: import_file brings a binary in from disk, select_program
    switches between programs already open, and this opens one that exists in the project
    but is closed. Needed before match_functions can see both sides.

    Args:
        path: Project path, e.g. "/CDW.exe". A unique name alone also works; ambiguous
              names return the candidates rather than picking one.
        make_current: Also make it the default for calls that omit program= (default
                      False). Leaving it hidden avoids Ghidra's analyse prompt and
                      Analysis Options dialog, which are modal and would block the caller.
    """
    return safe_post("open_program",
                     {"path": path, "make_current": str(make_current).lower()},
                     timeout=SLOW_TIMEOUT)


@tool("destructive")
def close_program(name: str, save: bool = False) -> str:
    """
    Close an open program, so a session can put back what it opened.

    Args:
        name: Program name, project path, or "#0"-style index from list_open_programs
        save: Save first if it has unsaved changes. Without this, a changed program is
              refused rather than silently discarded.
    """
    return safe_post("close_program", {"name": name, "save": str(save).lower()})



@tool()
def version() -> str:
    """
    Which build of each half is running.

    The plugin and the bridge are separate processes updated separately, and a stale half
    can behave exactly like a working one - a silent no-op that reports success is the
    failure mode this exists to prevent. Call it after any reinstall, and first in any
    session where behaviour does not match the documentation.

    Reports the plugin build, the bridge build, the endpoint count, the Ghidra version and
    the current program, and says so explicitly when the two builds disagree.
    """
    try:
        from importlib.metadata import version as _pkg_version
        sdk = _pkg_version("mcp")
    except Exception:
        sdk = "unknown"
    hints = "on" if _HINTS else "off - update mcp to 1.30 or later"
    return "\n".join(safe_get("version", {"bridge": BRIDGE_BUILD})
                     + [f"mcp_sdk: {sdk} (tool hints {hints})"])


@tool("edit")
def find_rtti(filter: str = None, limit: int = 200, apply: bool = False,
              with_bases: bool = False, chunk_kb: int = 0, program: str = None) -> str:
    """
    Recover C++ class names from MSVC RTTI and pair them with their vtables.

    A stripped binary still carries the class names its RTTI needs. This scans for Complete
    Object Locators, resolves each to its type descriptor name, demangles it, and finds the
    vtable that points at it. Naming a vtable is worth more than naming a function: it
    labels every slot in it at once, and combined with find_vtables_containing it turns
    "interesting function" into "virtual method N of a named class".

    Args:
        filter: Only classes whose demangled name contains this, e.g. "NetDriver"
        limit: Max classes to list
        apply: Create a "<Class>::vftable" label at each vtable (default False). Existing
               user-defined labels are left alone.
        with_bases: Also walk each class's BaseClassArray and report the inheritance chain
               with the offset of each base within the object (default False, because it
               adds a line per class and costs extra reads).
        chunk_kb: Testing only - read memory in pieces of this size (min 4) instead of
               16 MB, to check that records straddling a piece boundary are still found.

    Returns "class<TAB>vftable<TAB>slots<TAB>bases<TAB>vtable_offset<TAB>complete_object_locator".
    Slot counts stop at the first entry that is not a code pointer, so they are a lower
    bound. Template classes are reported in their mangled form rather than guessed at.
    A class with no vftable found is usually abstract or has had its table folded away.
    """
    data = {"limit": limit, "apply": str(apply).lower(),
            "with_bases": str(with_bases).lower()}
    if filter:
        data["filter"] = filter
    if chunk_kb:
        data["chunk_kb"] = chunk_kb
    return safe_post("find_rtti", data, timeout=SLOW_TIMEOUT, program=program)


@tool()
def demangle(name: str, program: str = None) -> str:
    """
    Demangle a C++ symbol or an RTTI type-descriptor name.

    Args:
        name: A mangled symbol, or an RTTI name like ".?AVUNetDriver@@"
    """
    return "\n".join(safe_get("demangle", {"name": name}, program=program))


def main():
    global ghidra_server_url, DEFAULT_TIMEOUT, SLOW_TIMEOUT
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Seconds to wait on normal Ghidra requests, default: {DEFAULT_TIMEOUT}")
    parser.add_argument("--slow-timeout", type=int, default=SLOW_TIMEOUT,
                        help=f"Seconds to wait on decompile/search requests, default: {SLOW_TIMEOUT}")
    args = parser.parse_args()

    # Use the global variable to ensure it's properly updated
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    DEFAULT_TIMEOUT = args.timeout
    SLOW_TIMEOUT = args.slow_timeout

    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

