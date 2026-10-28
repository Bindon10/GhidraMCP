[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)


# ghidraMCP
ghidraMCP is an Model Context Protocol server for allowing LLMs to autonomously reverse engineer applications. It exposes numerous tools from core Ghidra functionality to MCP clients.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9


# This fork

Extended for Ghidra 12.1.2: 87 MCP tools against the original 27, each run against real
binaries.

## What it lets you do

Ask your MCP client in plain language; the tool names are listed for reference.

- **Find the code behind something you can see.** A console command, error message or config
  key leads straight to the functions that use it (`find_string_xrefs`).
- **Find a magic number.** Give a value like `90.0f` or `120` and get every place it is stored
  or used as an immediate, each with its reference count, so live constants stand out from
  coincidences (`search_constant`).
- **Find who touches a struct field.** Every instruction that uses a given offset off a
  register, such as `+0x700` (`find_field_accesses`).
- **Ask where a value comes from, or where it goes.** The trace follows it through loads,
  arithmetic and calls into other functions, and lists what it could not follow
  (`trace_value`).
- **Work out what a function is** when it has no strings of its own, from the imports, strings
  and named callers around it (`function_evidence`).
- **Fix decompiles that stop mid-function.** When Ghidra wrongly decides a callee never
  returns, every caller is cut short at that call; this finds and repairs those flags, and
  decompiles warn when it has happened (`fix_noreturn`).
- **Recover C++ structure from a stripped binary.** Class names, vtables and inheritance from
  MSVC RTTI, and the target slot of an indirect call like `call [rax+0x280]` (`find_rtti`,
  `resolve_virtual_call`, `find_vtables_containing`).
- **Build types quickly.** Paste a C header, or infer a struct from how a pointer is used
  (`parse_c_header`, `auto_create_struct`).
- **Keep your work across a game update.** Carry function names from an analysed build to a
  new one by matching code shape (`match_functions`).
- **Drive Ghidra without the GUI.** Import a binary, run analysis, save, and work with several
  programs at once; undo changes step by step (`import_file`, `start_analysis`,
  `undo`).
- **Patch safely.** Get same-length patch bytes for a jump or call, then a Python script that
  checks the file before writing, backs it up, verifies afterwards and can revert
  (`inspect_instruction`, `generate_patch_script`).
- **Follow along in Ghidra.** The model can move your listing to what it is talking about and
  leave bookmarks you can browse later (`goto_address`, `set_bookmark`).
- **Check the setup.** Confirm both halves are the same build, and run consistency checks
  against the open program (`version`, `selftest`).

Decompiled output uses Ghidra's own Decompiler settings, so it matches the decompiler window,
and every tool is marked read-only, undoable edit or destructive for clients that use hints.
The HTTP server binds to `127.0.0.1` by default. See [docs/SUMMARY.md](docs/SUMMARY.md) for an
overview, [docs/CAPABILITIES.md](docs/CAPABILITIES.md) for the tool reference and
[docs/CHANGES.md](docs/CHANGES.md) for the full history.

# Features
MCP Server + Ghidra Plugin

- Decompile and analyze binaries in Ghidra
- Automatically rename methods and data
- List methods, classes, imports, and exports

# Installation

## Prerequisites
- Install [Ghidra](https://ghidra-sre.org)
- Python3
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk)

## Ghidra
First, build the extension (see [Building from Source](#building-from-source)) or download the `GhidraMCP-artifact` from this fork's latest [Actions](https://github.com/Bindon10/GhidraMCP/actions) build. It contains the Ghidra plugin and Python MCP client. Then, you can directly import the plugin into Ghidra.

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-1.0-SNAPSHOT.zip` from the build
5. Restart Ghidra
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`
7. *Optional*: Configure the port in Ghidra with `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

Theoretically, any MCP client should work with ghidraMCP.  Three examples are given below.

## Example 1: Claude Desktop
To set up Claude Desktop as a Ghidra MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Alternatively, edit this file directly:
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

The server IP and port are configurable and should be set to point to the target Ghidra instance. If not set, both will default to localhost:8080.

## Example 2: Cline
To use GhidraMCP with [Cline](https://cline.bot), this requires manually running the MCP server as well. First run the following command:

```
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

The only *required* argument is the transport. If all other arguments are unspecified, they will default to the above. Once the MCP server is running, open up Cline and select `MCP Servers` at the top.

![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

Then select `Remote Servers` and add the following, ensuring that the url matches the MCP host and port:

1. Server Name: GhidraMCP
2. Server URL: `http://127.0.0.1:8081/sse`

## Example 3: 5ire
Another MCP client that supports multiple models on the backend is [5ire](https://github.com/nanbingxyz/5ire). To set up GhidraMCP, open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

# Building from Source
Requires JDK 21 and Ghidra 12.1.2.

1. Copy the following files from your Ghidra directory to this project's `lib/` directory:
- `Ghidra/Features/Base/lib/Base.jar`
- `Ghidra/Features/Decompiler/lib/Decompiler.jar`
- `Ghidra/Framework/Docking/lib/Docking.jar`
- `Ghidra/Framework/Generic/lib/Generic.jar`
- `Ghidra/Framework/Project/lib/Project.jar`
- `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`
- `Ghidra/Framework/Utility/lib/Utility.jar`
- `Ghidra/Framework/Gui/lib/Gui.jar`
2. Build with Maven by running:

`mvn clean package assembly:single`

The generated zip file includes the built Ghidra plugin and its resources. These files are required for Ghidra to recognize the new extension.

- lib/GhidraMCP.jar
- extensions.properties
- Module.manifest
