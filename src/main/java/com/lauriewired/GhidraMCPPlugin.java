package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.mem.Memory;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.scalar.Scalar;
import ghidra.app.util.cparser.C.CParserUtils;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.concurrent.ConcurrentHashMap;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AnalysisBackgroundCommand;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.model.lang.Register;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private ExecutorService serverPool;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final String LOCALHOST_OPTION_NAME = "Bind To Localhost Only";
    private static final int DEFAULT_PORT = 8080;

    // Cached decompiler: creating a DecompInterface and re-opening the program on
    // every request is the single biggest source of latency in the original plugin.
    private DecompInterface cachedDecomp;
    private Program cachedDecompProgram;
    private final Object decompLock = new Object();

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");
        options.registerOption(LOCALHOST_OPTION_NAME, Boolean.TRUE,
            null,
            "When enabled (default) the server binds to 127.0.0.1 only. The API can rename " +
            "functions, edit types and write comments with no authentication, so exposing it " +
            "on all interfaces lets anyone on the network modify your project.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        boolean localOnly = options.getBoolean(LOCALHOST_OPTION_NAME, true);
        InetSocketAddress bindAddress = localOnly
            ? new InetSocketAddress(InetAddress.getLoopbackAddress(), port)
            : new InetSocketAddress(port);
        server = HttpServer.create(bindAddress, 0);

        // Each listing endpoint uses offset & limit from query params:
        ctx("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        ctx("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        ctx("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        ctx("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, renameFunction(params.get("oldName"), params.get("newName")));
        });

        ctx("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange,
                renameDataAtAddress(params.get("address"), params.get("newName")));
        });

        ctx("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        ctx("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        ctx("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        ctx("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        ctx("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        ctx("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        ctx("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        ctx("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        ctx("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        ctx("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        ctx("/list_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"), 500);
            sendResponse(exchange, listFunctions(offset, limit, qparams.get("filter")));
        });

        ctx("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, windowLines(decompileFunctionByAddress(address),
                parseIntOrDefault(qparams.get("start_line"), 1),
                parseIntOrDefault(qparams.get("max_lines"), 0)));
        });

        ctx("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        ctx("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        ctx("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        ctx("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        ctx("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        ctx("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);
            if (!success && lastVariableTypeError != null) {
                responseMsg.append("\nReason: ").append(lastVariableTypeError);
            }

            sendResponse(exchange, responseMsg.toString());
        });

        ctx("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        ctx("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        ctx("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        ctx("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        // ------------------------------------------------------------------
        // Endpoints added for LLM ergonomics / reverse-engineering workflows
        // ------------------------------------------------------------------

        ctx("/program_info", exchange ->
            sendResponse(exchange, getProgramInfo()));

        ctx("/function_context", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, windowLines(getFunctionContext(
                q.get("address"),
                q.get("name"),
                !"false".equalsIgnoreCase(q.get("decompile")),
                "true".equalsIgnoreCase(q.get("disassemble")),
                parseIntOrDefault(q.get("max_refs"), 40)),
                parseIntOrDefault(q.get("start_line"), 1),
                parseIntOrDefault(q.get("max_lines"), 0)));
        });

        ctx("/decompile_with_addresses", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, windowLines(decompileWithAddresses(q.get("address")),
                parseIntOrDefault(q.get("start_line"), 1),
                parseIntOrDefault(q.get("max_lines"), 0)));
        });

        ctx("/search_bytes", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, searchBytes(
                q.get("pattern"),
                q.get("start"),
                q.get("end"),
                parseIntOrDefault(q.get("limit"), 50)));
        });

        ctx("/read_bytes", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, readBytes(q.get("address"),
                parseIntOrDefault(q.get("length"), 64)));
        });

        ctx("/disassemble_range", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, disassembleRange(q.get("address"),
                parseIntOrDefault(q.get("count"), 40)));
        });

        ctx("/get_callers", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, getCallers(q.get("address"),
                parseIntOrDefault(q.get("offset"), 0), parseIntOrDefault(q.get("limit"), 100)));
        });

        ctx("/get_callees", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, getCallees(q.get("address"),
                parseIntOrDefault(q.get("offset"), 0), parseIntOrDefault(q.get("limit"), 100)));
        });

        ctx("/call_graph", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, callGraph(q.get("address"),
                parseIntOrDefault(q.get("depth"), 2),
                !"callers".equalsIgnoreCase(q.get("direction")),
                parseIntOrDefault(q.get("max_nodes"), 200)));
        });

        ctx("/list_symbols", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, listSymbols(q.get("filter"), q.get("type"),
                parseIntOrDefault(q.get("offset"), 0), parseIntOrDefault(q.get("limit"), 200)));
        });

        ctx("/list_data_types", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, listDataTypes(q.get("filter"),
                parseIntOrDefault(q.get("offset"), 0), parseIntOrDefault(q.get("limit"), 200)));
        });

        ctx("/get_type_info", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, getTypeInfo(q.get("name")));
        });

        ctx("/get_vtable", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, getVtable(q.get("address"),
                parseIntOrDefault(q.get("count"), 32)));
        });

        ctx("/search_decompiled", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, searchDecompiled(q.get("query"), q.get("name_filter"),
                parseIntOrDefault(q.get("max_functions"), 300),
                parseIntOrDefault(q.get("limit"), 50)));
        });

        ctx("/create_struct", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, createStruct(p.get("name"), p.get("fields"),
                "true".equalsIgnoreCase(p.get("packed"))));
        });

        ctx("/apply_data_type", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, applyDataTypeAt(p.get("address"), p.get("type_name"),
                parseIntOrDefault(p.get("count"), 1)));
        });

        ctx("/create_function", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, createFunctionAt(p.get("address"), p.get("name")));
        });

        ctx("/batch_rename", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, batchRename(p.get("kind"), p.get("entries")));
        });

        ctx("/list_annotations", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, listAnnotations(q.get("filter"), q.get("kind"),
                parseIntOrDefault(q.get("offset"), 0),
                parseIntOrDefault(q.get("limit"), 200)));
        });

        ctx("/get_comments", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, getComments(q.get("address"), q.get("name")));
        });

        ctx("/parse_c_header", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, parseCHeader(p.get("source"), p.get("args")));
        });

        ctx("/create_enum", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, createEnumType(p.get("name"),
                parseIntOrDefault(p.get("size"), 4), p.get("values"), p.get("category")));
        });

        ctx("/set_equate", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, setEquate(p.get("address"),
                parseIntOrDefault(p.get("operand_index"), 1),
                p.get("name"), p.get("value"), p.get("enum_name")));
        });

        ctx("/auto_create_struct", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, autoCreateStruct(p.get("address"), p.get("function"),
                p.get("variable"), parseIntOrDefault(p.get("param_index"), 0),
                p.get("struct_name"), !"false".equalsIgnoreCase(p.get("apply"))));
        });

        ctx("/find_field_accesses", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, findFieldAccesses(q.get("offset"), q.get("block"),
                parseIntOrDefault(q.get("limit"), 100),
                parseIntOrDefault(q.get("max_instructions"), 20000000)));
        });

        ctx("/search_constant", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, searchConstant(q.get("value"), q.get("kinds"),
                q.get("block"), parseIntOrDefault(q.get("limit"), 50)));
        });

        ctx("/search_instructions", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, searchInstructions(q.get("regex"), q.get("block"),
                parseIntOrDefault(q.get("limit"), 100),
                parseIntOrDefault(q.get("max_instructions"), 20000000)));
        });

        ctx("/get_call_sites", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, getCallSites(q.get("address"), q.get("name"),
                !"false".equalsIgnoreCase(q.get("with_args")),
                parseIntOrDefault(q.get("limit"), 50)));
        });

        ctx("/resolve_virtual_call", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, resolveVirtualCall(q.get("address")));
        });

        ctx("/find_vtables_containing", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, findVtablesContaining(q.get("address"), q.get("name"),
                parseIntOrDefault(q.get("limit"), 25)));
        });

        ctx("/file_offset", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, fileOffset(q.get("address"), q.get("file_offset")));
        });

        ctx("/version", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, versionReport(q.get("bridge")));
        });

        ctx("/find_rtti", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            int kb = parseIntOrDefault(p.get("chunk_kb"), 0);
            if (kb > 0) RTTI_CHUNK_OVERRIDE.set(Math.max(4, kb) * 1024);
            try {
                sendResponse(exchange, findRtti(p.get("filter"),
                    parseIntOrDefault(p.get("limit"), 200),
                    "true".equalsIgnoreCase(p.get("apply")),
                    "true".equalsIgnoreCase(p.get("with_bases"))));
            } finally {
                RTTI_CHUNK_OVERRIDE.remove();
            }
        });

        ctx("/demangle", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, demangleName(q.get("name")));
        });

        ctx("/list_project_files", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, listProjectFiles(q.get("filter"),
                parseIntOrDefault(q.get("limit"), 200)));
        });

        ctx("/open_program", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, openProjectProgram(p.get("path"),
                "true".equalsIgnoreCase(p.get("make_current"))));
        });

        ctx("/close_program", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, closeProjectProgram(p.get("name"),
                "true".equalsIgnoreCase(p.get("save"))));
        });

        ctx("/list_open_programs", exchange -> {
            sendResponse(exchange, listOpenPrograms());
        });

        ctx("/select_program", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, selectProgram(p.get("name")));
        });

        ctx("/import_file", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, importFile(p.get("path"), p.get("folder"),
                "true".equalsIgnoreCase(p.get("analyze"))));
        });

        ctx("/start_analysis", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, startAnalysis(p.get("name")));
        });

        ctx("/analysis_status", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, analysisStatusReport(q.get("name")));
        });

        ctx("/save_program", exchange -> {
            sendResponse(exchange, saveProgram());
        });

        ctx("/undo", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, undoRedo(true, parseIntOrDefault(p.get("count"), 1)));
        });

        ctx("/redo", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, undoRedo(false, parseIntOrDefault(p.get("count"), 1)));
        });

        ctx("/list_undo_stack", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, listUndoStack(parseIntOrDefault(q.get("limit"), 30)));
        });

        ctx("/find_string_xrefs", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, findStringXrefs(q.get("pattern"),
                "true".equalsIgnoreCase(q.get("regex")),
                parseIntOrDefault(q.get("limit"), 50),
                parseIntOrDefault(q.get("max_refs"), 10)));
        });

        ctx("/function_evidence", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, functionEvidence(q.get("address"), q.get("name"),
                parseIntOrDefault(q.get("depth"), 2),
                parseIntOrDefault(q.get("max_nodes"), 400)));
        });

        ctx("/suggest_names_from_strings", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, suggestNamesFromStrings(p.get("filter"),
                parseIntOrDefault(p.get("limit"), 100),
                parseIntOrDefault(p.get("min_length"), 4),
                "true".equalsIgnoreCase(p.get("apply"))));
        });

        ctx("/trace_value", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, traceValue(q.get("address"), q.get("variable"),
                parseIntOrDefault(q.get("depth"), 8), q.get("direction"),
                parseIntOrDefault(q.get("cross"), 1),
                parseIntOrDefault(q.get("max_functions"), 8)));
        });

        ctx("/match_functions", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, matchFunctions(p.get("from"), p.get("to"),
                parseIntOrDefault(p.get("min_instructions"), 8),
                "true".equalsIgnoreCase(p.get("apply")),
                parseIntOrDefault(p.get("limit"), 500)));
        });

        ctx("/generate_patch_script", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, generatePatchScript(p.get("edits"), p.get("script_name"),
                parseIntOrDefault(p.get("window"), 12)));
        });

        ctx("/goto_address", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, gotoAddress(p.get("address")));
        });

        ctx("/set_bookmark", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, setBookmark(p.get("address"), p.get("comment"), p.get("category")));
        });

        ctx("/list_bookmarks", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, listBookmarks(q.get("category"), q.get("filter"),
                "true".equalsIgnoreCase(q.get("all")), parseIntOrDefault(q.get("limit"), 200)));
        });

        ctx("/remove_bookmark", exchange -> {
            Map<String, String> p = parsePostParams(exchange);
            sendResponse(exchange, removeBookmark(p.get("address"), p.get("category")));
        });

        ctx("/inspect_instruction", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, inspectInstruction(q.get("address")));
        });

        ctx("/get_basic_blocks", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, getBasicBlocks(q.get("address"), q.get("name")));
        });

        ctx("/selftest", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, selftest(q.get("bridge"), parseIntOrDefault(q.get("samples"), 6)));
        });

        endpointCount = 86;

        // A small pool keeps one slow decompile from blocking every other request.
        // Decompiler access is serialized internally via decompLock. Waits on the UI
        // thread are bounded (see invokeAndWaitBounded) so a modal dialog cannot
        // permanently consume workers.
        serverPool = Executors.newFixedThreadPool(8, r -> {
            Thread t = new Thread(r, "GhidraMCP-Worker");
            t.setDaemon(true);
            return t;
        });
        server.setExecutor(serverPool);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        // Actual classes only. Collecting every non-global parent namespace makes this a
        // duplicate of list_namespaces, and fills the result with import namespaces like
        // ADVAPI32.DLL and demangler artefacts like .PEAX.
        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns instanceof ghidra.program.model.listing.GhidraClass) {
                classNames.add(ns.getName(true));
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        if (sorted.isEmpty()) {
            return "No classes defined. Ghidra creates class namespaces from RTTI or from "
                + "demangled symbols; a stripped binary built without RTTI has none. "
                + "Try find_rtti, or list_namespaces for every namespace including imports.";
        }
        return String.format("# %d class(es)\n", sorted.size())
            + paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        List<Function> matches = functionsNamed(program, name);
        if (matches.isEmpty()) return "Function not found";
        if (matches.size() > 1) {
            // Ambiguous names (C++ overloads, thunks) silently resolved to the first
            // match before. Say so instead, and let the caller pick by address.
            StringBuilder sb = new StringBuilder("Error: " + matches.size()
                + " functions named '" + name + "'. Use decompile_function_by_address with one of:\n");
            for (Function f : matches) {
                sb.append(f.getEntryPoint()).append('\t').append(f.getSignature().getPrototypeString()).append('\n');
            }
            return sb.toString();
        }
        DecompileResults result = decompileCached(program, matches.get(0), 60);
        if (result != null && result.decompileCompleted()) {
            return result.getDecompiledFunction().getC();
        }
        return "Decompilation failed";
    }

    private String renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (newName == null || newName.isEmpty()) return "Error: newName is required";
        Function f = uniqueFunctionNamed(program, oldName);
        if (f == null) return "Rename failed: no function named '" + oldName + "'";
        String err = inTransaction(program, "Rename function via HTTP",
            () -> f.setName(newName, SourceType.USER_DEFINED));
        return err == null ? "Renamed " + oldName + " -> " + newName + " @ " + f.getEntryPoint()
                           : "Rename failed: " + err;
    }

    private String renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (newName == null || newName.isEmpty()) return "Error: newName is required";
        Address addr = resolveAddress(program, addressStr);
        if (addr == null) return "Error: bad address: " + addressStr;

        final StringBuilder result = new StringBuilder();
        String err = inTransaction(program, "Rename data", () -> {
            Data data = program.getListing().getDefinedDataAt(addr);
            if (data == null) {
                result.append("No defined data at ").append(addr)
                      .append(" - apply_data_type first, or use batch_rename(kind=\"label\")");
                return;
            }
            SymbolTable symTable = program.getSymbolTable();
            Symbol symbol = symTable.getPrimarySymbol(addr);
            String before = symbol != null ? symbol.getName() : "(unnamed)";
            if (symbol != null) {
                symbol.setName(newName, SourceType.USER_DEFINED);
            } else {
                symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
            }
            result.append("Renamed data at ").append(addr).append(": ")
                  .append(before).append(" -> ").append(newName);
        });
        if (err != null) return "Rename failed: " + err;
        return result.toString();
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = uniqueFunctionNamed(program, functionName);
        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decompileCached(program, func, 60);
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            invokeAndWaitBounded(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        String needle = (filter == null || filter.isEmpty()) ? null : filter.toLowerCase();
        List<String> lines = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (needle != null && !func.getName().toLowerCase().contains(needle)) continue;
            lines.add(String.format("%s\t%s\t%d%s",
                func.getEntryPoint(),
                func.getName(),
                func.getBody().getNumAddresses(),
                func.isThunk() ? "\tthunk" : ""));
        }
        if (lines.isEmpty()) {
            return needle == null ? "No functions in program"
                                  : "No functions matching '" + filter + "'";
        }
        return String.format("# %d function(s) total, showing %d..%d (addr\tname\tsize)\n",
                lines.size(), offset, Math.min(lines.size(), offset + limit))
            + paginateList(lines, offset, limit);
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompileResults result = decompileCached(program, func, 60);

            return (result != null && result.decompileCompleted())
                ? result.getDecompiledFunction().getC()
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            invokeAndWaitBounded(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            invokeAndWaitBounded(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            invokeAndWaitBounded(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            invokeAndWaitBounded(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Reuses the cached, already-opened decompiler instead of spinning up a new
        // process and re-opening the program on every call.
        DecompileResults results = decompileCached(program, func, 60);

        if (results == null || !results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " +
                (results == null ? "decompiler unavailable" : results.getErrorMessage()));
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private String lastVariableTypeError = null;

    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        lastVariableTypeError = null;
        try {
            HighFunctionDBUtil.updateDBVariable(
                symbol,
                symbol.getName(),
                dataType,
                SourceType.USER_DEFINED
            );
            success.set(true);
        } catch (Exception e) {
            // "Failed to set variable type" on its own sends the caller looking in the
            // wrong place. The usual cause is a storage size mismatch - retyping an
            // 8-byte register variable to a 4-byte int - and the exception says so.
            lastVariableTypeError = e.getClass().getSimpleName() + ": " + e.getMessage();
            DataType current = symbol.getDataType();
            if (current != null && current.getLength() != dataType.getLength()) {
                lastVariableTypeError += " (currently " + current.getName() + ", "
                    + current.getLength() + " bytes; " + dataType.getName() + " is "
                    + dataType.getLength() + ". Ghidra only refuses a resize for variables "
                    + "in hash storage - ones the decompiler synthesised with no fixed "
                    + "register or stack location. Register and stack variables resize "
                    + "fine, so a same-sized type, or naming the underlying variable "
                    + "instead, is the way through.)";
            }
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null)
                    ? " in " + fromFunc.getName() + "+0x"
                      + Long.toHexString(fromAddr.subtract(fromFunc.getEntryPoint()))
                    : "";

                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Function inside = program.getFunctionManager().getFunctionContaining(toAddr);
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null && isStringData(data) && data.getValue() != null) {
                        String value = escapeString(data.getValue().toString());
                        if (value.length() > 80) value = value.substring(0, 80) + "...";
                        targetInfo = " to string \"" + value + "\"";
                    } else if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    } else if (inside != null) {
                        targetInfo = " into " + inside.getName() + "+0x"
                            + Long.toHexString(toAddr.subtract(inside.getEntryPoint()));
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            List<Function> named = functionsNamed(program, functionName);
            for (Function function : named) {
                {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null)
                            ? " in " + fromFunc.getName() + "+0x"
                              + Long.toHexString(fromAddr.subtract(fromFunc.getEntryPoint()))
                            : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName())
                            + (named.size() > 1 ? " -> " + entryPoint : ""));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        if (typeName.startsWith("/")) {
            DataType byPath = dtm.getDataType(typeName);
            if (byPath != null) return byPath;
        }
        // Exact matches win over case-insensitive ones anywhere in the manager, so "bool"
        // can never resolve to BOOL just because BOOL was iterated first.
        DataType exact = null;
        DataType folded = null;
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt.getName().equals(typeName)) {
                if (exact == null || dt.getCategoryPath().isRoot()) exact = dt;
            } else if (folded == null && dt.getName().equalsIgnoreCase(typeName)) {
                folded = dt;
            }
        }
        return exact != null ? exact : folded;
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * The program this request is about: the ?program= override when one was given,
     * otherwise whatever the tool has current.
     */
    public Program getCurrentProgram() {
        return resolveProgram(PROGRAM_OVERRIDE.get());
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        sendResponse(exchange, response, statusForResponse(response));
    }

    private void sendResponse(HttpExchange exchange, String response, int status) throws IOException {
        byte[] bytes = (response == null ? "" : response).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    // ==================================================================================
    // Decompiler lifecycle
    // ==================================================================================

    /**
     * Returns a DecompInterface already opened on the given program, reusing the cached
     * one when possible. Callers must hold decompLock.
     */
    private DecompInterface acquireDecompiler(Program program) {
        if (cachedDecomp != null && cachedDecompProgram == program) {
            return cachedDecomp;
        }
        releaseDecompiler();
        DecompInterface decomp = new DecompInterface();
        if (!decomp.openProgram(program)) {
            decomp.dispose();
            return null;
        }
        cachedDecomp = decomp;
        cachedDecompProgram = program;
        return decomp;
    }

    private void releaseDecompiler() {
        if (cachedDecomp != null) {
            try {
                cachedDecomp.dispose();
            } catch (Exception ignored) {
                // best effort
            }
            cachedDecomp = null;
            cachedDecompProgram = null;
        }
    }

    /**
     * Decompile using the cached interface. Serialized: DecompInterface is not thread safe.
     */
    private DecompileResults decompileCached(Program program, Function func, int timeoutSeconds) {
        synchronized (decompLock) {
            DecompInterface decomp = acquireDecompiler(program);
            if (decomp == null) return null;
            return decomp.decompileFunction(func, timeoutSeconds, TaskMonitor.DUMMY);
        }
    }

    // ==================================================================================
    // Shared helpers for the added endpoints
    // ==================================================================================

    /**
     * How long any request may wait on Ghidra's UI thread before giving up.
     * Deliberately below the 60s an MCP client typically allows a tool call.
     */
    private static final int SWING_TIMEOUT_SECONDS = 40;

    /**
     * invokeAndWait with a timeout.
     *
     * SwingUtilities.invokeAndWait waits forever. If Ghidra's UI thread is blocked - most
     * often a modal dialog waiting on the user - the HTTP worker thread blocks with it,
     * and enough blocked workers exhaust the pool and wedge the whole server: even
     * endpoints that never touch the UI thread stop answering. Failing with a message
     * that names the likely cause beats hanging silently.
     */
    private void invokeAndWaitBounded(Runnable task)
            throws InterruptedException, InvocationTargetException {
        if (SwingUtilities.isEventDispatchThread()) {
            task.run();
            return;
        }
        final CountDownLatch latch = new CountDownLatch(1);
        final Throwable[] failure = new Throwable[1];
        SwingUtilities.invokeLater(() -> {
            try {
                task.run();
            } catch (Throwable t) {
                failure[0] = t;
            } finally {
                latch.countDown();
            }
        });
        if (!latch.await(SWING_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            throw new InvocationTargetException(new TimeoutException(
                "Ghidra's UI thread did not respond within " + SWING_TIMEOUT_SECONDS
                + "s. A modal dialog waiting for input in the Ghidra window is the usual "
                + "cause - dismiss it and retry."));
        }
        if (failure[0] != null) {
            throw new InvocationTargetException(failure[0]);
        }
    }

    private interface TxBodyResult {
        boolean run() throws Exception;
    }

    /**
     * Like inTransaction, but the body reports whether it changed anything. A false result
     * rolls the transaction back so a failed operation leaves no undo entry.
     */
    private String inTransactionAborting(Program program, String txName, TxBodyResult body) {
        final StringBuilder error = new StringBuilder();
        Runnable task = () -> {
            int tx = program.startTransaction(txName);
            boolean ok = false;
            try {
                ok = body.run();
            } catch (Exception e) {
                error.append(e.getClass().getSimpleName()).append(": ").append(e.getMessage());
            } finally {
                program.endTransaction(tx, ok);
            }
        };
        try {
            if (SwingUtilities.isEventDispatchThread()) {
                task.run();
            } else {
                invokeAndWaitBounded(task);
            }
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to run on Swing thread: " + e.getMessage();
        }
        return error.length() == 0 ? null : error.toString();
    }

    private interface TxBody {
        void run() throws Exception;
    }

    /**
     * Run a program-modifying block inside a transaction on the Swing thread.
     * Returns null on success, or an error message.
     */
    private String inTransaction(Program program, String txName, TxBody body) {
        final StringBuilder error = new StringBuilder();
        Runnable task = () -> {
            int tx = program.startTransaction(txName);
            boolean ok = false;
            try {
                body.run();
                ok = true;
            } catch (Exception e) {
                error.append(e.getClass().getSimpleName()).append(": ").append(e.getMessage());
            } finally {
                program.endTransaction(tx, ok);
            }
        };
        try {
            if (SwingUtilities.isEventDispatchThread()) {
                task.run();
            } else {
                invokeAndWaitBounded(task);
            }
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to run on Swing thread: " + e.getMessage();
        }
        return error.length() == 0 ? null : error.toString();
    }

    /**
     * Resolve an address string, tolerating "0x" prefixes and plain hex.
     */
    private Address resolveAddress(Program program, String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) return null;
        String s = addressStr.trim();
        try {
            Address addr = program.getAddressFactory().getAddress(s);
            if (addr != null) return addr;
        } catch (Exception ignored) {
            // fall through to the normalized attempt below
        }
        if (s.toLowerCase().startsWith("0x")) {
            s = s.substring(2);
        }
        try {
            return program.getAddressFactory().getAddress(s);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Locate a function by address string, or by name when address is absent.
     */
    private Function findFunction(Program program, String addressStr, String name) {
        if (addressStr != null && !addressStr.isEmpty()) {
            Address addr = resolveAddress(program, addressStr);
            if (addr == null) return null;
            return getFunctionForAddress(program, addr);
        }
        if (name != null && !name.isEmpty()) return uniqueFunctionNamed(program, name);
        return null;
    }

    // ==================================================================================
    // Added endpoints
    // ==================================================================================

    /**
     * Basic orientation: architecture, bitness, image base, counts.
     */
    private String getProgramInfo() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Language lang = program.getLanguage();
        StringBuilder sb = new StringBuilder();
        sb.append("name: ").append(program.getName()).append('\n');
        sb.append("executable_path: ").append(program.getExecutablePath()).append('\n');
        sb.append("format: ").append(program.getExecutableFormat()).append('\n');
        sb.append("sha256: ").append(program.getExecutableSHA256()).append('\n');
        sb.append("language: ").append(lang.getLanguageID()).append('\n');
        sb.append("processor: ").append(lang.getProcessor()).append('\n');
        sb.append("endian: ").append(lang.isBigEndian() ? "big" : "little").append('\n');
        sb.append("pointer_size: ").append(program.getDefaultPointerSize()).append('\n');
        sb.append("compiler_spec: ").append(program.getCompilerSpec().getCompilerSpecID()).append('\n');
        sb.append("image_base: ").append(program.getImageBase()).append('\n');
        sb.append("min_address: ").append(program.getMinAddress()).append('\n');
        sb.append("max_address: ").append(program.getMaxAddress()).append('\n');
        sb.append("function_count: ").append(program.getFunctionManager().getFunctionCount()).append('\n');
        sb.append("symbol_count: ").append(program.getSymbolTable().getNumSymbols()).append('\n');
        return sb.toString();
    }

    /**
     * One call that answers "what is this function?" - signature, params, locals,
     * callers, callees, referenced strings and the decompiled body with per-line
     * addresses. Replaces roughly five separate round trips.
     */
    private String getFunctionContext(String addressStr, String name, boolean decompile,
                                      boolean disassemble, int maxRefs) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = findFunction(program, addressStr, name);
        if (func == null) return "No function found for address=" + addressStr + " name=" + name;

        StringBuilder sb = new StringBuilder();
        sb.append("=== FUNCTION\n");
        sb.append("name: ").append(func.getName()).append('\n');
        sb.append("entry: ").append(func.getEntryPoint()).append('\n');
        sb.append("body: ").append(func.getBody().getMinAddress())
          .append(" - ").append(func.getBody().getMaxAddress())
          .append(" (").append(func.getBody().getNumAddresses()).append(" bytes)\n");
        sb.append("signature: ").append(func.getSignature().getPrototypeString()).append('\n');
        sb.append("calling_convention: ").append(func.getCallingConventionName()).append('\n');
        sb.append("thunk: ").append(func.isThunk()).append('\n');
        if (func.getSymbol() != null && func.getSymbol().getParentNamespace() != null) {
            sb.append("namespace: ").append(func.getSymbol().getParentNamespace().getName(true)).append('\n');
        }

        Parameter[] params = func.getParameters();
        sb.append("\n=== PARAMS (").append(params.length).append(")\n");
        for (Parameter p : params) {
            sb.append(p.getDataType().getName()).append(' ').append(p.getName())
              .append("  @").append(p.getVariableStorage()).append('\n');
        }

        Variable[] locals = func.getLocalVariables();
        sb.append("\n=== LOCALS (").append(locals.length).append(")\n");
        for (Variable v : locals) {
            sb.append(v.getDataType().getName()).append(' ').append(v.getName())
              .append("  @").append(v.getVariableStorage()).append('\n');
        }

        Set<Function> callers = func.getCallingFunctions(TaskMonitor.DUMMY);
        sb.append("\n=== CALLERS (").append(callers.size()).append(")\n");
        int n = 0;
        for (Function c : callers) {
            if (n++ >= maxRefs) { sb.append("... truncated\n"); break; }
            sb.append(c.getEntryPoint()).append('\t').append(c.getName()).append('\n');
        }

        Set<Function> callees = func.getCalledFunctions(TaskMonitor.DUMMY);
        sb.append("\n=== CALLEES (").append(callees.size()).append(")\n");
        n = 0;
        for (Function c : callees) {
            if (n++ >= maxRefs) { sb.append("... truncated\n"); break; }
            sb.append(c.getEntryPoint()).append('\t').append(c.getName()).append('\n');
        }

        sb.append("\n=== STRINGS REFERENCED\n");
        sb.append(collectReferencedStrings(program, func, maxRefs));

        if (disassemble) {
            sb.append("\n=== DISASSEMBLY\n");
            sb.append(disassembleFunction(func.getEntryPoint().toString()));
        }

        if (decompile) {
            sb.append("\n=== DECOMPILED (addr | code)\n");
            sb.append(decompileWithAddresses(func.getEntryPoint().toString()));
        }

        return sb.toString();
    }

    private String collectReferencedStrings(Program program, Function func, int maxRefs) {
        StringBuilder sb = new StringBuilder();
        Listing listing = program.getListing();
        ReferenceManager refs = program.getReferenceManager();
        int count = 0;
        InstructionIterator it = listing.getInstructions(func.getBody(), true);
        while (it.hasNext() && count < maxRefs) {
            Instruction instr = it.next();
            for (Reference ref : refs.getReferencesFrom(instr.getAddress())) {
                Data data = listing.getDataAt(ref.getToAddress());
                if (data != null && isStringData(data) && data.getValue() != null) {
                    sb.append(instr.getAddress()).append("\t")
                      .append(ref.getToAddress()).append("\t\"")
                      .append(escapeString(data.getValue().toString())).append("\"\n");
                    if (++count >= maxRefs) break;
                }
            }
        }
        if (count == 0) sb.append("(none)\n");
        return sb.toString();
    }

    /**
     * Decompiled C where every line is prefixed with the address it maps back to.
     * Without this the comment endpoints are unusable - the plain C output carries
     * no addresses, so there is nothing to anchor a comment to.
     */
    private String decompileWithAddresses(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Address addr = resolveAddress(program, addressStr);
        if (addr == null) return "Address is required";
        Function func = getFunctionForAddress(program, addr);
        if (func == null) return "No function found at or containing address " + addressStr;

        DecompileResults result = decompileCached(program, func, 60);
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed" +
                (result != null && result.getErrorMessage() != null ? ": " + result.getErrorMessage() : "");
        }

        ClangTokenGroup markup = result.getCCodeMarkup();
        if (markup == null) {
            return result.getDecompiledFunction().getC();
        }

        StringBuilder sb = new StringBuilder();
        try {
            PrettyPrinter printer = new PrettyPrinter(func, markup, null);
            for (ClangLine line : printer.getLines()) {
                Address lineAddr = null;
                for (ClangToken token : line.getAllTokens()) {
                    Address t = DecompilerUtils.getClosestAddress(program, token);
                    if (t != null && (lineAddr == null || t.compareTo(lineAddr) < 0)) {
                        lineAddr = t;
                    }
                }
                sb.append(lineAddr != null ? lineAddr.toString() : "          ")
                  .append(" | ")
                  .append(line.toString())
                  .append('\n');
            }
        } catch (Exception e) {
            return result.getDecompiledFunction().getC();
        }
        return sb.toString();
    }

    /**
     * Byte-pattern (AOB) search with wildcards, e.g. "48 8B ?? ?? 89 05" or "488B??89".
     */
    private String searchBytes(String pattern, String startStr, String endStr, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (pattern == null || pattern.trim().isEmpty()) return "Error: pattern is required";

        byte[] bytes;
        byte[] mask;
        try {
            byte[][] parsed = parseBytePattern(pattern);
            bytes = parsed[0];
            mask = parsed[1];
        } catch (IllegalArgumentException e) {
            return "Error: " + e.getMessage();
        }
        if (bytes.length == 0) return "Error: empty pattern";

        Memory memory = program.getMemory();
        Address start = startStr != null && !startStr.isEmpty()
            ? resolveAddress(program, startStr) : program.getMinAddress();
        Address end = endStr != null && !endStr.isEmpty()
            ? resolveAddress(program, endStr) : program.getMaxAddress();
        if (start == null || end == null) return "Error: bad start/end address";

        List<String> hits = new ArrayList<>();
        Address cursor = start;
        while (hits.size() < limit) {
            Address found = memory.findBytes(cursor, end, bytes, mask, true, TaskMonitor.DUMMY);
            if (found == null) break;
            Function containing = program.getFunctionManager().getFunctionContaining(found);
            MemoryBlock block = memory.getBlock(found);
            hits.add(String.format("%s\t%s\t%s",
                found,
                block != null ? block.getName() : "?",
                containing != null ? containing.getName() + "+0x" +
                    Long.toHexString(found.subtract(containing.getEntryPoint())) : "-"));
            try {
                cursor = found.add(1);
            } catch (Exception e) {
                break;
            }
        }

        if (hits.isEmpty()) return "No matches for pattern: " + pattern;
        return String.format("# %d match(es), pattern length %d bytes (addr\tblock\tfunction+off)\n",
            hits.size(), bytes.length) + String.join("\n", hits);
    }

    /**
     * Accepts "48 8B ?? 89", "48 8b ? 89", "\\x48\\x8b" or "488B??89".
     * Returns {bytes, mask} where mask 0x00 marks a wildcard.
     */
    private byte[][] parseBytePattern(String pattern) {
        String cleaned = pattern.replace("\\x", " ").replace("0x", " ").trim();
        List<Byte> values = new ArrayList<>();
        List<Byte> masks = new ArrayList<>();

        String[] tokens = cleaned.split("[\\s,]+");
        boolean spaced = tokens.length > 1;
        if (spaced) {
            for (String token : tokens) {
                if (token.isEmpty()) continue;
                if (token.equals("?") || token.equals("??") || token.equals("*")) {
                    values.add((byte) 0);
                    masks.add((byte) 0);
                } else if (token.length() == 2 || token.length() == 1) {
                    values.add((byte) Integer.parseInt(token, 16));
                    masks.add((byte) 0xFF);
                } else {
                    throw new IllegalArgumentException("bad token '" + token + "'");
                }
            }
        } else {
            String s = tokens.length == 1 ? tokens[0] : "";
            if (s.length() % 2 != 0) throw new IllegalArgumentException("odd-length hex string");
            for (int i = 0; i < s.length(); i += 2) {
                String pair = s.substring(i, i + 2);
                if (pair.equals("??") || pair.equals("**")) {
                    values.add((byte) 0);
                    masks.add((byte) 0);
                } else {
                    values.add((byte) Integer.parseInt(pair, 16));
                    masks.add((byte) 0xFF);
                }
            }
        }

        byte[] outValues = new byte[values.size()];
        byte[] outMasks = new byte[masks.size()];
        for (int i = 0; i < values.size(); i++) {
            outValues[i] = values.get(i);
            outMasks[i] = masks.get(i);
        }
        return new byte[][] { outValues, outMasks };
    }

    /**
     * Hex dump at an address.
     */
    private String readBytes(String addressStr, int length) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Address addr = resolveAddress(program, addressStr);
        if (addr == null) return "Address is required";
        if (length <= 0) return "Error: length must be positive";
        if (length > 4096) length = 4096;

        byte[] buffer = new byte[length];
        int read;
        try {
            read = program.getMemory().getBytes(addr, buffer);
        } catch (Exception e) {
            return "Error reading memory: " + e.getMessage();
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < read; i += 16) {
            StringBuilder hex = new StringBuilder();
            StringBuilder ascii = new StringBuilder();
            for (int j = 0; j < 16 && i + j < read; j++) {
                int b = buffer[i + j] & 0xFF;
                hex.append(String.format("%02X ", b));
                ascii.append(b >= 32 && b < 127 ? (char) b : '.');
            }
            sb.append(String.format("%s  %-48s |%s|\n", addr.add(i), hex.toString(), ascii));
        }
        return sb.toString();
    }

    /**
     * Disassemble N instructions from an address, whether or not a function exists there.
     */
    private String disassembleRange(String addressStr, int count) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Address addr = resolveAddress(program, addressStr);
        if (addr == null) return "Address is required";
        if (count <= 0 || count > 2000) count = 40;

        StringBuilder sb = new StringBuilder();
        Listing listing = program.getListing();
        InstructionIterator it = listing.getInstructions(addr, true);
        int n = 0;
        while (it.hasNext() && n++ < count) {
            Instruction instr = it.next();
            String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
            sb.append(instr.getAddress()).append(": ").append(instr.toString());
            if (comment != null) sb.append("  ; ").append(comment);
            sb.append('\n');
        }
        if (n == 0) return "No instructions at " + addressStr + " (undefined bytes?)";
        return sb.toString();
    }

    private String getCallers(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Function func = findFunction(program, addressStr, null);
        if (func == null) return "No function found at " + addressStr;

        List<String> lines = new ArrayList<>();
        for (Function f : func.getCallingFunctions(TaskMonitor.DUMMY)) {
            lines.add(f.getEntryPoint() + "\t" + f.getName());
        }
        Collections.sort(lines);
        if (lines.isEmpty()) return "No callers of " + func.getName();
        return paginateList(lines, offset, limit);
    }

    private String getCallees(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Function func = findFunction(program, addressStr, null);
        if (func == null) return "No function found at " + addressStr;

        List<String> lines = new ArrayList<>();
        for (Function f : func.getCalledFunctions(TaskMonitor.DUMMY)) {
            lines.add(f.getEntryPoint() + "\t" + f.getName());
        }
        Collections.sort(lines);
        if (lines.isEmpty()) return "No callees of " + func.getName();
        return paginateList(lines, offset, limit);
    }

    /**
     * Depth-limited call tree, rendered as indented text.
     */
    private String callGraph(String addressStr, int depth, boolean down, int maxNodes) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Function root = findFunction(program, addressStr, null);
        if (root == null) return "No function found at " + addressStr;
        if (depth < 1) depth = 1;
        if (depth > 5) depth = 5;

        StringBuilder sb = new StringBuilder();
        Set<Function> visited = new HashSet<>();
        int[] budget = new int[] { maxNodes };
        walkCallGraph(root, 0, depth, down, visited, sb, budget);
        if (budget[0] <= 0) sb.append("... node budget exhausted\n");
        return sb.toString();
    }

    private void walkCallGraph(Function func, int level, int maxDepth, boolean down,
                               Set<Function> visited, StringBuilder sb, int[] budget) {
        if (budget[0]-- <= 0) return;
        sb.append("  ".repeat(level)).append(func.getEntryPoint())
          .append(' ').append(func.getName());
        if (!visited.add(func)) {
            sb.append("  (seen)\n");
            return;
        }
        sb.append('\n');
        if (level >= maxDepth) return;
        Set<Function> next = down ? func.getCalledFunctions(TaskMonitor.DUMMY)
                                  : func.getCallingFunctions(TaskMonitor.DUMMY);
        List<Function> sorted = new ArrayList<>(next);
        sorted.sort(Comparator.comparing(f -> f.getEntryPoint()));
        for (Function child : sorted) {
            walkCallGraph(child, level + 1, maxDepth, down, visited, sb, budget);
        }
    }

    /**
     * Symbol search. type: function | label | data | class | any (default any).
     * The filter is a substring match, or a regex when wrapped in slashes: /re/
     */
    private String listSymbols(String filter, String type, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        java.util.regex.Pattern regex = null;
        String needle = null;
        if (filter != null && filter.length() > 1 && filter.startsWith("/") && filter.endsWith("/")) {
            try {
                regex = java.util.regex.Pattern.compile(filter.substring(1, filter.length() - 1));
            } catch (Exception e) {
                return "Error: bad regex - " + e.getMessage();
            }
        } else if (filter != null && !filter.isEmpty()) {
            needle = filter.toLowerCase();
        }

        String wanted = (type == null || type.isEmpty()) ? "any" : type.toLowerCase();
        List<String> lines = new ArrayList<>();
        SymbolIterator it = program.getSymbolTable().getAllSymbols(true);
        while (it.hasNext()) {
            Symbol symbol = it.next();
            String kind = symbol.getSymbolType().toString().toLowerCase();
            if (!wanted.equals("any") && !kind.contains(wanted)) continue;
            // Match what is displayed. Filtering on the short name while printing the
            // namespace-qualified one means you cannot search for what you can see:
            // "CSource::vftable" is right there in the output and matches nothing.
            String symName = symbol.getName(true);
            if (regex != null && !regex.matcher(symName).find()) continue;
            if (needle != null && !symName.toLowerCase().contains(needle)) continue;
            lines.add(String.format("%s\t%s\t%s", symbol.getAddress(), kind, symName));
        }
        if (lines.isEmpty()) return "No symbols matching filter=" + filter + " type=" + type;
        return String.format("# %d match(es) (addr\ttype\tname)\n", lines.size())
            + paginateList(lines, offset, limit);
    }

    private String listDataTypes(String filter, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        String needle = (filter == null || filter.isEmpty()) ? null : filter.toLowerCase();
        List<String> lines = new ArrayList<>();
        Iterator<DataType> it = program.getDataTypeManager().getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            if (needle != null && !dt.getName().toLowerCase().contains(needle)) continue;
            lines.add(String.format("%s\t%d\t%s", dt.getName(), dt.getLength(), dt.getPathName()));
        }
        Collections.sort(lines);
        if (lines.isEmpty()) return "No data types matching '" + filter + "'";
        return String.format("# %d match(es) (name\tsize\tpath)\n", lines.size())
            + paginateList(lines, offset, limit);
    }

    /**
     * Full layout of a struct/union - offsets, sizes, field names.
     */
    private String getTypeInfo(String typeName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (typeName == null || typeName.isEmpty()) return "Error: name is required";

        DataType dt = findDataTypeByNameInAllCategories(program.getDataTypeManager(), typeName);
        if (dt == null) return "Type not found: " + typeName;

        StringBuilder sb = new StringBuilder();
        sb.append("name: ").append(dt.getName()).append('\n');
        sb.append("path: ").append(dt.getPathName()).append('\n');
        sb.append("size: ").append(dt.getLength()).append('\n');
        sb.append("kind: ").append(dt.getClass().getSimpleName()).append('\n');

        if (dt instanceof Structure) {
            Structure struct = (Structure) dt;
            sb.append("\n# offset\tsize\ttype\tfield\tcomment\n");
            for (DataTypeComponent comp : struct.getDefinedComponents()) {
                sb.append(String.format("0x%X\t%d\t%s\t%s\t%s\n",
                    comp.getOffset(),
                    comp.getLength(),
                    comp.getDataType().getName(),
                    comp.getFieldName() == null ? "-" : comp.getFieldName(),
                    comp.getComment() == null ? "" : comp.getComment()));
            }
        }
        return sb.toString();
    }

    /**
     * Walk a pointer table and resolve each slot to a function. Useful for vtables.
     */
    private String getVtable(String addressStr, int count) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Address addr = resolveAddress(program, addressStr);
        if (addr == null) return "Address is required";
        if (count <= 0 || count > 512) count = 32;

        int ptrSize = program.getDefaultPointerSize();
        Memory memory = program.getMemory();
        StringBuilder sb = new StringBuilder();
        sb.append("# index\tslot_addr\ttarget\tname\n");

        for (int i = 0; i < count; i++) {
            Address slot;
            try {
                slot = addr.add((long) i * ptrSize);
            } catch (Exception e) {
                break;
            }
            long value;
            try {
                value = ptrSize == 8 ? memory.getLong(slot) : (memory.getInt(slot) & 0xFFFFFFFFL);
            } catch (Exception e) {
                break;
            }
            if (value == 0) {
                sb.append(i).append('\t').append(slot).append("\t0\t(null - end of table?)\n");
                break;
            }
            Address target;
            try {
                target = program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
            } catch (Exception e) {
                break;
            }
            if (!memory.contains(target)) {
                sb.append(i).append('\t').append(slot).append('\t')
                  .append(Long.toHexString(value)).append("\t(not mapped - end of table?)\n");
                break;
            }
            Function func = program.getFunctionManager().getFunctionAt(target);
            sb.append(i).append('\t').append(slot).append('\t').append(target).append('\t')
              .append(func != null ? func.getName() : "(no function defined)").append('\n');
        }
        return sb.toString();
    }

    /**
     * Grep the decompiled output of many functions at once. Scope it with name_filter
     * on large binaries - decompiling everything is slow.
     */
    private String searchDecompiled(String query, String nameFilter, int maxFunctions, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (query == null || query.isEmpty()) return "Error: query is required";

        String needle = query.toLowerCase();
        String nameNeedle = (nameFilter == null || nameFilter.isEmpty())
            ? null : nameFilter.toLowerCase();

        List<String> hits = new ArrayList<>();
        int examined = 0;
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (examined >= maxFunctions || hits.size() >= limit) break;
            if (nameNeedle != null && !func.getName().toLowerCase().contains(nameNeedle)) continue;
            if (func.isThunk()) continue;
            examined++;

            DecompileResults result = decompileCached(program, func, 30);
            if (result == null || !result.decompileCompleted()) continue;
            String code = result.getDecompiledFunction().getC();
            if (code == null) continue;

            String[] lines = code.split("\n");
            for (String line : lines) {
                if (line.toLowerCase().contains(needle)) {
                    hits.add(String.format("%s\t%s\t%s",
                        func.getEntryPoint(), func.getName(), line.trim()));
                    if (hits.size() >= limit) break;
                }
            }
        }

        if (hits.isEmpty()) {
            return String.format("No matches for '%s' (examined %d function(s))", query, examined);
        }
        return String.format("# %d hit(s) after examining %d function(s) (addr\tfunction\tline)\n",
            hits.size(), examined) + String.join("\n", hits);
    }

    /**
     * Create a structure. fields is ";"-separated, each "type:name" (sequential layout)
     * or "offset:type:name" (explicit offsets, allows gaps).
     * Example: "0:int:health;8:float:posX;0xC:float:posY"
     */
    private String createStruct(String name, String fields, boolean packed) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Error: name is required";
        if (fields == null || fields.trim().isEmpty()) return "Error: fields is required";

        DataTypeManager dtm = program.getDataTypeManager();
        String[] entries = fields.split("[;\n]");

        // First pass: parse everything so we fail before opening a transaction.
        List<int[]> offsets = new ArrayList<>();
        List<DataType> types = new ArrayList<>();
        List<String> names = new ArrayList<>();
        boolean explicitOffsets = false;
        int cursor = 0;

        for (String entry : entries) {
            String e = entry.trim();
            if (e.isEmpty()) continue;
            String[] parts = e.split(":");
            String typeName;
            String fieldName;
            int offset;
            if (parts.length >= 3) {
                explicitOffsets = true;
                try {
                    String off = parts[0].trim();
                    offset = off.toLowerCase().startsWith("0x")
                        ? Integer.parseInt(off.substring(2), 16) : Integer.parseInt(off);
                } catch (NumberFormatException ex) {
                    return "Error: bad offset in '" + e + "'";
                }
                typeName = parts[1].trim();
                fieldName = parts[2].trim();
            } else if (parts.length == 2) {
                offset = cursor;
                typeName = parts[0].trim();
                fieldName = parts[1].trim();
            } else {
                return "Error: bad field spec '" + e + "' (want type:name or offset:type:name)";
            }
            DataType dt = resolveDataType(dtm, typeName);
            if (dt == null) return "Error: unknown type '" + typeName + "'";
            offsets.add(new int[] { offset });
            types.add(dt);
            names.add(fieldName);
            cursor = offset + Math.max(1, dt.getLength());
        }
        if (types.isEmpty()) return "Error: no valid fields parsed";

        int totalSize = 0;
        for (int i = 0; i < types.size(); i++) {
            totalSize = Math.max(totalSize, offsets.get(i)[0] + Math.max(1, types.get(i).getLength()));
        }

        final boolean useOffsets = explicitOffsets;
        final int structSize = totalSize;
        final StringBuilder created = new StringBuilder();

        String error = inTransaction(program, "GhidraMCP create struct " + name, () -> {
            StructureDataType struct = new StructureDataType(new CategoryPath("/GhidraMCP"),
                name, useOffsets ? structSize : 0, dtm);
            if (packed) struct.setPackingEnabled(true);
            for (int i = 0; i < types.size(); i++) {
                DataType dt = types.get(i);
                int len = Math.max(1, dt.getLength());
                if (useOffsets) {
                    struct.replaceAtOffset(offsets.get(i)[0], dt, len, names.get(i), null);
                } else {
                    struct.add(dt, len, names.get(i), null);
                }
            }
            DataType added = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
            created.append(added.getPathName()).append(" (").append(added.getLength()).append(" bytes)");
        });

        if (error != null) return "Failed to create struct: " + error;
        return "Created " + created;
    }

    /**
     * Define data of a named type at an address (optionally as an array of `count`).
     */
    private String applyDataTypeAt(String addressStr, String typeName, int count) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Address addr = resolveAddress(program, addressStr);
        if (addr == null) return "Address is required";
        if (typeName == null || typeName.isEmpty()) return "Error: type_name is required";
        if (count < 1) count = 1;

        DataType dt = resolveDataType(program.getDataTypeManager(), typeName);
        if (dt == null) return "Error: unknown type '" + typeName + "'";
        int unit = Math.max(1, dt.getLength());
        final int total = unit * count;
        final DataType finalType = dt;
        final int finalCount = count;

        String error = inTransaction(program, "GhidraMCP apply data type", () -> {
            Listing listing = program.getListing();
            listing.clearCodeUnits(addr, addr.add(total - 1), false);
            for (int i = 0; i < finalCount; i++) {
                listing.createData(addr.add((long) i * unit), finalType);
            }
        });

        if (error != null) return "Failed to apply data type: " + error;
        return String.format("Applied %s x%d at %s (%d bytes)", dt.getName(), count, addr, total);
    }

    /**
     * Define a function at an address that Ghidra left as raw code.
     */
    private String createFunctionAt(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Address addr = resolveAddress(program, addressStr);
        if (addr == null) return "Address is required";

        Function existing = program.getFunctionManager().getFunctionAt(addr);
        if (existing != null) return "Function already exists at " + addr + ": " + existing.getName();
        Function containing = program.getFunctionManager().getFunctionContaining(addr);
        if (containing != null) {
            return "Error: " + addr + " is already inside " + containing.getName() + " (entry "
                + containing.getEntryPoint() + "). Split it in the GUI if that is wrong.";
        }

        // A failed command must not leave an empty transaction on the undo stack: the log
        // of what changed is only useful if everything in it actually changed something.
        final AtomicBoolean ok = new AtomicBoolean(false);
        final StringBuilder cmdError = new StringBuilder();
        String error = inTransactionAborting(program, "GhidraMCP create function", () -> {
            CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
            ok.set(cmd.applyTo(program, TaskMonitor.DUMMY));
            if (!ok.get() && cmd.getStatusMsg() != null) cmdError.append(cmd.getStatusMsg());
            return ok.get();
        });
        if (error != null) return "Failed to create function: " + error;
        if (!ok.get()) {
            return "Ghidra could not create a function at " + addr
                + (cmdError.length() > 0 ? ": " + cmdError : " (are the bytes code?)")
                + " - nothing was written.";
        }

        Function created = program.getFunctionManager().getFunctionAt(addr);
        if (created == null) return "Function creation reported success but none found at " + addr;

        if (name != null && !name.isEmpty()) {
            String renameError = inTransaction(program, "GhidraMCP name new function",
                () -> created.setName(name, SourceType.USER_DEFINED));
            if (renameError != null) {
                return "Created " + created.getName() + " at " + addr + " but rename failed: " + renameError;
            }
        }
        return "Created function " + program.getFunctionManager().getFunctionAt(addr).getName()
            + " at " + addr;
    }

    /**
     * Rename many things in one request/transaction. entries is newline-separated
     * "address=NewName". kind is function | data | label (default function).
     */
    private String batchRename(String kind, String entries) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (entries == null || entries.trim().isEmpty()) return "Error: entries is required";

        String mode = (kind == null || kind.isEmpty()) ? "function" : kind.toLowerCase();
        List<String[]> pairs = new ArrayList<>();
        for (String line : entries.split("[\n;]")) {
            String l = line.trim();
            if (l.isEmpty()) continue;
            int eq = l.indexOf('=');
            if (eq <= 0) return "Error: bad entry '" + l + "' (want address=NewName)";
            pairs.add(new String[] { l.substring(0, eq).trim(), l.substring(eq + 1).trim() });
        }
        if (pairs.isEmpty()) return "Error: no entries parsed";

        final List<String> results = new ArrayList<>();
        String error = inTransaction(program, "GhidraMCP batch rename", () -> {
            SymbolTable symbolTable = program.getSymbolTable();
            for (String[] pair : pairs) {
                Address addr = resolveAddress(program, pair[0]);
                if (addr == null) {
                    results.add(pair[0] + "\tFAIL\tbad address");
                    continue;
                }
                try {
                    if (mode.startsWith("func")) {
                        Function func = program.getFunctionManager().getFunctionAt(addr);
                        if (func == null) {
                            results.add(pair[0] + "\tFAIL\tno function at address");
                            continue;
                        }
                        String old = func.getName();
                        func.setName(pair[1], SourceType.USER_DEFINED);
                        results.add(pair[0] + "\tOK\t" + old + " -> " + pair[1]);
                    } else {
                        Symbol symbol = symbolTable.getPrimarySymbol(addr);
                        if (symbol == null) {
                            symbolTable.createLabel(addr, pair[1], SourceType.USER_DEFINED);
                            results.add(pair[0] + "\tOK\tcreated label " + pair[1]);
                        } else {
                            String old = symbol.getName();
                            symbol.setName(pair[1], SourceType.USER_DEFINED);
                            results.add(pair[0] + "\tOK\t" + old + " -> " + pair[1]);
                        }
                    }
                } catch (Exception e) {
                    results.add(pair[0] + "\tFAIL\t" + e.getMessage());
                }
            }
        });

        if (error != null) return "Batch rename failed: " + error;
        long okCount = results.stream().filter(r -> r.contains("\tOK\t")).count();
        return String.format("# %d/%d renamed\n", okCount, pairs.size())
            + String.join("\n", results);
    }

    // ==================================================================================
    // Response plumbing
    // ==================================================================================

    /**
     * Map the plugin's plain-text failure strings onto HTTP status codes so a client
     * can tell "this is your answer" from "this went wrong". Previously every reply
     * was 200 and the caller had to guess.
     */

    // ==================================================================================
    // Session recall: read back what previous sessions wrote
    // ==================================================================================

    private static final int[] COMMENT_TYPES = {
        CodeUnit.PLATE_COMMENT, CodeUnit.PRE_COMMENT, CodeUnit.EOL_COMMENT,
        CodeUnit.POST_COMMENT, CodeUnit.REPEATABLE_COMMENT
    };
    private static final String[] COMMENT_NAMES = { "plate", "pre", "eol", "post", "repeatable" };

    /**
     * Every user-defined symbol and every comment in the program. This is the
     * "what did I already work out" query - without it, analysis notes written by an
     * earlier session are invisible to the next one.
     */
    private String listAnnotations(String filter, String kind, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        String k = (kind == null || kind.isEmpty()) ? "all" : kind.toLowerCase();
        boolean wantSymbols = k.equals("all") || k.startsWith("symbol");
        boolean wantComments = k.equals("all") || k.startsWith("comment");
        String f = (filter == null || filter.isEmpty()) ? null : filter.toLowerCase();

        List<String> out = new ArrayList<>();

        if (wantSymbols) {
            SymbolIterator it = program.getSymbolTable().getSymbolIterator();
            while (it.hasNext()) {
                Symbol s = it.next();
                if (s == null || s.getSource() != SourceType.USER_DEFINED) continue;
                String type = s.getSymbolType() != null ? s.getSymbolType().toString() : "?";
                String line = String.format("%s\tsymbol:%s\t%s", s.getAddress(), type, s.getName(true));
                if (f == null || line.toLowerCase().contains(f)) out.add(line);
            }
        }

        if (wantComments) {
            Listing listing = program.getListing();
            for (int i = 0; i < COMMENT_TYPES.length; i++) {
                AddressIterator ai = listing.getCommentAddressIterator(
                    COMMENT_TYPES[i], program.getMemory(), true);
                while (ai.hasNext()) {
                    Address a = ai.next();
                    String c = listing.getComment(COMMENT_TYPES[i], a);
                    if (c == null) continue;
                    Function fn = program.getFunctionManager().getFunctionContaining(a);
                    String line = String.format("%s\tcomment:%s\t%s\t%s", a, COMMENT_NAMES[i],
                        fn != null ? fn.getName() : "-", c.replace("\n", " | "));
                    if (f == null || line.toLowerCase().contains(f)) out.add(line);
                }
            }
        }

        if (out.isEmpty()) {
            return "No annotations found" + (f != null ? " matching: " + filter : "")
                + " (nothing has been renamed or commented by hand yet)";
        }
        Collections.sort(out);
        String header = String.format("# %d annotation(s) (address\tkind\tcontext\tvalue)\n", out.size());
        return header + paginateList(out, offset, limit);
    }

    /**
     * All comments attached to one function, including the function's own comment.
     */
    private String getComments(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Function func = findFunction(program, addressStr, name);
        if (func == null) return "No function found";

        Listing listing = program.getListing();
        StringBuilder sb = new StringBuilder();
        sb.append("# comments in ").append(func.getName())
          .append(" @ ").append(func.getEntryPoint()).append('\n');

        if (func.getComment() != null && !func.getComment().isEmpty()) {
            sb.append(func.getEntryPoint()).append("\tfunction\t")
              .append(func.getComment().replace("\n", " | ")).append('\n');
        }

        int count = 0;
        for (int i = 0; i < COMMENT_TYPES.length; i++) {
            AddressIterator ai = listing.getCommentAddressIterator(
                COMMENT_TYPES[i], func.getBody(), true);
            while (ai.hasNext()) {
                Address a = ai.next();
                String c = listing.getComment(COMMENT_TYPES[i], a);
                if (c == null) continue;
                sb.append(a).append('\t').append(COMMENT_NAMES[i]).append('\t')
                  .append(c.replace("\n", " | ")).append('\n');
                count++;
            }
        }
        if (count == 0 && (func.getComment() == null || func.getComment().isEmpty())) {
            return "No comments in " + func.getName();
        }
        return sb.toString();
    }

    // ==================================================================================
    // Type construction
    // ==================================================================================

    /**
     * Run a block of C through Ghidra's header parser and into the program's type
     * manager. Handles structs, unions, typedefs and enums in one shot, including
     * types that reference each other - which create_struct cannot express.
     */
    private String parseCHeader(String source, String args) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (source == null || source.trim().isEmpty()) return "Error: source is required";

        DataTypeManager dtm = program.getDataTypeManager();

        // The parser names the category after the file, so the file gets a stable name in
        // a throwaway directory rather than a randomised one - otherwise every call files
        // its types under a different "/ghidramcp_8417362....h" category.
        java.io.File tmp;
        java.io.File tmpDir = null;
        try {
            tmpDir = java.nio.file.Files.createTempDirectory("ghidramcp").toFile();
            tmp = new java.io.File(tmpDir, "ghidramcp.h");
            java.nio.file.Files.write(tmp.toPath(), source.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            return "Error: could not write temporary header: " + e.getMessage();
        }

        Set<String> before = snapshotTypeNames(dtm);
        String[] parseArgs = (args == null || args.trim().isEmpty())
            ? new String[0] : args.trim().split("\\s+");

        final StringBuilder messages = new StringBuilder();
        final AtomicBoolean ok = new AtomicBoolean(false);

        String txError = inTransaction(program, "Parse C header", () -> {
            CParserUtils.CParseResults results = CParserUtils.parseHeaderFiles(
                new DataTypeManager[0],
                new String[] { tmp.getAbsolutePath() },
                parseArgs,
                dtm,
                TaskMonitor.DUMMY);
            ok.set(results.successful());
            String cpp = results.cppParseMessages();
            String c = results.cParseMessages();
            if (cpp != null && !cpp.trim().isEmpty()) messages.append(cpp.trim()).append('\n');
            if (c != null && !c.trim().isEmpty()) messages.append(c.trim()).append('\n');
        });

        tmp.delete();
        if (tmpDir != null) tmpDir.delete();

        if (txError != null) {
            return "Error: header parse failed: " + txError
                + (messages.length() > 0 ? "\n" + messages : "");
        }

        Set<String> after = snapshotTypeNames(dtm);
        after.removeAll(before);

        StringBuilder sb = new StringBuilder();
        sb.append(ok.get() ? "Parsed successfully. " : "Parser reported problems. ");
        sb.append(after.size()).append(" new type(s) in the program type manager.\n");
        if (!after.isEmpty()) {
            List<String> added = new ArrayList<>(after);
            Collections.sort(added);
            int shown = Math.min(added.size(), 200);
            for (int i = 0; i < shown; i++) sb.append("  ").append(added.get(i)).append('\n');
            if (added.size() > shown) {
                sb.append("  ... ").append(added.size() - shown).append(" more\n");
            }
        }
        if (messages.length() > 0) {
            sb.append("--- parser messages ---\n").append(messages);
        }
        return sb.toString();
    }

    private Set<String> snapshotTypeNames(DataTypeManager dtm) {
        Set<String> names = new HashSet<>();
        Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            if (dt != null) names.add(dt.getPathName());
        }
        return names;
    }

    /**
     * Create an enum. Turns "if (state == 3)" into "if (state == EState_Dying)"
     * everywhere the enum is applied, which no amount of renaming can do.
     */
    private String createEnumType(String name, int size, String values, String category) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Error: name is required";
        if (values == null || values.trim().isEmpty()) return "Error: values is required";
        if (size != 1 && size != 2 && size != 4 && size != 8) size = 4;

        CategoryPath path = (category == null || category.isEmpty())
            ? CategoryPath.ROOT : new CategoryPath(category);
        EnumDataType e = new EnumDataType(path, name, size, program.getDataTypeManager());

        long next = 0;
        int added = 0;
        for (String entry : values.split("[;,\n]")) {
            String t = entry.trim();
            if (t.isEmpty()) continue;
            String memberName;
            long memberValue;
            int eq = t.indexOf('=');
            if (eq >= 0) {
                memberName = t.substring(0, eq).trim();
                String v = t.substring(eq + 1).trim();
                try {
                    memberValue = v.toLowerCase().startsWith("0x")
                        ? Long.parseLong(v.substring(2), 16) : Long.parseLong(v);
                } catch (NumberFormatException nfe) {
                    return "Error: bad value '" + v + "' for member '" + memberName + "'";
                }
            } else {
                memberName = t;
                memberValue = next;
            }
            if (memberName.isEmpty()) return "Error: empty member name in: " + t;
            e.add(memberName, memberValue);
            next = memberValue + 1;
            added++;
        }
        if (added == 0) return "Error: no members parsed from values";

        final int finalAdded = added;
        final StringBuilder result = new StringBuilder();
        String err = inTransaction(program, "Create enum " + name, () -> {
            DataType created = program.getDataTypeManager()
                .addDataType(e, DataTypeConflictHandler.REPLACE_HANDLER);
            result.append("Created enum ").append(created.getPathName())
                  .append(" (").append(finalAdded).append(" members, ")
                  .append(created.getLength()).append(" bytes)");
        });
        if (err != null) return "Error: " + err;
        return result.toString();
    }

    /**
     * Attach a name to a constant operand. Either give an explicit name, or give
     * enum_name and let the matching member supply it.
     */
    private String setEquate(String addressStr, int opIndex, String name, String valueStr,
                             String enumName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Address addr = resolveAddress(program, addressStr);
        if (addr == null) return "Address is required";

        Instruction instr = program.getListing().getInstructionAt(addr);
        if (instr == null) return "Error: no instruction at " + addr;
        if (opIndex < 0 || opIndex >= instr.getNumOperands()) {
            return "Error: operand " + opIndex + " out of range for " + instr
                + " (" + instr.getNumOperands() + " operands)";
        }

        Long value = null;
        if (valueStr != null && !valueStr.isEmpty()) {
            try {
                value = valueStr.toLowerCase().startsWith("0x")
                    ? Long.parseLong(valueStr.substring(2), 16) : Long.parseLong(valueStr);
            } catch (NumberFormatException e) {
                return "Error: bad value: " + valueStr;
            }
        } else {
            for (Object o : instr.getOpObjects(opIndex)) {
                if (o instanceof Scalar) { value = ((Scalar) o).getValue(); break; }
            }
            if (value == null) {
                return "Error: operand " + opIndex + " of " + instr + " has no scalar to equate";
            }
        }

        String equateName = name;
        if ((equateName == null || equateName.isEmpty()) && enumName != null && !enumName.isEmpty()) {
            DataType dt = findDataTypeByNameInAllCategories(program.getDataTypeManager(), enumName);
            if (!(dt instanceof ghidra.program.model.data.Enum)) {
                return "Type not found (or not an enum): " + enumName;
            }
            ghidra.program.model.data.Enum en = (ghidra.program.model.data.Enum) dt;
            String member = en.getName(value);
            if (member == null) {
                return "Error: enum " + enumName + " has no member with value " + value
                    + " (0x" + Long.toHexString(value) + ")";
            }
            equateName = en.getName() + "_" + member;
        }
        if (equateName == null || equateName.isEmpty()) {
            return "Error: either name or enum_name is required";
        }

        final long finalValue = value;
        final String finalName = equateName;
        final StringBuilder result = new StringBuilder();
        String err = inTransaction(program, "Set equate", () -> {
            EquateTable table = program.getEquateTable();
            Equate eq = table.getEquate(finalName);
            if (eq == null) {
                eq = table.createEquate(finalName, finalValue);
            } else if (eq.getValue() != finalValue) {
                throw new IllegalStateException("equate '" + finalName + "' already exists with value "
                    + eq.getValue());
            }
            eq.addReference(addr, opIndex);
            result.append("Equate ").append(finalName).append(" = ").append(finalValue)
                  .append(" (0x").append(Long.toHexString(finalValue)).append(") applied at ")
                  .append(addr).append(" operand ").append(opIndex);
        });
        if (err != null) return "Error: " + err;
        return result.toString();
    }

    // ==================================================================================
    // Struct recovery from access patterns
    // ==================================================================================

    private static class FieldEvidence {
        int size = 0;
        int loads = 0;
        int stores = 0;
        boolean floatUse = false;
        boolean callThrough = false;
    }

    /**
     * Infer a struct from how a pointer is actually used. Walks the decompiler's
     * p-code from a parameter or local, collecting every offset that gets loaded,
     * stored or called through, and builds a type from the result.
     *
     * This is the thing that otherwise costs a full read of the decompiled body plus
     * manual bookkeeping of every "*(int *)(param_1 + 0x64)".
     */
    private String autoCreateStruct(String addressStr, String funcName, String variable,
                                    int paramIndex, String structName, boolean apply) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Function func = findFunction(program, addressStr, funcName);
        if (func == null) return "No function found";

        DecompileResults results = decompileCached(program, func, 60);
        if (results == null || !results.decompileCompleted()) {
            return "Decompilation failed for " + func.getName();
        }
        HighFunction hf = results.getHighFunction();
        if (hf == null) return "Decompilation failed: no high function for " + func.getName();

        LocalSymbolMap lsm = hf.getLocalSymbolMap();
        HighSymbol target = null;
        if (variable != null && !variable.isEmpty()) {
            Iterator<HighSymbol> it = lsm.getSymbols();
            while (it.hasNext()) {
                HighSymbol s = it.next();
                if (s.getName().equals(variable)) { target = s; break; }
            }
            if (target == null) return "Error: no variable named '" + variable + "' in " + func.getName();
        } else {
            if (paramIndex < 0) paramIndex = 0;
            if (paramIndex >= lsm.getNumParams()) {
                return "Error: parameter index " + paramIndex + " out of range ("
                    + lsm.getNumParams() + " parameters)";
            }
            target = lsm.getParamSymbol(paramIndex);
            if (target == null) return "Error: no parameter at index " + paramIndex;
        }

        HighVariable hv = target.getHighVariable();
        if (hv == null) return "Error: no p-code variable for '" + target.getName() + "'";

        Map<Long, FieldEvidence> fields = new TreeMap<>();
        Set<String> visited = new HashSet<>();
        Deque<Object[]> work = new ArrayDeque<>();
        for (Varnode vn : hv.getInstances()) work.push(new Object[] { vn, 0L });

        int guard = 0;
        while (!work.isEmpty() && guard++ < 20000) {
            Object[] item = work.pop();
            Varnode vn = (Varnode) item[0];
            long base = (Long) item[1];
            // Key on pointer *and* offset: the same varnode reached at two different
            // offsets describes two different fields.
            if (vn == null || !visited.add(System.identityHashCode(vn) + "@" + base)) continue;

            Iterator<PcodeOp> descIt = vn.getDescendants();
            while (descIt.hasNext()) {
                PcodeOp op = descIt.next();
                int opc = op.getOpcode();
                Varnode out = op.getOutput();

                switch (opc) {
                    case PcodeOp.PTRSUB:
                    case PcodeOp.INT_ADD: {
                        Varnode other = op.getInput(0) == vn ? op.getInput(1) : op.getInput(0);
                        if (other != null && other.isConstant() && out != null) {
                            work.push(new Object[] { out, base + other.getOffset() });
                        } else if (out != null) {
                            work.push(new Object[] { out, base });
                        }
                        break;
                    }
                    case PcodeOp.PTRADD: {
                        Varnode idx = op.getInput(1);
                        Varnode elem = op.getInput(2);
                        if (out != null && idx != null && idx.isConstant()
                            && elem != null && elem.isConstant()) {
                            work.push(new Object[] { out, base + idx.getOffset() * elem.getOffset() });
                        } else if (out != null) {
                            work.push(new Object[] { out, base });
                        }
                        break;
                    }
                    case PcodeOp.CAST:
                    case PcodeOp.COPY:
                    case PcodeOp.MULTIEQUAL:
                    case PcodeOp.INT_ZEXT:
                    case PcodeOp.INT_SEXT: {
                        if (out != null) work.push(new Object[] { out, base });
                        break;
                    }
                    case PcodeOp.LOAD: {
                        if (op.getInput(1) != vn) break;
                        FieldEvidence fe = fields.computeIfAbsent(base, x -> new FieldEvidence());
                        fe.loads++;
                        if (out != null) {
                            fe.size = Math.max(fe.size, out.getSize());
                            if (usedAsFloat(out)) fe.floatUse = true;
                            if (calledThrough(out)) fe.callThrough = true;
                        }
                        break;
                    }
                    case PcodeOp.STORE: {
                        if (op.getInput(1) == vn) {
                            FieldEvidence fe = fields.computeIfAbsent(base, x -> new FieldEvidence());
                            fe.stores++;
                            Varnode val = op.getInput(2);
                            if (val != null) {
                                fe.size = Math.max(fe.size, val.getSize());
                                if (val.getDef() != null && isFloatOp(val.getDef().getOpcode())) {
                                    fe.floatUse = true;
                                }
                            }
                        }
                        break;
                    }
                    case PcodeOp.CALLIND: {
                        if (op.getInput(0) == vn) {
                            FieldEvidence fe = fields.computeIfAbsent(base, x -> new FieldEvidence());
                            fe.callThrough = true;
                            fe.size = Math.max(fe.size, program.getDefaultPointerSize());
                        }
                        break;
                    }
                    default:
                        break;
                }
            }
        }

        if (fields.isEmpty()) {
            List<String> vars = new ArrayList<>();
            Iterator<HighSymbol> all = lsm.getSymbols();
            Set<String> seenNames = new LinkedHashSet<>();
            while (all.hasNext() && vars.size() < 40) {
                HighSymbol s2 = all.next();
                // Equates appear in the symbol map too; they are named constants, not
                // variables, and listing them as retry candidates is just noise.
                if (s2.getHighVariable() == null) continue;
                if (!seenNames.add(s2.getName())) continue;
                DataType dt = s2.getDataType();
                vars.add(s2.getName() + " : " + (dt != null ? dt.getName() : "?"));
            }
            return "No field accesses found through '" + target.getName() + "' in "
                + func.getName() + ".\n"
                + "Prototype: " + func.getSignature().getPrototypeString() + "\n"
                + (func.getSignatureSource() == SourceType.DEFAULT
                    ? "The signature is still the analyser's default guess, so the decompiler "
                      + "may not model the object pointer as a parameter at all. Set it with "
                      + "set_function_prototype first, or name a variable below.\n"
                    : "")
                + "Variables in this function:\n  "
                + (vars.isEmpty() ? "(none)" : String.join("\n  ", vars))
                + "\nRe-run with variable=<one of these>.";
        }

        String typeName = (structName == null || structName.isEmpty())
            ? func.getName() + "_" + target.getName() + "_t" : structName;

        StringBuilder report = new StringBuilder();
        report.append("# ").append(fields.size()).append(" field(s) inferred from ")
              .append(target.getName()).append(" in ").append(func.getName()).append('\n');
        report.append("# offset\tsize\ttype\tloads\tstores\tnote\n");

        // Size the structure up front. Growing it incrementally trips over an empty
        // StructureDataType reporting getLength() == 1, which cost the first field one
        // byte and silently dropped it - usually the most interesting one.
        int totalSize = 0;
        for (Map.Entry<Long, FieldEvidence> e : fields.entrySet()) {
            long off = e.getKey();
            if (off < 0) continue;
            int sz = e.getValue().size > 0 ? e.getValue().size : 1;
            if (off + sz > totalSize && off + sz <= Integer.MAX_VALUE) {
                totalSize = (int) (off + sz);
            }
        }
        StructureDataType struct = new StructureDataType(new CategoryPath("/GhidraMCP"), typeName,
            totalSize, program.getDataTypeManager());

        for (Map.Entry<Long, FieldEvidence> entry : fields.entrySet()) {
            long off = entry.getKey();
            FieldEvidence fe = entry.getValue();
            if (off < 0) continue;
            int size = fe.size > 0 ? fe.size : 1;
            DataType dt = fieldTypeFor(program, size, fe);
            String note = fe.callThrough ? "called through (vtable/function pointer)"
                        : fe.floatUse ? "used in float math" : "";
            report.append(String.format("0x%x\t%d\t%s\t%d\t%d\t%s\n",
                off, size, dt.getName(), fe.loads, fe.stores, note));
            try {
                if (off + size <= Integer.MAX_VALUE) {
                    struct.replaceAtOffset((int) off, dt, size,
                        String.format("field_0x%x", off), note.isEmpty() ? null : note);
                }
            } catch (Exception e) {
                report.append("# could not place field at 0x").append(Long.toHexString(off))
                      .append(": ").append(e.getMessage()).append('\n');
            }
        }

        if (!apply) {
            // A dry run must not touch the program. Report the layout and stop.
            return report + "\n# Not created: apply=false is a dry run. Re-run with apply=true "
                + "to add " + typeName + " to the type manager and retype "
                + target.getName() + ".";
        }

        final StringBuilder created = new StringBuilder();
        final HighSymbol finalTarget = target;
        String err = inTransaction(program, "Auto create struct " + typeName, () -> {
            DataType stored = program.getDataTypeManager()
                .addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
            created.append("Created ").append(stored.getPathName())
                   .append(" (").append(stored.getLength()).append(" bytes)");
            {
                DataType ptr = new PointerDataType(stored, program.getDataTypeManager());
                HighFunctionDBUtil.updateDBVariable(finalTarget, finalTarget.getName(), ptr,
                    SourceType.USER_DEFINED);
                created.append("; applied to ").append(finalTarget.getName())
                       .append(" as ").append(stored.getName()).append(" *");
            }
        });
        if (err != null) {
            return report + "\n# type creation failed: " + err;
        }
        return report + "\n" + created;
    }

    private DataType fieldTypeFor(Program program, int size, FieldEvidence fe) {
        DataTypeManager dtm = program.getDataTypeManager();
        if (fe.callThrough && size == program.getDefaultPointerSize()) {
            return new PointerDataType(dtm);
        }
        if (fe.floatUse) {
            if (size == 4) return ghidra.program.model.data.FloatDataType.dataType;
            if (size == 8) return ghidra.program.model.data.DoubleDataType.dataType;
        }
        switch (size) {
            case 1: return ghidra.program.model.data.ByteDataType.dataType;
            case 2: return ghidra.program.model.data.WordDataType.dataType;
            case 4: return ghidra.program.model.data.DWordDataType.dataType;
            case 8: return ghidra.program.model.data.QWordDataType.dataType;
            default: return new ghidra.program.model.data.ArrayDataType(
                ghidra.program.model.data.ByteDataType.dataType, size, 1);
        }
    }

    private boolean isFloatOp(int opcode) {
        return opcode == PcodeOp.FLOAT_ADD || opcode == PcodeOp.FLOAT_SUB
            || opcode == PcodeOp.FLOAT_MULT || opcode == PcodeOp.FLOAT_DIV
            || opcode == PcodeOp.FLOAT_NEG || opcode == PcodeOp.FLOAT_ABS
            || opcode == PcodeOp.FLOAT_SQRT || opcode == PcodeOp.FLOAT_INT2FLOAT
            || opcode == PcodeOp.FLOAT_FLOAT2FLOAT || opcode == PcodeOp.FLOAT_LESS
            || opcode == PcodeOp.FLOAT_LESSEQUAL || opcode == PcodeOp.FLOAT_EQUAL
            || opcode == PcodeOp.FLOAT_NOTEQUAL;
    }

    private boolean usedAsFloat(Varnode vn) {
        Iterator<PcodeOp> it = vn.getDescendants();
        while (it.hasNext()) {
            if (isFloatOp(it.next().getOpcode())) return true;
        }
        return false;
    }

    private boolean calledThrough(Varnode vn) {
        Iterator<PcodeOp> it = vn.getDescendants();
        while (it.hasNext()) {
            PcodeOp op = it.next();
            if (op.getOpcode() == PcodeOp.CALLIND && op.getInput(0) == vn) return true;
        }
        return false;
    }

    /**
     * Find every instruction whose memory operand uses a given structure offset -
     * "who touches +0x64". Works before any type has been applied, which is exactly
     * when you need it.
     */
    private String findFieldAccesses(String offsetStr, String blockName, int limit, int maxInstr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (offsetStr == null || offsetStr.isEmpty()) return "Error: offset is required";

        long offset;
        try {
            String s = offsetStr.trim().toLowerCase();
            offset = s.startsWith("0x") ? Long.parseLong(s.substring(2), 16) : Long.parseLong(s);
        } catch (NumberFormatException e) {
            return "Error: bad offset: " + offsetStr;
        }
        if (limit <= 0) limit = 100;
        if (maxInstr <= 0) maxInstr = 20000000;

        AddressSetView scope = scopeFor(program, blockName);
        if (scope == null) return "Error: no memory block named " + blockName;

        List<String> hits = new ArrayList<>();
        InstructionIterator it = program.getListing().getInstructions(scope, true);
        int scanned = 0;
        boolean capped = false;
        while (it.hasNext()) {
            if (scanned++ >= maxInstr) { capped = true; break; }
            Instruction instr = it.next();
            boolean match = false;
            int matchOp = -1;
            for (int i = 0; i < instr.getNumOperands() && !match; i++) {
                Object[] objs = instr.getOpObjects(i);
                boolean hasRegister = false;
                boolean hasOffset = false;
                for (Object o : objs) {
                    if (o instanceof ghidra.program.model.lang.Register) hasRegister = true;
                    else if (o instanceof Scalar && ((Scalar) o).getUnsignedValue() == offset) hasOffset = true;
                }
                if (hasRegister && hasOffset) { match = true; matchOp = i; }
            }
            if (!match) continue;

            Function fn = program.getFunctionManager().getFunctionContaining(instr.getAddress());
            hits.add(String.format("%s\t%s\t%s\t%s",
                instr.getAddress(),
                fn != null ? fn.getName() + "+0x"
                    + Long.toHexString(instr.getAddress().subtract(fn.getEntryPoint())) : "-",
                instr.getOperandRefType(matchOp) != null ? instr.getOperandRefType(matchOp).getName() : "-",
                instr.toString()));
            if (hits.size() >= limit) break;
        }

        if (hits.isEmpty()) {
            return "No instructions use offset 0x" + Long.toHexString(offset)
                + " with a register base" + (capped ? " (scan capped at " + maxInstr + " instructions)" : "");
        }
        String header = String.format("# %d hit(s) for offset 0x%s%s (addr\tfunction+off\treftype\tinstruction)\n",
            hits.size(), Long.toHexString(offset),
            capped ? ", scan capped at " + maxInstr + " instructions" : "");
        return header + String.join("\n", hits);
    }

    private AddressSetView scopeFor(Program program, String blockName) {
        if (blockName == null || blockName.isEmpty()) return program.getMemory();
        MemoryBlock block = program.getMemory().getBlock(blockName);
        if (block == null) return null;
        return new AddressSet(block.getStart(), block.getEnd());
    }

    // ==================================================================================
    // Discovery
    // ==================================================================================

    /**
     * Search for a typed value rather than a byte pattern. "90.0f" is encoded to its
     * IEEE-754 bytes, integers to each plausible width, and every hit comes back with
     * its block, containing function and reference count already resolved.
     */
    private String searchConstant(String valueStr, String kinds, String blockName, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (valueStr == null || valueStr.trim().isEmpty()) return "Error: value is required";
        if (limit <= 0) limit = 50;

        String v = valueStr.trim().toLowerCase();
        boolean explicitFloat = v.endsWith("f") || v.endsWith("d") || v.contains(".");
        String numeric = v.endsWith("f") || v.endsWith("d") ? v.substring(0, v.length() - 1) : v;

        Double dval = null;
        Long lval = null;
        try {
            if (explicitFloat) {
                dval = Double.parseDouble(numeric);
            } else if (numeric.startsWith("0x")) {
                lval = Long.parseUnsignedLong(numeric.substring(2), 16);
            } else {
                lval = Long.parseLong(numeric);
                dval = (double) lval;
            }
        } catch (NumberFormatException e) {
            return "Error: cannot parse value: " + valueStr;
        }

        String kindSpec = (kinds == null || kinds.isEmpty()) ? "auto" : kinds.toLowerCase();
        boolean auto = kindSpec.equals("auto");
        boolean wantFloat  = auto ? dval != null : kindSpec.contains("float");
        boolean wantDouble = auto ? dval != null : kindSpec.contains("double");
        boolean wantInt32  = auto ? lval != null : kindSpec.contains("int32");
        boolean wantInt64  = auto ? lval != null : kindSpec.contains("int64");
        boolean wantImm    = auto ? lval != null : kindSpec.contains("imm");

        boolean bigEndian = program.getLanguage().isBigEndian();
        Map<String, byte[]> patterns = new LinkedHashMap<>();
        if (wantFloat && dval != null && !Double.isNaN(dval)) {
            patterns.put("float", encode(Float.floatToIntBits((float) (double) dval), 4, bigEndian));
        }
        if (wantDouble && dval != null && !Double.isNaN(dval)) {
            patterns.put("double", encode(Double.doubleToLongBits(dval), 8, bigEndian));
        }
        if (wantInt32 && lval != null) patterns.put("int32", encode(lval, 4, bigEndian));
        if (wantInt64 && lval != null) patterns.put("int64", encode(lval, 8, bigEndian));

        AddressSetView scope = scopeFor(program, blockName);
        if (scope == null) return "Error: no memory block named " + blockName;

        StringBuilder sb = new StringBuilder();
        int total = 0;

        for (Map.Entry<String, byte[]> p : patterns.entrySet()) {
            byte[] bytes = p.getValue();
            byte[] mask = new byte[bytes.length];
            Arrays.fill(mask, (byte) 0xFF);
            List<String> hits = new ArrayList<>();
            Address cursor = scope.getMinAddress();
            Address end = scope.getMaxAddress();
            while (cursor != null && hits.size() < limit) {
                Address found = program.getMemory().findBytes(cursor, end, bytes, mask, true, TaskMonitor.DUMMY);
                if (found == null) break;
                if (scope.contains(found)) {
                    hits.add(describeDataHit(program, found));
                }
                try { cursor = found.add(1); } catch (Exception e) { break; }
            }
            if (!hits.isEmpty()) {
                sb.append("## as ").append(p.getKey()).append(" (")
                  .append(toHexBytes(bytes)).append(")\n");
                sb.append(String.join("\n", hits)).append('\n');
                total += hits.size();
            }
        }

        if (wantImm && lval != null) {
            List<String> immHits = new ArrayList<>();
            InstructionIterator it = program.getListing().getInstructions(scope, true);
            while (it.hasNext() && immHits.size() < limit) {
                Instruction instr = it.next();
                boolean match = false;
                for (int i = 0; i < instr.getNumOperands() && !match; i++) {
                    for (Object o : instr.getOpObjects(i)) {
                        if (o instanceof Scalar && ((Scalar) o).getUnsignedValue() == lval) {
                            match = true;
                            break;
                        }
                    }
                }
                if (!match) continue;
                Function fn = program.getFunctionManager().getFunctionContaining(instr.getAddress());
                immHits.add(String.format("%s\t%s\t%s", instr.getAddress(),
                    fn != null ? fn.getName() + "+0x"
                        + Long.toHexString(instr.getAddress().subtract(fn.getEntryPoint())) : "-",
                    instr.toString()));
            }
            if (!immHits.isEmpty()) {
                sb.append("## as instruction immediate\n");
                sb.append(String.join("\n", immHits)).append('\n');
                total += immHits.size();
            }
        }

        if (total == 0) {
            return "No matches for " + valueStr + " (tried: " + String.join(", ", patterns.keySet())
                + (wantImm ? ", instruction immediates" : "") + ")";
        }
        return String.format("# %d hit(s) for %s (addr\tblock/function\trefs\tcontext)\n", total, valueStr)
            + sb;
    }

    private String describeDataHit(Program program, Address found) {
        MemoryBlock block = program.getMemory().getBlock(found);
        int refCount = 0;
        List<String> referrers = new ArrayList<>();
        ReferenceIterator ri = program.getReferenceManager().getReferencesTo(found);
        while (ri.hasNext()) {
            Reference ref = ri.next();
            refCount++;
            if (referrers.size() < 4) {
                Function fn = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                referrers.add(ref.getFromAddress() + (fn != null ? " in " + fn.getName() : ""));
            }
        }
        Function containing = program.getFunctionManager().getFunctionContaining(found);
        return String.format("%s\t%s\t%d\t%s", found,
            containing != null ? containing.getName() : (block != null ? block.getName() : "?"),
            refCount,
            referrers.isEmpty() ? "(no references - probably not the one you want)"
                                : String.join("; ", referrers));
    }

    private byte[] encode(long value, int width, boolean bigEndian) {
        byte[] out = new byte[width];
        for (int i = 0; i < width; i++) {
            int shift = bigEndian ? (width - 1 - i) * 8 : i * 8;
            out[i] = (byte) ((value >>> shift) & 0xFF);
        }
        return out;
    }

    private String toHexBytes(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Regex over disassembly text across the whole program. Catches things a byte
     * pattern misses because you would have had to guess the encoding, e.g.
     * "MOV dword ptr \[.*\+0x700\]," for every immediate write to a field.
     */
    private String searchInstructions(String regex, String blockName, int limit, int maxInstr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (regex == null || regex.isEmpty()) return "Error: regex is required";
        if (limit <= 0) limit = 100;
        if (maxInstr <= 0) maxInstr = 20000000;

        Pattern pattern;
        try {
            pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            return "Error: bad regex: " + e.getMessage();
        }

        AddressSetView scope = scopeFor(program, blockName);
        if (scope == null) return "Error: no memory block named " + blockName;

        List<String> hits = new ArrayList<>();
        InstructionIterator it = program.getListing().getInstructions(scope, true);
        int scanned = 0;
        boolean capped = false;
        while (it.hasNext()) {
            if (scanned++ >= maxInstr) { capped = true; break; }
            Instruction instr = it.next();
            String text = instr.toString();
            if (!pattern.matcher(text).find()) continue;
            Function fn = program.getFunctionManager().getFunctionContaining(instr.getAddress());
            hits.add(String.format("%s\t%s\t%s", instr.getAddress(),
                fn != null ? fn.getName() + "+0x"
                    + Long.toHexString(instr.getAddress().subtract(fn.getEntryPoint())) : "-",
                text));
            if (hits.size() >= limit) break;
        }

        if (hits.isEmpty()) {
            return "No instructions match /" + regex + "/"
                + (capped ? " (scan capped at " + maxInstr + " instructions)" : "");
        }
        return String.format("# %d match(es)%s (addr\tfunction+off\tinstruction)\n",
            hits.size(), capped ? ", scan capped" : "") + String.join("\n", hits);
    }

    /**
     * Every call site of a function, with the constant arguments passed at each one
     * resolved - strings, global addresses and immediates.
     *
     * Pointed at a registration helper this recovers whole tables at once: name,
     * offset and flags for every field a UE-style property registrar declares.
     */
    private String getCallSites(String addressStr, String name, boolean withArgs, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Function callee = findFunction(program, addressStr, name);
        if (callee == null) return "No function found";
        if (limit <= 0) limit = 50;

        List<Reference> callRefs = new ArrayList<>();
        ReferenceIterator ri = program.getReferenceManager().getReferencesTo(callee.getEntryPoint());
        while (ri.hasNext()) {
            Reference ref = ri.next();
            if (ref.getReferenceType() != null && ref.getReferenceType().isCall()) callRefs.add(ref);
        }
        if (callRefs.isEmpty()) return "No call sites reference " + callee.getName();

        StringBuilder sb = new StringBuilder();
        sb.append("# ").append(callRefs.size()).append(" call site(s) of ").append(callee.getName());
        if (callRefs.size() > limit) sb.append(" (showing first ").append(limit).append(')');
        sb.append('\n');

        if (!withArgs) {
            sb.append("# addr\tcaller\n");
            int n = 0;
            for (Reference ref : callRefs) {
                if (n++ >= limit) break;
                Function caller = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                sb.append(ref.getFromAddress()).append('\t')
                  .append(caller != null ? caller.getName() : "-").append('\n');
            }
            return sb.toString();
        }

        sb.append("# addr\tcaller\targuments\n");
        Map<Function, HighFunction> cache = new HashMap<>();
        int n = 0;
        for (Reference ref : callRefs) {
            if (n++ >= limit) break;
            Address site = ref.getFromAddress();
            Function caller = program.getFunctionManager().getFunctionContaining(site);
            if (caller == null) {
                sb.append(site).append("\t-\t(not in a defined function)\n");
                continue;
            }
            HighFunction hf = cache.get(caller);
            if (hf == null && !cache.containsKey(caller)) {
                DecompileResults dr = decompileCached(program, caller, 60);
                hf = (dr != null && dr.decompileCompleted()) ? dr.getHighFunction() : null;
                cache.put(caller, hf);
            }
            if (hf == null) {
                sb.append(site).append('\t').append(caller.getName())
                  .append("\t(decompilation failed)\n");
                continue;
            }
            List<String> args = new ArrayList<>();
            Iterator<PcodeOpAST> ops = hf.getPcodeOps(site);
            while (ops.hasNext()) {
                PcodeOp op = ops.next();
                if (op.getOpcode() != PcodeOp.CALL && op.getOpcode() != PcodeOp.CALLIND) continue;
                for (int i = 1; i < op.getNumInputs(); i++) {
                    args.add(describeArgument(program, op.getInput(i)));
                }
                break;
            }
            sb.append(site).append('\t').append(caller.getName()).append('\t')
              .append(args.isEmpty() ? "(no arguments recovered)" : String.join(", ", args))
              .append('\n');
        }
        return sb.toString();
    }

    private String describeArgument(Program program, Varnode vn) {
        if (vn == null) return "?";
        if (vn.isConstant()) {
            long val = vn.getOffset();
            String resolved = resolveConstantMeaning(program, val);
            return resolved != null ? resolved : formatConstant(val);
        }
        PcodeOp def = vn.getDef();
        if (def != null && (def.getOpcode() == PcodeOp.COPY || def.getOpcode() == PcodeOp.CAST)) {
            return describeArgument(program, def.getInput(0));
        }
        if (def != null && def.getOpcode() == PcodeOp.PTRSUB) {
            Varnode a = def.getInput(0);
            Varnode b = def.getInput(1);
            if (a != null && a.isConstant() && a.getOffset() == 0 && b != null && b.isConstant()) {
                String resolved = resolveConstantMeaning(program, b.getOffset());
                if (resolved != null) return resolved;
            }
        }
        HighVariable hv = vn.getHigh();
        if (hv != null && hv.getName() != null && !"UNNAMED".equals(hv.getName())) {
            return hv.getName();
        }
        return describeStorage(program, vn);
    }

    /**
     * Ghidra names an un-named local "UNNAMED", which tells the caller nothing. Describe
     * where the value actually lives instead.
     */
    private String describeStorage(Program program, Varnode vn) {
        if (vn.isRegister()) {
            Register reg = program.getRegister(vn.getAddress(), vn.getSize());
            if (reg != null) return reg.getName();
        }
        if (vn.getAddress() != null && vn.getAddress().isStackAddress()) {
            long off = vn.getAddress().getOffset();
            return "stack[" + (off < 0 ? "-0x" + Long.toHexString(-off)
                                       : "0x" + Long.toHexString(off)) + "]";
        }
        PcodeOp def = vn.getDef();
        if (def != null && (def.getOpcode() == PcodeOp.PTRSUB || def.getOpcode() == PcodeOp.INT_ADD)
            && def.getInput(1) != null && def.getInput(1).isConstant()) {
            long off = def.getInput(1).getOffset();
            Varnode base = def.getInput(0);
            String baseName = "?";
            if (base != null && base.isRegister()) {
                Register reg = program.getRegister(base.getAddress(), base.getSize());
                if (reg != null) baseName = reg.getName();
            } else if (base != null && base.getAddress() != null
                       && base.getAddress().isStackAddress()) {
                baseName = "stack";
            }
            return "&" + baseName + (off < 0 ? "-0x" + Long.toHexString(-off)
                                             : "+0x" + Long.toHexString(off));
        }
        if (def != null) return "<" + def.getMnemonic().toLowerCase() + " result>";
        return "<local>";
    }

    private String formatConstant(long val) {
        if (val >= 0 && val < 10) return Long.toString(val);
        return "0x" + Long.toHexString(val);
    }

    private String resolveConstantMeaning(Program program, long val) {
        if (val == 0) return null;
        Address addr;
        try {
            addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(val);
        } catch (Exception e) {
            return null;
        }
        if (!program.getMemory().contains(addr)) return null;

        Data data = program.getListing().getDataAt(addr);
        if (data != null && isStringData(data) && data.getValue() != null) {
            String s = escapeString(data.getValue().toString());
            if (s.length() > 80) s = s.substring(0, 80) + "...";
            return "\"" + s + "\"";
        }
        Function fn = program.getFunctionManager().getFunctionAt(addr);
        if (fn != null) return fn.getName();
        Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
        if (sym != null) return sym.getName() + " (" + addr + ")";
        return null;
    }

    // ==================================================================================
    // Virtual dispatch and file layout
    // ==================================================================================

    /**
     * Work out what an indirect call goes to. Resolves the vtable slot when the
     * table is known statically, and reports the slot index either way.
     */
    private String resolveVirtualCall(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Address site = resolveAddress(program, addressStr);
        if (site == null) return "Address is required";

        Function caller = program.getFunctionManager().getFunctionContaining(site);
        if (caller == null) return "No function found containing " + site;

        DecompileResults dr = decompileCached(program, caller, 60);
        if (dr == null || !dr.decompileCompleted() || dr.getHighFunction() == null) {
            return "Decompilation failed for " + caller.getName();
        }

        PcodeOp callOp = null;
        Iterator<PcodeOpAST> ops = dr.getHighFunction().getPcodeOps(site);
        while (ops.hasNext()) {
            PcodeOp op = ops.next();
            if (op.getOpcode() == PcodeOp.CALLIND || op.getOpcode() == PcodeOp.CALL) {
                callOp = op;
                break;
            }
        }
        if (callOp == null) return "No call at " + site + " (is that the call instruction address?)";

        StringBuilder sb = new StringBuilder();
        sb.append("call site ").append(site).append(" in ").append(caller.getName()).append('\n');

        if (callOp.getOpcode() == PcodeOp.CALL) {
            Varnode t = callOp.getInput(0);
            Function direct = t != null ? program.getFunctionManager().getFunctionAt(t.getAddress()) : null;
            sb.append("direct call -> ").append(direct != null ? direct.getName() : String.valueOf(t));
            return sb.toString();
        }

        Varnode target = callOp.getInput(0);
        long slotOffset = -1;
        long objectOffset = 0;
        boolean objectOffsetKnown = false;
        Address tableAddr = null;
        int ptrSize = program.getDefaultPointerSize();

        // Two dereferences are involved: the first LOAD produces the function pointer out
        // of the vtable, the second produces the vtable pointer out of the object. Only
        // offsets accumulated between them are the slot offset - anything past the second
        // LOAD is an offset within the object (a this-adjustment for a base sub-object)
        // and belongs to a different address space entirely. Adding the two together
        // yields a plausible, wrong slot number.
        int loads = 0;
        Varnode cursor = target;
        for (int depth = 0; depth < 16 && cursor != null; depth++) {
            PcodeOp def = cursor.getDef();
            if (def == null) break;
            int opc = def.getOpcode();
            long delta = 0;
            boolean haveDelta = false;

            if (opc == PcodeOp.CAST || opc == PcodeOp.COPY || opc == PcodeOp.MULTIEQUAL) {
                cursor = def.getInput(0);
            } else if (opc == PcodeOp.LOAD) {
                loads++;
                if (loads >= 2) {
                    // Everything from here on describes the object, not the table.
                    cursor = def.getInput(1);
                    continue;
                }
                cursor = def.getInput(1);
            } else if (opc == PcodeOp.PTRADD) {
                Varnode idx = def.getInput(1);
                Varnode elem = def.getInput(2);
                if (idx != null && idx.isConstant() && elem != null && elem.isConstant()) {
                    delta = idx.getOffset() * elem.getOffset();
                    haveDelta = true;
                }
                cursor = def.getInput(0);
            } else if (opc == PcodeOp.PTRSUB || opc == PcodeOp.INT_ADD) {
                Varnode a = def.getInput(0);
                Varnode b = def.getInput(1);
                if (b != null && b.isConstant()) {
                    delta = b.getOffset();
                    haveDelta = true;
                    cursor = a;
                } else if (a != null && a.isConstant()) {
                    delta = a.getOffset();
                    haveDelta = true;
                    cursor = b;
                } else {
                    break;
                }
            } else {
                break;
            }

            if (haveDelta) {
                if (loads < 2) {
                    slotOffset = (slotOffset < 0 ? 0 : slotOffset) + delta;
                } else {
                    objectOffset += delta;
                    objectOffsetKnown = true;
                }
            }
            if (cursor != null && cursor.isConstant() && loads < 2) {
                try {
                    tableAddr = program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(cursor.getOffset());
                } catch (Exception ignored) { }
                break;
            }
        }

        if (slotOffset < 0) {
            sb.append("indirect call; could not recover a constant slot offset. ");
            sb.append("Target varnode: ").append(target);
            return sb.toString();
        }

        sb.append("indirect call through slot offset 0x").append(Long.toHexString(slotOffset))
          .append(" (index ").append(slotOffset / ptrSize).append(", pointer size ")
          .append(ptrSize).append(")\n");
        if (objectOffsetKnown && objectOffset != 0) {
            sb.append("vtable pointer read from this")
              .append(objectOffset < 0 ? "-0x" + Long.toHexString(-objectOffset)
                                       : "+0x" + Long.toHexString(objectOffset))
              .append(" - a base sub-object, so this is that base's vtable, not the "
                  + "most-derived one\n");
        }

        if (tableAddr != null && program.getMemory().contains(tableAddr)) {
            sb.append("vtable base ").append(tableAddr).append('\n');
            try {
                Address slot = tableAddr.add(slotOffset);
                long value = ptrSize == 8 ? program.getMemory().getLong(slot)
                                          : (program.getMemory().getInt(slot) & 0xFFFFFFFFL);
                Address t = program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
                Function impl = program.getFunctionManager().getFunctionAt(t);
                sb.append("resolves to ").append(t).append(' ')
                  .append(impl != null ? impl.getName() : "(no function defined)");
            } catch (Exception e) {
                sb.append("could not read slot: ").append(e.getMessage());
            }
        } else {
            sb.append("vtable is not a compile-time constant here. ")
              .append("Use find_vtables_containing on a known implementation, or get_vtable on a ")
              .append("vftable symbol, then read index ").append(slotOffset / ptrSize).append('.');
        }
        return sb.toString();
    }

    /**
     * Reverse vtable lookup: which tables contain this function, and at what index.
     * Turns "I found an interesting function" into "this is virtual method N of these
     * classes".
     */
    private String findVtablesContaining(String addressStr, String name, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Function func = findFunction(program, addressStr, name);
        if (func == null) return "No function found";
        if (limit <= 0) limit = 25;

        int ptrSize = program.getDefaultPointerSize();
        byte[] needle = encode(func.getEntryPoint().getOffset(), ptrSize,
            program.getLanguage().isBigEndian());
        byte[] mask = new byte[needle.length];
        Arrays.fill(mask, (byte) 0xFF);

        Memory memory = program.getMemory();
        List<String> hits = new ArrayList<>();
        Address cursor = memory.getMinAddress();
        Address end = memory.getMaxAddress();

        while (cursor != null && hits.size() < limit) {
            Address found = memory.findBytes(cursor, end, needle, mask, true, TaskMonitor.DUMMY);
            if (found == null) break;

            if (found.getOffset() % ptrSize == 0
                && program.getFunctionManager().getFunctionContaining(found) == null) {
                Address base = found;
                int index = 0;
                for (int back = 1; back <= 4096; back++) {
                    Address prev;
                    try { prev = found.subtract((long) back * ptrSize); } catch (Exception e) { break; }
                    if (!memory.contains(prev)) break;
                    long value;
                    try {
                        value = ptrSize == 8 ? memory.getLong(prev) : (memory.getInt(prev) & 0xFFFFFFFFL);
                    } catch (Exception e) { break; }
                    if (value == 0) break;
                    Address t;
                    try {
                        t = program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
                    } catch (Exception e) { break; }
                    // Accept any pointer into executable memory. Requiring a *defined*
                    // function stops the walk at the first slot auto-analysis never got
                    // to, which reports a table base that is too high and a slot index
                    // that is too low.
                    MemoryBlock targetBlock = memory.getBlock(t);
                    if (targetBlock == null || !targetBlock.isExecute()) break;
                    base = prev;
                    index = back;
                }
                Symbol sym = program.getSymbolTable().getPrimarySymbol(base);
                MemoryBlock block = memory.getBlock(found);
                hits.add(String.format("%s\t%d\t%s\t%s", base, index,
                    sym != null ? sym.getName(true) : "(unnamed table)",
                    block != null ? block.getName() : "?"));
            }
            try { cursor = found.add(1); } catch (Exception e) { break; }
        }

        if (hits.isEmpty()) {
            return func.getName() + " does not appear in any pointer table "
                + "(not a virtual method, or the table is not in mapped memory)";
        }
        return String.format("# %s appears in %d table(s) (table_base\tslot_index\tsymbol\tblock)\n",
            func.getName(), hits.size()) + String.join("\n", hits);
    }

    /**
     * Convert between virtual address and file offset using the loader's own section
     * mapping, instead of doing PE header arithmetic by hand.
     */
    private String fileOffset(String addressStr, String fileOffsetStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        if (fileOffsetStr != null && !fileOffsetStr.isEmpty()) {
            long fo;
            try {
                String s = fileOffsetStr.trim().toLowerCase();
                fo = s.startsWith("0x") ? Long.parseLong(s.substring(2), 16) : Long.parseLong(s);
            } catch (NumberFormatException e) {
                return "Error: bad file_offset: " + fileOffsetStr;
            }
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
                    if (info.containsFileOffset(fo)) {
                        Address a = info.locateAddressForFileOffset(fo);
                        if (a != null) {
                            return String.format("file 0x%s -> VA %s (block %s)",
                                Long.toHexString(fo), a, block.getName());
                        }
                    }
                }
            }
            return "No mapped block contains file offset 0x" + Long.toHexString(fo);
        }

        Address addr = resolveAddress(program, addressStr);
        if (addr == null) return "Address is required";
        MemoryBlock block = program.getMemory().getBlock(addr);
        if (block == null) return "Error: " + addr + " is not in a memory block";
        for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
            if (info.contains(addr)) {
                if (info.getFileBytes().isEmpty()) {
                    return "Error: block " + block.getName() + " has no backing file bytes "
                        + "(uninitialized section such as .bss - it does not exist in the file)";
                }
                long fo = info.getFileBytesOffset(addr);
                return String.format("VA %s -> file 0x%s (block %s, %s)",
                    addr, Long.toHexString(fo), block.getName(),
                    block.isInitialized() ? "initialized" : "uninitialized");
            }
        }
        return "Error: no source info for " + addr;
    }



    // ==================================================================================
    // Multi-program support
    //
    // Every endpoint accepts an optional ?program= parameter, and every response carries
    // an X-Ghidra-Program header naming the program that answered it. The header matters
    // more than the parameter: with two binaries open, silently analysing the wrong one
    // is a failure the caller cannot otherwise detect.
    // ==================================================================================

    private static final ThreadLocal<String> PROGRAM_OVERRIDE = new ThreadLocal<>();
    private final Map<String, String> analysisStatus = new ConcurrentHashMap<>();
    private final Map<String, String> importStatus = new ConcurrentHashMap<>();
    private int endpointCount;

    private static class NoSuchProgramException extends RuntimeException {
        NoSuchProgramException(String message) { super(message); }
    }

    /**
     * Register a context with the program-selection wrapper. Used in place of
     * server.createContext for every endpoint.
     */
    private void ctx(String path, com.sun.net.httpserver.HttpHandler handler) {
        server.createContext(path, exchange -> {
            String want = null;
            try {
                want = parseQueryParams(exchange).get("program");
            } catch (Exception ignored) {
                // a malformed query string is the handler's problem, not ours
            }
            PROGRAM_OVERRIDE.set(want);
            try {
                Program resolved;
                try {
                    resolved = getCurrentProgram();
                } catch (NoSuchProgramException e) {
                    exchange.getResponseHeaders().set("X-Ghidra-Program", "none");
                    sendResponse(exchange, "Error: " + e.getMessage(), 404);
                    return;
                }
                exchange.getResponseHeaders().set("X-Ghidra-Program",
                    resolved != null ? programLabel(resolved) : "none");
                try {
                    handler.handle(exchange);
                } catch (AmbiguousNameException e) {
                    trySend(exchange, "Error: " + e.getMessage(), 400);
                } catch (Throwable t) {
                    // Without this the connection just drops and the bridge reports
                    // "cannot reach Ghidra", which sends debugging the wrong way.
                    Msg.error(this, "GhidraMCP " + path + " failed", t);
                    StackTraceElement[] st = t.getStackTrace();
                    trySend(exchange, "Error: plugin exception in " + path + ": " + t
                        + (st.length > 0 ? " at " + st[0] : ""), 500);
                }
            } finally {
                PROGRAM_OVERRIDE.remove();
            }
        });
    }

    private void trySend(HttpExchange exchange, String body, int status) {
        try {
            sendResponse(exchange, body, status);
        } catch (Exception ignored) {
            // response already started; nothing more to do
        }
    }

    private String programLabel(Program program) {
        if (program == null) return "none";
        DomainFile df = program.getDomainFile();
        return df != null ? df.getName() : program.getName();
    }

    /**
     * Resolve a program by name, project path or #index among the open programs.
     */
    private Program resolveProgram(String want) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return null;
        Program[] all = pm.getAllOpenPrograms();
        if (want == null || want.trim().isEmpty()) return pm.getCurrentProgram();
        String w = want.trim();

        if (w.startsWith("#")) {
            try {
                int idx = Integer.parseInt(w.substring(1));
                if (idx >= 0 && idx < all.length) return all[idx];
            } catch (NumberFormatException ignored) { }
        }
        for (Program p : all) {
            if (programLabel(p).equals(w) || p.getName().equals(w)) return p;
        }
        for (Program p : all) {
            DomainFile df = p.getDomainFile();
            if (df != null && df.getPathname().equals(w)) return p;
        }
        Program partial = null;
        int partials = 0;
        for (Program p : all) {
            if (programLabel(p).toLowerCase().contains(w.toLowerCase())) {
                partial = p;
                partials++;
            }
        }
        if (partials == 1) return partial;

        List<String> names = new ArrayList<>();
        for (int i = 0; i < all.length; i++) names.add("#" + i + " " + programLabel(all[i]));
        throw new NoSuchProgramException(partials > 1
            ? "'" + want + "' matches " + partials + " open programs; be specific. Open: "
              + String.join(", ", names)
            : "no open program matches '" + want + "'. Open: "
              + (names.isEmpty() ? "(none)" : String.join(", ", names)));
    }

    /**
     * Every open program, with the current one marked. Call this before any analysis
     * session with more than one binary loaded.
     */
    private String listOpenPrograms() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return "No program loaded";
        Program[] all = pm.getAllOpenPrograms();
        if (all.length == 0) return "No programs are open in this tool";
        Program current = pm.getCurrentProgram();

        StringBuilder sb = new StringBuilder();
        sb.append("# index\tcurrent\tname\tarch\tfunctions\tchanged\tanalyzing\tpath\n");
        for (int i = 0; i < all.length; i++) {
            Program p = all[i];
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(p);
            DomainFile df = p.getDomainFile();
            sb.append('#').append(i).append('\t')
              .append(p == current ? "*" : "-").append('\t')
              .append(programLabel(p)).append('\t')
              .append(p.getLanguage() != null ? p.getLanguage().getLanguageID() : "?").append('\t')
              .append(p.getFunctionManager().getFunctionCount()).append('\t')
              .append(p.isChanged() ? "unsaved" : "saved").append('\t')
              .append(mgr != null && mgr.isAnalyzing() ? "yes" : "no").append('\t')
              .append(df != null ? df.getPathname() : "-").append('\n');
        }
        return sb.toString();
    }

    /**
     * Change which program is current for callers that do not pass ?program=.
     */
    private String selectProgram(String want) {
        if (want == null || want.trim().isEmpty()) return "Error: program is required";
        final Program target;
        try {
            target = resolveProgram(want);
        } catch (NoSuchProgramException e) {
            return "Error: " + e.getMessage();
        }
        if (target == null) return "Error: could not resolve program " + want;
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return "No program loaded";
        try {
            invokeAndWaitBounded(() -> pm.setCurrentProgram(target));
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to switch program: " + e.getMessage();
        }
        return "Current program is now " + programLabel(target);
    }

    // ==================================================================================
    // Import and analysis
    // ==================================================================================

    /**
     * Import a binary from a path on the machine running Ghidra, save it into the open
     * project and open it in this tool.
     */
    private String importFile(String path, String folderPath, boolean analyze) {
        if (path == null || path.trim().isEmpty()) return "Error: path is required";
        Project project = tool.getProject();
        if (project == null) return "Error: no project is open in this Ghidra instance";
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return "Error: no program manager service in this tool";

        final java.io.File file = new java.io.File(path.trim());
        if (!file.exists()) {
            return "Error: no such file on the Ghidra machine: " + file.getAbsolutePath()
                + " (paths are resolved by Ghidra, not by the caller)";
        }
        if (file.isDirectory()) return "Error: " + file + " is a directory";

        final String folder = (folderPath == null || folderPath.trim().isEmpty())
            ? "/" : folderPath.trim();
        final String key = file.getName();
        String current = importStatus.get(key);
        if (current != null && current.startsWith("running")) {
            return "An import of " + key + " is already running: " + current;
        }
        importStatus.put(key, "running: loading " + file.getAbsolutePath());

        // Importing a large binary takes far longer than the ~60s an MCP client allows a
        // tool call, so this cannot be synchronous. It also must not block on the UI
        // thread: opening a program can raise Ghidra's "analyze now?" prompt, which waits
        // on the user, which would hold an HTTP worker until they answered.
        Thread worker = new Thread(() -> {
            MessageLog log = new MessageLog();
            DomainFile saved;
            try (LoadResults<Program> results = ProgramLoader.builder()
                    .source(file)
                    .project(project)
                    .projectFolderPath(folder)
                    .log(log)
                    .monitor(TaskMonitor.DUMMY)
                    .load()) {
                saved = results.getPrimary().save(TaskMonitor.DUMMY);
            } catch (Throwable e) {
                importStatus.put(key, "failed: " + e.getClass().getSimpleName() + ": "
                    + e.getMessage() + (log.hasMessages() ? " | " + log : ""));
                return;
            }

            importStatus.put(key, "running: opening " + saved.getPathname());
            // OPEN_HIDDEN: the program is opened but not made current. Activating it is
            // what triggers the analyse prompt, and an unattended import should not put a
            // modal dialog in front of the user. Use select_program when you want it.
            final DomainFile df = saved;
            SwingUtilities.invokeLater(() -> {
                try {
                    Program opened = pm.openProgram(df, -1, ProgramManager.OPEN_HIDDEN);
                    if (opened == null) {
                        importStatus.put(key, "imported to " + df.getPathname()
                            + " but the tool did not open it");
                        return;
                    }
                    importStatus.put(key, "done: " + df.getPathname() + " open as "
                        + programLabel(opened) + ", "
                        + (opened.getLanguage() != null
                            ? opened.getLanguage().getLanguageID().toString() : "?")
                        + ", image base " + opened.getImageBase()
                        + ", " + opened.getFunctionManager().getFunctionCount()
                        + " functions so far");
                    if (analyze) startAnalysis(programLabel(opened));
                } catch (Throwable e) {
                    importStatus.put(key, "imported to " + df.getPathname()
                        + " but opening failed: " + e.getMessage());
                }
            });
        }, "GhidraMCP-Import");
        worker.setDaemon(true);
        worker.start();

        return "Import of " + file.getName() + " started (" + file.length() + " bytes) into "
            + folder + ".\nThis returns immediately - poll analysis_status for progress. "
            + "The program is opened hidden rather than made current, so no analyse prompt "
            + "appears; use select_program once it reports done."
            + (analyze ? " Auto-analysis will start as soon as it opens." : "");
    }

    /**
     * Kick off auto-analysis on a background thread and return immediately.
     */
    private String startAnalysis(String want) {
        final Program program;
        try {
            program = want == null || want.isEmpty() ? getCurrentProgram() : resolveProgram(want);
        } catch (NoSuchProgramException e) {
            return "Error: " + e.getMessage();
        }
        if (program == null) return "No program loaded";

        String label = programLabel(program);
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        if (mgr == null) return "Error: no analysis manager for " + label;
        if (mgr.isAnalyzing()) return "Analysis is already running on " + label;

        analysisStatus.put(label, "running: started");
        // Hand this to the tool's own background-command queue rather than running it on
        // a thread of our own: transactions, progress reporting and the GUI's analysis
        // state are then handled the same way as an analysis started from the menu.
        try {
            invokeAndWaitBounded(() -> {
                mgr.initializeOptions();
                // Without this the analysis queue is empty, so the background command
                // completes instantly having done nothing - and reports success.
                mgr.reAnalyzeAll(null);
                tool.executeBackgroundCommand(new AnalysisBackgroundCommand(mgr, false), program);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            analysisStatus.put(label, "failed to start: " + e.getMessage());
            return "Failed to start analysis: " + e.getMessage();
        }
        // Note the completion asynchronously so analysis_status can report it.
        Thread watcher = new Thread(() -> {
            try {
                Thread.sleep(1000);
                while (mgr.isAnalyzing()) Thread.sleep(2000);
                // Ghidra records "has been analyzed" as a program property, and nothing
                // sets it for us: AnalysisBackgroundCommand only runs the analyzers. Without
                // this the project keeps reporting the program as unanalysed, and Ghidra
                // raises its modal "would you like to analyze it now?" prompt the next time
                // the program is activated - the exact dialog the hidden-open avoids.
                String markError = inTransaction(program, "Mark program analyzed",
                    () -> ghidra.program.util.GhidraProgramUtilities.markProgramAnalyzed(program));
                analysisStatus.put(label, "finished: "
                    + program.getFunctionManager().getFunctionCount() + " functions"
                    + (markError == null ? "" : " (could not set the analyzed flag: "
                        + markError + ")"));
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                analysisStatus.put(label, "unknown: " + e.getMessage());
            }
        }, "GhidraMCP-AnalysisWatcher");
        watcher.setDaemon(true);
        watcher.start();

        return "Analysis started on " + label + ". This takes minutes on a large binary - "
            + "poll analysis_status rather than waiting on this call. Results are incomplete "
            + "until it reports finished.";
    }

    private String analysisStatusReport(String want) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return "No program loaded";
        Program[] all = pm.getAllOpenPrograms();
        StringBuilder sb = new StringBuilder(
            "# program\tanalyzing\tanalyzed\tfunctions\tlast_run\n");
        for (Program p : all) {
            String label = programLabel(p);
            if (want != null && !want.isEmpty() && !label.equalsIgnoreCase(want)) continue;
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(p);
            sb.append(label).append('\t')
              .append(mgr != null && mgr.isAnalyzing() ? "YES" : "no").append('\t')
              .append(ghidra.program.util.GhidraProgramUtilities.isAnalyzed(p) ? "yes" : "NO")
              .append('\t')
              .append(p.getFunctionManager().getFunctionCount()).append('\t')
              .append(analysisStatus.getOrDefault(label, "(not started by this session)"))
              .append('\n');
        }
        if (!importStatus.isEmpty()) {
            sb.append("\n## imports started this session\n");
            for (Map.Entry<String, String> e : importStatus.entrySet()) {
                sb.append(e.getKey()).append('\t').append(e.getValue()).append('\n');
            }
        }
        return sb.toString();
    }

    /**
     * Write the program back to the project.
     */
    private String saveProgram() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (!program.isChanged()) return programLabel(program) + " has no unsaved changes";
        final StringBuilder result = new StringBuilder();
        try {
            invokeAndWaitBounded(() -> {
                try {
                    program.save("GhidraMCP save", TaskMonitor.DUMMY);
                    result.append("Saved ").append(programLabel(program));
                } catch (Exception e) {
                    result.append("Failed to save: ").append(e.getMessage());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to save on Swing thread: " + e.getMessage();
        }
        return result.toString();
    }

    // ==================================================================================
    // Undo
    // ==================================================================================

    /**
     * Undo the last N program transactions. Every write endpoint names its transaction,
     * so the stack is readable before you decide.
     */
    private String undoRedo(boolean undo, int count) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (count <= 0) count = 1;

        List<String> done = new ArrayList<>();
        final StringBuilder error = new StringBuilder();
        final int steps = count;
        final boolean isUndo = undo;

        try {
            invokeAndWaitBounded(() -> {
                for (int i = 0; i < steps; i++) {
                    try {
                        if (isUndo) {
                            if (!program.canUndo()) break;
                            done.add(program.getUndoName());
                            program.undo();
                        } else {
                            if (!program.canRedo()) break;
                            done.add(program.getRedoName());
                            program.redo();
                        }
                    } catch (Exception e) {
                        error.append(e.getMessage());
                        break;
                    }
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed on Swing thread: " + e.getMessage();
        }

        if (done.isEmpty()) {
            return "Nothing to " + (undo ? "undo" : "redo") + " on " + programLabel(program)
                + (error.length() > 0 ? " (" + error + ")" : "");
        }
        return (undo ? "Undid " : "Redid ") + done.size() + " transaction(s) on "
            + programLabel(program) + ":\n  " + String.join("\n  ", done)
            + (error.length() > 0 ? "\nStopped early: " + error : "");
    }

    private String listUndoStack(int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (limit <= 0) limit = 30;
        List<String> undo = program.getAllUndoNames();
        List<String> redo = program.getAllRedoNames();

        StringBuilder sb = new StringBuilder();
        sb.append("# ").append(programLabel(program))
          .append(program.isChanged() ? " (unsaved changes)" : " (saved)").append('\n');
        sb.append("## undo stack, most recent first\n");
        if (undo.isEmpty()) sb.append("  (empty)\n");
        for (int i = 0; i < undo.size() && i < limit; i++) {
            sb.append("  ").append(i + 1).append(". ").append(undo.get(i)).append('\n');
        }
        sb.append("## redo stack\n");
        if (redo.isEmpty()) sb.append("  (empty)\n");
        for (int i = 0; i < redo.size() && i < limit; i++) {
            sb.append("  ").append(i + 1).append(". ").append(redo.get(i)).append('\n');
        }
        return sb.toString();
    }

    // ==================================================================================
    // Strings as an entry point
    // ==================================================================================

    /**
     * Strings matching a pattern together with the functions that reference them, in
     * one call. The usual way into an unfamiliar binary.
     */
    private String findStringXrefs(String pattern, boolean regex, int limit, int maxRefs) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (pattern == null || pattern.isEmpty()) return "Error: pattern is required";
        if (limit <= 0) limit = 50;
        if (maxRefs <= 0) maxRefs = 10;

        Pattern compiled = null;
        if (regex) {
            try {
                compiled = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
            } catch (Exception e) {
                return "Error: bad regex: " + e.getMessage();
            }
        }
        String lower = pattern.toLowerCase();

        StringBuilder sb = new StringBuilder();
        int found = 0;
        int unreferenced = 0;
        DataIterator dataIt = program.getListing().getDefinedData(true);
        while (dataIt.hasNext() && found < limit) {
            Data data = dataIt.next();
            if (data == null || !isStringData(data) || data.getValue() == null) continue;
            String value = data.getValue().toString();
            boolean match = compiled != null
                ? compiled.matcher(value).find()
                : value.toLowerCase().contains(lower);
            if (!match) continue;

            List<String> referrers = new ArrayList<>();
            ReferenceIterator ri = program.getReferenceManager().getReferencesTo(data.getAddress());
            int refCount = 0;
            while (ri.hasNext()) {
                Reference ref = ri.next();
                refCount++;
                if (referrers.size() >= maxRefs) continue;
                Function fn = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                referrers.add(fn != null
                    ? fn.getName() + " @ " + ref.getFromAddress()
                    : "(no function) @ " + ref.getFromAddress());
            }
            found++;
            if (refCount == 0) unreferenced++;
            sb.append(data.getAddress()).append("\t\"").append(escapeString(value)).append("\"\t")
              .append(refCount).append(" ref(s)\t")
              .append(referrers.isEmpty() ? "-" : String.join("; ", referrers))
              .append(refCount > referrers.size() ? " ... +" + (refCount - referrers.size()) : "")
              .append('\n');
        }

        if (found == 0) return "No strings match: " + pattern;
        return String.format("# %d string(s) matching \"%s\"%s (addr\tstring\trefs\treferrers)\n",
            found, pattern,
            unreferenced > 0 ? ", " + unreferenced + " with no references" : "") + sb;
    }


    // ==================================================================================
    // Identification
    // ==================================================================================

    /**
     * Transitive evidence for what a function is. A leaf function often references no
     * strings itself; what identifies it is two or three hops out - the imported APIs it
     * eventually reaches, the strings its callees touch, and which already-named
     * functions call it.
     */
    private String functionEvidence(String addressStr, String name, int depth, int maxNodes) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Function func = findFunction(program, addressStr, name);
        if (func == null) return "No function found";
        if (depth <= 0) depth = 2;
        if (depth > 4) depth = 4;
        if (maxNodes <= 0) maxNodes = 400;

        Set<Function> visited = new LinkedHashSet<>();
        Map<String, Integer> imports = new TreeMap<>();
        Map<String, String> strings = new LinkedHashMap<>();
        List<String> namedCallees = new ArrayList<>();

        Deque<Object[]> queue = new ArrayDeque<>();
        queue.add(new Object[] { func, 0 });
        visited.add(func);

        while (!queue.isEmpty() && visited.size() < maxNodes) {
            Object[] item = queue.poll();
            Function f = (Function) item[0];
            int d = (Integer) item[1];

            for (String s : referencedStrings(program, f, 12)) {
                if (strings.size() < 60 && !strings.containsKey(s)) {
                    strings.put(s, f == func ? "direct" : f.getName() + " (depth " + d + ")");
                }
            }

            if (d >= depth) continue;
            for (Function callee : f.getCalledFunctions(TaskMonitor.DUMMY)) {
                Function resolved = callee.isThunk() ? callee.getThunkedFunction(true) : callee;
                if (resolved == null) resolved = callee;
                if (resolved.isExternal() || resolved.getName().startsWith("__imp_")) {
                    imports.merge(resolved.getName(), 1, Integer::sum);
                    continue;
                }
                if (!isDefaultName(resolved.getName()) && namedCallees.size() < 60
                    && !namedCallees.contains(resolved.getName() + " (depth " + (d + 1) + ")")) {
                    namedCallees.add(resolved.getName() + " (depth " + (d + 1) + ")");
                }
                if (visited.add(resolved) && visited.size() < maxNodes) {
                    queue.add(new Object[] { resolved, d + 1 });
                }
            }
        }

        List<String> namedCallers = new ArrayList<>();
        int callerCount = 0;
        for (Function caller : func.getCallingFunctions(TaskMonitor.DUMMY)) {
            callerCount++;
            if (!isDefaultName(caller.getName()) && namedCallers.size() < 40) {
                namedCallers.add(caller.getName() + " @ " + caller.getEntryPoint());
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("# evidence for ").append(func.getName()).append(" @ ")
          .append(func.getEntryPoint()).append(" (depth ").append(depth)
          .append(", ").append(visited.size()).append(" function(s) walked)\n");
        sb.append("signature: ").append(func.getSignature().getPrototypeString()).append('\n');
        sb.append("size: ").append(func.getBody().getNumAddresses()).append(" bytes, ")
          .append(callerCount).append(" caller(s)\n\n");

        sb.append("## imported APIs reached\n");
        if (imports.isEmpty()) {
            sb.append("  (none within depth ").append(depth)
              .append(" - this is pure computation, or the imports are further out)\n");
        }
        for (Map.Entry<String, Integer> e : imports.entrySet()) {
            sb.append("  ").append(e.getKey());
            if (e.getValue() > 1) sb.append(" (x").append(e.getValue()).append(')');
            sb.append('\n');
        }

        sb.append("\n## strings reachable\n");
        if (strings.isEmpty()) sb.append("  (none)\n");
        for (Map.Entry<String, String> e : strings.entrySet()) {
            sb.append("  \"").append(e.getKey()).append("\"  <- ").append(e.getValue()).append('\n');
        }

        sb.append("\n## already-named callers\n");
        sb.append(namedCallers.isEmpty() ? "  (none - nothing that calls this has a name yet)\n"
            : "  " + String.join("\n  ", namedCallers) + "\n");

        sb.append("\n## already-named callees\n");
        sb.append(namedCallees.isEmpty() ? "  (none)\n"
            : "  " + String.join("\n  ", namedCallees) + "\n");

        return sb.toString();
    }

    private boolean isDefaultName(String name) {
        return name == null || name.startsWith("FUN_") || name.startsWith("SUB_")
            || name.startsWith("thunk_FUN_") || name.startsWith("LAB_")
            || name.startsWith("DAT_") || name.startsWith("UNK_");
    }

    private List<String> referencedStrings(Program program, Function func, int max) {
        List<String> out = new ArrayList<>();
        ReferenceManager rm = program.getReferenceManager();
        AddressIterator it = rm.getReferenceSourceIterator(func.getBody(), true);
        while (it.hasNext() && out.size() < max) {
            Address from = it.next();
            for (Reference ref : rm.getReferencesFrom(from)) {
                Data data = program.getListing().getDataAt(ref.getToAddress());
                if (data != null && isStringData(data) && data.getValue() != null) {
                    String s = escapeString(data.getValue().toString());
                    if (s.length() > 120) s = s.substring(0, 120) + "...";
                    if (!out.contains(s)) out.add(s);
                }
            }
        }
        return out;
    }

    /**
     * Mine identifier-shaped strings for function names.
     *
     * Engine builds are full of assert and log format strings that carry the real
     * function or class name of the code that emits them. Where such a string is
     * referenced from exactly one unnamed function, that is a strong naming candidate.
     * Output is deliberately batch_rename-shaped so a human can read it before it is
     * applied.
     */
    private String suggestNamesFromStrings(String filter, int limit, int minLength, boolean apply) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (limit <= 0) limit = 100;
        if (minLength <= 0) minLength = 4;

        Pattern identifier = Pattern.compile(
            "([A-Za-z_][A-Za-z0-9_]{2,}(?:::[A-Za-z_][A-Za-z0-9_]{2,})+)"   // Class::Method
            + "|([A-Za-z_][A-Za-z0-9_]{" + Math.max(2, minLength - 1) + ",})\\s*\\(\\)");  // Name()

        String lower = filter == null ? null : filter.toLowerCase();
        List<String> proposals = new ArrayList<>();
        List<String> rejected = new ArrayList<>();
        Set<String> usedNames = new HashSet<>();
        Map<String, List<String[]>> byAddress = new LinkedHashMap<>();

        DataIterator dataIt = program.getListing().getDefinedData(true);
        while (dataIt.hasNext() && byAddress.size() < limit * 4) {
            Data data = dataIt.next();
            if (data == null || !isStringData(data) || data.getValue() == null) continue;
            String value = data.getValue().toString();
            if (value.length() < minLength) continue;
            if (lower != null && !value.toLowerCase().contains(lower)) continue;

            Matcher m = identifier.matcher(value);
            if (!m.find()) continue;
            String candidate = m.group(1) != null ? m.group(1) : m.group(2);
            if (candidate == null || candidate.length() < minLength) continue;

            Function only = null;
            int refCount = 0;
            ReferenceIterator ri = program.getReferenceManager().getReferencesTo(data.getAddress());
            while (ri.hasNext()) {
                Reference ref = ri.next();
                Function fn = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                if (fn == null) continue;
                refCount++;
                if (only == null) only = fn;
                else if (!only.equals(fn)) { only = null; break; }
            }
            if (only == null || refCount == 0) continue;
            if (!isDefaultName(only.getName())) {
                rejected.add(only.getName() + " already named; string \"" + escapeString(value) + "\"");
                continue;
            }

            String proposed = sanitizeSymbolName(candidate);
            // A string that opens with the identifier ("FExec::Exec failed ...") is far
            // better evidence than one that merely mentions it in passing.
            boolean leading = value.trim().startsWith(candidate);
            byAddress.computeIfAbsent(only.getEntryPoint().toString(), x -> new ArrayList<>())
                     .add(new String[] { proposed, escapeString(value), leading ? "1" : "0" });
        }

        // One function can reference several identifier-shaped strings. Emitting a rename
        // line per string would silently rename it more than once, last one winning.
        for (Map.Entry<String, List<String[]>> e : byAddress.entrySet()) {
            List<String[]> cands = e.getValue();
            Set<String> distinct = new LinkedHashSet<>();
            for (String[] c : cands) distinct.add(c[0]);

            String[] pick = null;
            if (distinct.size() == 1) {
                pick = cands.get(0);
            } else {
                List<String[]> leadingOnes = new ArrayList<>();
                for (String[] c : cands) if ("1".equals(c[2])) leadingOnes.add(c);
                Set<String> leadingNames = new LinkedHashSet<>();
                for (String[] c : leadingOnes) leadingNames.add(c[0]);
                if (leadingNames.size() == 1) pick = leadingOnes.get(0);
            }

            if (pick == null) {
                rejected.add(e.getKey() + " has competing candidates ("
                    + String.join(", ", distinct) + ") - decide by hand");
                continue;
            }
            if (!usedNames.add(pick[0])) {
                rejected.add(pick[0] + " proposed for more than one address, skipped");
                continue;
            }
            proposals.add(e.getKey() + "=" + pick[0] + "\t# \"" + pick[1] + "\"");
            if (proposals.size() >= limit) break;
        }

        if (proposals.isEmpty()) {
            return "No naming candidates found"
                + (filter != null ? " for filter: " + filter : "")
                + (rejected.isEmpty() ? "" : "\n# skipped:\n  " + String.join("\n  ",
                    rejected.subList(0, Math.min(rejected.size(), 20))));
        }

        StringBuilder sb = new StringBuilder();
        sb.append("# ").append(proposals.size()).append(" naming candidate(s)");
        sb.append(apply ? ", applying" : ", NOT applied - review, then pass apply=true or feed "
            + "the address=Name column to batch_rename");
        sb.append("\n").append(String.join("\n", proposals)).append('\n');

        if (apply) {
            StringBuilder entries = new StringBuilder();
            for (String p : proposals) {
                entries.append(p.substring(0, p.indexOf('\t'))).append('\n');
            }
            sb.append("\n").append(batchRename("function", entries.toString()));
        }
        if (!rejected.isEmpty()) {
            sb.append("\n# skipped ").append(rejected.size()).append(":\n  ")
              .append(String.join("\n  ", rejected.subList(0, Math.min(rejected.size(), 20))))
              .append('\n');
        }
        return sb.toString();
    }

    private String sanitizeSymbolName(String raw) {
        StringBuilder sb = new StringBuilder();
        for (char c : raw.toCharArray()) {
            if (Character.isLetterOrDigit(c) || c == '_' || c == ':') sb.append(c);
            else sb.append('_');
        }
        String s = sb.toString();
        if (!s.isEmpty() && Character.isDigit(s.charAt(0))) s = "_" + s;
        return s;
    }

    /**
     * Where did this value come from. Walks the decompiler's definition chain backwards
     * from a variable or from the value produced at an address.
     */
    // Budget and bookkeeping for one trace_value call. Crossing into other functions
    // costs a decompile each, so both the number of functions and wall time are capped.
    private static class TraceCtx {
        int maxCross;
        int functionsLeft;
        int linesLeft;
        long deadline;
        int decompiled;
        final Set<String> seen = new HashSet<>();
        final LinkedHashSet<String> unknowns = new LinkedHashSet<>();
        boolean outOfBudget() {
            return functionsLeft <= 0 || System.currentTimeMillis() > deadline;
        }
    }

    private String traceValue(String addressStr, String variable, int depth,
                              String direction, int cross, int maxFunctions) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Address addr = resolveAddress(program, addressStr);
        if (addr == null) return "Address is required";
        Function func = program.getFunctionManager().getFunctionContaining(addr);
        if (func == null) return "No function found containing " + addr;
        if (depth <= 0) depth = 8;
        if (depth > 40) depth = 40;
        boolean forward = "forward".equalsIgnoreCase(direction);
        if (direction != null && !direction.isEmpty() && !forward
            && !"backward".equalsIgnoreCase(direction)) {
            return "Error: direction must be backward or forward";
        }

        Long outerDeadline = TRACE_DEADLINE.get();
        DecompileResults dr = decompileCached(program, func,
            outerDeadline != null ? Math.min(60, secondsLeft(outerDeadline)) : 60);
        if (dr == null || !dr.decompileCompleted() || dr.getHighFunction() == null) {
            return "Decompilation failed for " + func.getName();
        }
        HighFunction hf = dr.getHighFunction();

        Varnode start = null;
        String what;
        String extra = "";
        if (variable != null && !variable.isEmpty()) {
            Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
            while (it.hasNext()) {
                HighSymbol s = it.next();
                if (s.getName().equals(variable) && s.getHighVariable() != null) {
                    start = s.getHighVariable().getRepresentative();
                    break;
                }
            }
            if (start == null) return "Error: no variable named '" + variable + "' in " + func.getName();
            what = "variable " + variable;
        } else {
            // One instruction lowers to several p-code ops; the result is the op whose
            // output nothing else at this address consumes.
            List<PcodeOp> candidates = new ArrayList<>();
            Iterator<PcodeOpAST> ops = hf.getPcodeOps(addr);
            while (ops.hasNext()) {
                PcodeOp op = ops.next();
                if (op.getOutput() != null) candidates.add(op);
            }
            if (candidates.isEmpty()) {
                return "No p-code operation with an output at " + addr
                    + " - name a variable instead, or pick the instruction that computes the value";
            }
            Set<Integer> consumedHere = new HashSet<>();
            for (PcodeOp op : candidates) {
                Iterator<PcodeOp> uses = op.getOutput().getDescendants();
                while (uses.hasNext()) {
                    PcodeOp use = uses.next();
                    Address useAt = use.getSeqnum() != null ? use.getSeqnum().getTarget() : null;
                    if (useAt != null && useAt.equals(addr)) {
                        consumedHere.add(System.identityHashCode(op.getOutput()));
                        break;
                    }
                }
            }
            PcodeOp chosen = null;
            for (PcodeOp op : candidates) {
                if (!consumedHere.contains(System.identityHashCode(op.getOutput()))) chosen = op;
            }
            if (chosen == null) chosen = candidates.get(candidates.size() - 1);

            start = chosen.getOutput();
            what = "the value produced at " + addr + " (" + chosen.getMnemonic() + ")";
            if (candidates.size() > 1) {
                List<String> others = new ArrayList<>();
                for (PcodeOp op : candidates) {
                    if (op != chosen) others.add(op.getMnemonic());
                }
                extra = "# this instruction also lowered to: " + String.join(", ", others)
                    + " - intermediate steps feeding the result above\n";
            }
        }

        TraceCtx tc = new TraceCtx();
        tc.maxCross = Math.max(0, Math.min(cross, 4));
        tc.functionsLeft = maxFunctions <= 0 ? 8 : Math.min(maxFunctions, 32);
        tc.linesLeft = 600;
        Long outer = TRACE_DEADLINE.get();
        tc.deadline = Math.min(System.currentTimeMillis() + 40_000, outer != null ? outer : Long.MAX_VALUE);

        StringBuilder sb = new StringBuilder();
        if (forward) {
            sb.append("# forward slice for ").append(what).append(" in ").append(func.getName())
              .append("\n# each line uses the line above it\n");
        } else {
            sb.append("# backward slice for ").append(what).append(" in ").append(func.getName())
              .append("\n# each line is what defines the line above it\n");
        }
        sb.append("# crossing up to ").append(tc.maxCross).append(" call level(s), at most ")
          .append(tc.functionsLeft).append(" extra function(s)\n").append(extra);
        if (forward) {
            traceFwd(program, start, 0, depth, sb, tc, 0);
        } else {
            traceBack(program, start, 0, depth, sb, tc, 0);
        }
        if (tc.linesLeft <= 0) tc.unknowns.add("output limit reached - lower depth or cross");
        sb.append("# decompiled ").append(tc.decompiled).append(" other function(s)\n");
        if (!tc.unknowns.isEmpty()) {
            sb.append("# not followed:\n");
            for (String u : tc.unknowns) sb.append("#   ").append(u).append('\n');
        }
        return sb.toString();
    }

    private boolean traceLine(StringBuilder sb, TraceCtx tc, String line) {
        if (tc.linesLeft-- <= 0) return false;
        sb.append(line).append('\n');
        return true;
    }

    /** Decompile another function for a cross-function step, within the trace budget. */
    private HighFunction traceDecompile(Program program, Function f, TraceCtx tc) {
        if (tc.outOfBudget()) {
            tc.unknowns.add("budget exhausted before " + f.getName()
                + " - raise max_functions or narrow the trace");
            return null;
        }
        tc.functionsLeft--;
        long left = (tc.deadline - System.currentTimeMillis()) / 1000;
        DecompileResults r = decompileCached(program, f, (int) Math.max(5, Math.min(20, left)));
        tc.decompiled++;
        if (r == null || !r.decompileCompleted() || r.getHighFunction() == null) {
            tc.unknowns.add("decompile failed for " + f.getName());
            return null;
        }
        return r.getHighFunction();
    }

    /** Direct callee of a CALL op, thunks resolved; null with a reason recorded otherwise. */
    private Function traceCallee(Program program, PcodeOp call, TraceCtx tc) {
        if (call.getOpcode() == PcodeOp.CALLIND) {
            Address at = call.getSeqnum() != null ? call.getSeqnum().getTarget() : null;
            tc.unknowns.add("indirect call at " + at + " - try resolve_virtual_call");
            return null;
        }
        Function callee = program.getFunctionManager().getFunctionAt(call.getInput(0).getAddress());
        if (callee == null) return null;
        if (callee.isThunk()) {
            Function real = callee.getThunkedFunction(true);
            if (real != null) callee = real;
        }
        if (callee.isExternal()) {
            tc.unknowns.add("external " + callee.getName() + " - no code to follow");
            return null;
        }
        return callee;
    }

    /** CALL ops in other functions that call f directly or through one of its thunks. */
    private List<PcodeOp[]> traceCallSites(Program program, Function f, TraceCtx tc,
                                           List<Function> callerOut, List<HighFunction> hfOut) {
        Set<Address> entries = new HashSet<>();
        entries.add(f.getEntryPoint());
        Address[] thunks = f.getFunctionThunkAddresses(true);
        if (thunks != null) entries.addAll(Arrays.asList(thunks));

        List<Reference> sites = new ArrayList<>();
        for (Address e : entries) {
            ReferenceIterator it = program.getReferenceManager().getReferencesTo(e);
            while (it.hasNext()) {
                Reference r = it.next();
                if (r.getReferenceType().isCall()) sites.add(r);
            }
        }
        if (sites.isEmpty()) {
            tc.unknowns.add(f.getName() + " has no direct call sites (virtual or callback?) - "
                + "try find_vtables_containing");
            return Collections.emptyList();
        }
        int cap = 4;
        if (sites.size() > cap) {
            tc.unknowns.add(f.getName() + " has " + sites.size() + " call sites; followed "
                + cap + " - use get_call_sites for the rest");
        }
        List<PcodeOp[]> out = new ArrayList<>();
        for (Reference r : sites.subList(0, Math.min(cap, sites.size()))) {
            Function caller = program.getFunctionManager().getFunctionContaining(r.getFromAddress());
            if (caller == null) continue;
            HighFunction chf = traceDecompile(program, caller, tc);
            if (chf == null) continue;
            Iterator<PcodeOpAST> ops = chf.getPcodeOps(r.getFromAddress());
            while (ops.hasNext()) {
                PcodeOp op = ops.next();
                if (op.getOpcode() == PcodeOp.CALL && entries.contains(op.getInput(0).getAddress())) {
                    out.add(new PcodeOp[] { op });
                    callerOut.add(caller);
                    hfOut.add(chf);
                    break;
                }
            }
        }
        return out;
    }

    // __chkstk / _alloca_probe preserve every argument register by contract.
    private boolean isStackProbe(Program program, Instruction call) {
        for (Address t : call.getFlows()) {
            Function f = program.getFunctionManager().getFunctionAt(t);
            if (f == null) continue;
            String n = f.getName().toLowerCase();
            if (n.contains("chkstk") || n.contains("alloca_probe")) return true;
        }
        return false;
    }

    /**
     * Find a register argument the caller's decompile dropped: walk back from the call
     * through straight-line code to the instruction that sets the register.
     */
    private void argFromDisassembly(Program program, HighVariable param, Function caller,
                                    HighFunction chf, Address callSite, int level, int maxDepth,
                                    StringBuilder sb, TraceCtx tc, int crossLevel) {
        String indent = "  ".repeat(Math.min(level, 20));
        Varnode rep = param.getRepresentative();
        Register reg = rep != null && rep.isRegister() ? program.getRegister(rep.getAddress(), rep.getSize()) : null;
        if (reg == null) {
            traceLine(sb, tc, indent + "(stack-passed argument - not read from disassembly)");
            tc.unknowns.add("stack argument at " + callSite);
            return;
        }
        Register base = reg.getBaseRegister();
        Listing listing = program.getListing();
        Instruction cur = listing.getInstructionAt(callSite);
        for (int steps = 0; cur != null && steps < 64; steps++) {
            if (cur.getAddress().equals(caller.getEntryPoint())) {
                LocalSymbolMap lsm = chf.getLocalSymbolMap();
                for (int i = 0; i < lsm.getNumParams(); i++) {
                    HighSymbol ps = lsm.getParamSymbol(i);
                    if (ps == null || ps.getHighVariable() == null || !ps.getStorage().isRegisterStorage()) continue;
                    if (!ps.getStorage().getRegister().getBaseRegister().equals(base)) continue;
                    traceLine(sb, tc, indent + base.getName() + " is unchanged since " + caller.getName()
                        + " was entered = its parameter " + i);
                    Varnode in = ps.getHighVariable().getRepresentative();
                    for (Varnode v : ps.getHighVariable().getInstances()) if (v.isInput()) in = v;
                    traceBack(program, in, level + 1, maxDepth, sb, tc, crossLevel);
                    return;
                }
                traceLine(sb, tc, indent + base.getName() + " is unchanged since " + caller.getName()
                    + " was entered, but its own signature does not list it either");
                tc.unknowns.add(base.getName() + " on entry to " + caller.getName());
                return;
            }
            ReferenceIterator in = program.getReferenceManager().getReferencesTo(cur.getAddress());
            while (in.hasNext()) {
                Reference r = in.next();
                if (r.getReferenceType().isFlow() && !r.getReferenceType().isCall()) {
                    traceLine(sb, tc, indent + "several paths join at " + cur.getAddress() + " before "
                        + base.getName() + " is set - not followed");
                    tc.unknowns.add(base.getName() + " at the join " + cur.getAddress() + " in " + caller.getName());
                    return;
                }
            }
            Instruction prev = listing.getInstructionBefore(cur.getAddress());
            if (prev == null || !caller.getBody().contains(prev.getAddress())) break;
            if (prev.getFlowType().isCall() && !isStackProbe(program, prev)) {
                traceLine(sb, tc, indent + base.getName() + " is not set between the call at " + prev.getAddress()
                    + " and this one, so it is whatever that call left - not followed");
                tc.unknowns.add(base.getName() + " after the call at " + prev.getAddress());
                return;
            }
            for (Object o : prev.getResultObjects()) {
                if (o instanceof Register r && r.getBaseRegister().equals(base)) {
                    traceLine(sb, tc, indent + base.getName() + " set by " + prev + "  @ " + prev.getAddress());
                    Iterator<PcodeOpAST> ops = chf.getPcodeOps(prev.getAddress());
                    while (ops.hasNext()) {
                        PcodeOp op = ops.next();
                        Varnode out = op.getOutput();
                        if (out != null && out.isRegister()) {
                            Register w = program.getRegister(out.getAddress(), out.getSize());
                            if (w != null && w.getBaseRegister().equals(base)) {
                                for (int k = 0; k < op.getNumInputs(); k++) {
                                    traceBack(program, op.getInput(k), level + 1, maxDepth, sb, tc, crossLevel);
                                }
                                return;
                            }
                        }
                    }
                    tc.unknowns.add("source of " + prev + " @ " + prev.getAddress() + " (dropped by the decompiler)");
                    return;
                }
            }
            cur = prev;
        }
        traceLine(sb, tc, indent + "could not find where " + base.getName() + " is set");
        tc.unknowns.add(base.getName() + " before " + callSite);
    }

    private void traceBack(Program program, Varnode vn, int level, int maxDepth,
                           StringBuilder sb, TraceCtx tc, int crossLevel) {
        if (vn == null || level > maxDepth || tc.linesLeft <= 0) return;
        String indent = "  ".repeat(Math.min(level, 20));
        if (!tc.seen.add(System.identityHashCode(vn) + "@" + level)) {
            traceLine(sb, tc, indent + "(already shown)");
            return;
        }

        if (vn.isConstant()) {
            String meaning = resolveConstantMeaning(program, vn.getOffset());
            traceLine(sb, tc, indent + "constant " + formatConstant(vn.getOffset())
                + (meaning != null ? "  -> " + meaning : ""));
            return;
        }

        PcodeOp def = vn.getDef();
        if (def != null && def.getOpcode() == PcodeOp.INDIRECT) {
            tc.unknowns.add("values passing calls that might modify them (INDIRECT) were followed as unchanged");
            traceBack(program, def.getInput(0), level, maxDepth, sb, tc, crossLevel);
            return;
        }
        if (def == null) {
            HighVariable hv = vn.getHigh();
            String label = hv != null && hv.getName() != null ? hv.getName() : vn.toString();
            StringBuilder line = new StringBuilder(indent).append("input/undefined: ").append(label);
            if (vn.isRegister()) {
                Register reg = program.getRegister(vn.getAddress(), vn.getSize());
                if (reg != null) line.append(" (register ").append(reg.getName()).append(')');
            }
            if (hv instanceof ghidra.program.model.pcode.HighParam hp && hv.getHighFunction() != null) {
                Function owner = hv.getHighFunction().getFunction();
                line.append(" = parameter ").append(hp.getSlot()).append(" of ").append(owner.getName());
                traceLine(sb, tc, line.toString());
                if (crossLevel < tc.maxCross) {
                    List<Function> callers = new ArrayList<>();
                    List<HighFunction> callerHfs = new ArrayList<>();
                    List<PcodeOp[]> calls = traceCallSites(program, owner, tc, callers, callerHfs);
                    for (int i = 0; i < calls.size(); i++) {
                        PcodeOp call = calls.get(i)[0];
                        int slot = hp.getSlot() + 1;
                        String site = indent + "  <= " + callers.get(i).getName() + " passes it at "
                            + call.getSeqnum().getTarget();
                        if (slot >= call.getNumInputs()) {
                            traceLine(sb, tc, site + " - not in the caller's decompiled call ("
                                + owner.getName() + "'s stored signature lacks it); from disassembly:");
                            argFromDisassembly(program, hp, callers.get(i), callerHfs.get(i),
                                call.getSeqnum().getTarget(), level + 2, maxDepth + 2, sb, tc, crossLevel + 1);
                            continue;
                        }
                        traceLine(sb, tc, site);
                        traceBack(program, call.getInput(slot), level + 2, maxDepth + 2, sb, tc,
                            crossLevel + 1);
                    }
                } else if (tc.maxCross > 0) {
                    tc.unknowns.add("callers of " + owner.getName() + " (cross limit)");
                }
                return;
            }
            traceLine(sb, tc, line.toString());
            return;
        }

        Address at = def.getSeqnum() != null ? def.getSeqnum().getTarget() : null;
        StringBuilder line = new StringBuilder(indent).append(def.getMnemonic());
        if (at != null) line.append("  @ ").append(at);
        boolean isCall = def.getOpcode() == PcodeOp.CALL || def.getOpcode() == PcodeOp.CALLIND;
        Function named = null;
        if (def.getOpcode() == PcodeOp.CALL && def.getNumInputs() > 0 && def.getInput(0) != null) {
            named = program.getFunctionManager().getFunctionAt(def.getInput(0).getAddress());
            if (named != null) line.append("  ").append(named.getName()).append("()");
        }
        traceLine(sb, tc, line.toString());

        if (isCall) {
            // The value is the call's return value: continue inside the callee.
            if (crossLevel >= tc.maxCross) {
                if (tc.maxCross > 0 && named != null) {
                    tc.unknowns.add("return value of " + named.getName() + " (cross limit)");
                }
                return;
            }
            Function callee = traceCallee(program, def, tc);
            if (callee == null) return;
            HighFunction chf = traceDecompile(program, callee, tc);
            if (chf == null) return;
            List<Varnode> rets = new ArrayList<>();
            Iterator<PcodeOpAST> all = chf.getPcodeOps();
            while (all.hasNext()) {
                PcodeOp op = all.next();
                if (op.getOpcode() == PcodeOp.RETURN && op.getNumInputs() > 1) rets.add(op.getInput(1));
            }
            if (rets.isEmpty()) {
                traceLine(sb, tc, indent + "  => " + callee.getName()
                    + " returns nothing the decompiler recovered");
                return;
            }
            traceLine(sb, tc, indent + "  => inside " + callee.getName() + " ("
                + rets.size() + " return site(s))");
            for (Varnode r : rets.subList(0, Math.min(4, rets.size()))) {
                traceBack(program, r, level + 2, maxDepth + 2, sb, tc, crossLevel + 1);
            }
            if (rets.size() > 4) tc.unknowns.add((rets.size() - 4) + " more return sites in " + callee.getName());
            return;
        }
        for (int i = 0; i < def.getNumInputs(); i++) {
            if (def.getOpcode() == PcodeOp.LOAD && i == 0) continue; // address space id
            if (def.getOpcode() == PcodeOp.INDIRECT && i == 1) continue; // op reference
            traceBack(program, def.getInput(i), level + 1, maxDepth, sb, tc, crossLevel);
        }
    }

    // The call a forward trace entered a callee through; RETURN resumes there.
    private record RetSite(Varnode out, Function caller, RetSite parent) { }

    private void traceFwd(Program program, Varnode vn, int level, int maxDepth,
                          StringBuilder sb, TraceCtx tc, int crossLevel) {
        traceFwd(program, vn, level, maxDepth, sb, tc, crossLevel, null);
    }

    private static String constInputs(PcodeOp op, Varnode except) {
        List<String> c = new ArrayList<>();
        int opc = op.getOpcode();
        for (int i = 0; i < op.getNumInputs(); i++) {
            Varnode in = op.getInput(i);
            if (in == null || in == except || !in.isConstant()) continue;
            if ((opc == PcodeOp.LOAD || opc == PcodeOp.STORE) && i == 0) continue;
            if ((opc == PcodeOp.CALL || opc == PcodeOp.CALLIND) && i == 0) continue;
            c.add("0x" + Long.toHexString(in.getOffset()));
        }
        return c.isEmpty() ? "" : "  [" + String.join(", ", c) + "]";
    }

    private void traceFwd(Program program, Varnode vn, int level, int maxDepth,
                          StringBuilder sb, TraceCtx tc, int crossLevel, RetSite ret) {
        if (vn == null || level > maxDepth || tc.linesLeft <= 0) return;
        if (!tc.seen.add("f" + System.identityHashCode(vn))) return;
        String indent = "  ".repeat(Math.min(level, 20));

        List<PcodeOp> uses = new ArrayList<>();
        Iterator<PcodeOp> it = vn.getDescendants();
        while (it.hasNext()) uses.add(it.next());
        uses.sort(Comparator.comparing(o -> o.getSeqnum()));

        for (PcodeOp use : uses) {
            if (tc.linesLeft <= 0) return;
            Address at = use.getSeqnum() != null ? use.getSeqnum().getTarget() : null;
            int opc = use.getOpcode();
            if (opc == PcodeOp.INDIRECT) {
                if (use.getOutput() != null) traceFwd(program, use.getOutput(), level, maxDepth, sb, tc, crossLevel, ret);
                continue;
            }
            String head = indent + use.getMnemonic() + (at != null ? "  @ " + at : "") + constInputs(use, vn);

            if (opc == PcodeOp.CALL || opc == PcodeOp.CALLIND) {
                int slot = -1;
                for (int i = 1; i < use.getNumInputs(); i++) if (use.getInput(i) == vn) { slot = i - 1; break; }
                if (slot < 0) {
                    traceLine(sb, tc, head + "  (is the call target)");
                    continue;
                }
                Function callee = opc == PcodeOp.CALL
                    ? program.getFunctionManager().getFunctionAt(use.getInput(0).getAddress()) : null;
                traceLine(sb, tc, head + "  passed as argument " + slot
                    + (callee != null ? " to " + callee.getName() + "()" : ""));
                if (crossLevel >= tc.maxCross) {
                    if (tc.maxCross > 0 && callee != null) tc.unknowns.add("use inside " + callee.getName() + " (cross limit)");
                    continue;
                }
                Function real = traceCallee(program, use, tc);
                if (real == null) continue;
                HighFunction chf = traceDecompile(program, real, tc);
                if (chf == null) continue;
                LocalSymbolMap lsm = chf.getLocalSymbolMap();
                if (slot >= lsm.getNumParams() || lsm.getParamSymbol(slot) == null
                    || lsm.getParamSymbol(slot).getHighVariable() == null) {
                    traceLine(sb, tc, indent + "  => " + real.getName() + " never reads parameter " + slot);
                    continue;
                }
                HighVariable p = lsm.getParamSymbol(slot).getHighVariable();
                traceLine(sb, tc, indent + "  => inside " + real.getName() + " as " + p.getName());
                Function here = vn.getHigh() != null && vn.getHigh().getHighFunction() != null
                    ? vn.getHigh().getHighFunction().getFunction() : null;
                RetSite back = new RetSite(use.getOutput(), here, ret);
                for (Varnode inst : p.getInstances()) {
                    traceFwd(program, inst, level + 2, maxDepth + 2, sb, tc, crossLevel + 1, back);
                }
                continue;
            }
            if (opc == PcodeOp.STORE) {
                traceLine(sb, tc, head + (use.getInput(1) == vn
                    ? "  used as the address written to"
                    : "  written to memory - not followed (find_field_accesses / get_xrefs_to)"));
                continue;
            }
            if (opc == PcodeOp.CBRANCH || opc == PcodeOp.BRANCHIND) {
                traceLine(sb, tc, head + "  decides a branch");
                continue;
            }
            if (opc == PcodeOp.RETURN) {
                Function owner = vn.getHigh() != null && vn.getHigh().getHighFunction() != null
                    ? vn.getHigh().getHighFunction().getFunction() : null;
                traceLine(sb, tc, head + "  returned" + (owner != null ? " from " + owner.getName() : ""));
                if (ret != null) {
                    if (ret.out() == null) {
                        traceLine(sb, tc, indent + "  => " + (ret.caller() != null ? ret.caller().getName() : "caller")
                            + " ignores the result");
                    } else {
                        traceLine(sb, tc, indent + "  => back in " + (ret.caller() != null ? ret.caller().getName() : "caller")
                            + " as the call's result");
                        traceFwd(program, ret.out(), level + 2, maxDepth + 2, sb, tc, crossLevel, ret.parent());
                    }
                    continue;
                }
                if (owner == null) continue;
                if (crossLevel >= tc.maxCross) {
                    if (tc.maxCross > 0) tc.unknowns.add("callers' use of " + owner.getName() + "'s result (cross limit)");
                    continue;
                }
                List<Function> callers = new ArrayList<>();
                List<PcodeOp[]> calls = traceCallSites(program, owner, tc, callers, new ArrayList<>());
                for (int i = 0; i < calls.size(); i++) {
                    PcodeOp call = calls.get(i)[0];
                    traceLine(sb, tc, indent + "  => " + callers.get(i).getName() + " receives it at "
                        + call.getSeqnum().getTarget());
                    if (call.getOutput() != null) {
                        traceFwd(program, call.getOutput(), level + 2, maxDepth + 2, sb, tc, crossLevel + 1, null);
                    } else {
                        traceLine(sb, tc, indent + "    (result ignored)");
                    }
                }
                continue;
            }
            String note = opc == PcodeOp.LOAD && use.getInput(1) == vn ? "  dereferenced" : "";
            traceLine(sb, tc, head + note);
            if (use.getOutput() != null) traceFwd(program, use.getOutput(), level + 1, maxDepth, sb, tc, crossLevel, ret);
        }
    }

    // ==================================================================================
    // Cross-binary matching
    // ==================================================================================

    /**
     * Match functions between two open programs by structural hash, so names carry
     * across builds. Addresses shift on every patch; the shape of the code usually
     * does not.
     */
    private String matchFunctions(String fromWant, String toWant, int minInstructions,
                                  boolean apply, int limit) {
        final Program from;
        final Program to;
        try {
            from = resolveProgram(fromWant);
            to = resolveProgram(toWant);
        } catch (NoSuchProgramException e) {
            return "Error: " + e.getMessage();
        }
        if (from == null || to == null) return "Error: both from and to must name an open program";
        if (from == to) return "Error: from and to are the same program (" + programLabel(from) + ")";
        if (minInstructions <= 0) minInstructions = 8;
        if (limit <= 0) limit = 500;

        Map<Long, List<Function>> fromHashes = hashFunctions(from, minInstructions);
        Map<Long, List<Function>> toHashes = hashFunctions(to, minInstructions);

        List<String> matches = new ArrayList<>();
        List<String> renameEntries = new ArrayList<>();
        int ambiguous = 0;
        int alreadyNamed = 0;
        int unnamedSource = 0;

        for (Map.Entry<Long, List<Function>> e : fromHashes.entrySet()) {
            List<Function> src = e.getValue();
            List<Function> dst = toHashes.get(e.getKey());
            if (dst == null) continue;
            if (src.size() != 1 || dst.size() != 1) { ambiguous++; continue; }
            Function a = src.get(0);
            Function b = dst.get(0);
            if (isDefaultName(a.getName())) { unnamedSource++; continue; }
            if (!isDefaultName(b.getName())) { alreadyNamed++; continue; }
            if (matches.size() >= limit) break;
            matches.add(String.format("%s\t%s\t%s\t%d instrs", a.getName(),
                a.getEntryPoint(), b.getEntryPoint(), countInstructions(from, a)));
            renameEntries.add(b.getEntryPoint() + "=" + a.getName());
        }

        StringBuilder sb = new StringBuilder();
        sb.append("# matching ").append(programLabel(from)).append(" -> ")
          .append(programLabel(to)).append('\n');
        sb.append("# ").append(fromHashes.size()).append(" distinct shapes in source, ")
          .append(toHashes.size()).append(" in target, minimum ").append(minInstructions)
          .append(" instructions\n");
        sb.append("# ").append(matches.size()).append(" confident match(es); skipped ")
          .append(ambiguous).append(" ambiguous, ").append(unnamedSource)
          .append(" with no name to carry, ").append(alreadyNamed)
          .append(" already named in target\n");

        if (matches.isEmpty()) {
            sb.append("\nNothing to carry across. If both binaries are stripped, name things in "
                + "the source first - this only propagates names that already exist.");
            return sb.toString();
        }

        sb.append("# name\tfrom_addr\tto_addr\tsize\n");
        sb.append(String.join("\n", matches)).append('\n');

        if (apply) {
            String err = inTransaction(to, "Apply matched names from " + programLabel(from), () -> {
                for (String entry : renameEntries) {
                    int eq = entry.indexOf('=');
                    Address addr = resolveAddress(to, entry.substring(0, eq));
                    if (addr == null) continue;
                    Function f = to.getFunctionManager().getFunctionAt(addr);
                    if (f != null) f.setName(entry.substring(eq + 1), SourceType.USER_DEFINED);
                }
            });
            sb.append(err == null
                ? "\nApplied " + renameEntries.size() + " name(s) to " + programLabel(to)
                  + " in one transaction (undo reverses all of them)."
                : "\nApply failed: " + err);
        } else {
            sb.append("\nNot applied. Review, then call again with apply=true, or feed the "
                + "to_addr=name columns to batch_rename with program=" + programLabel(to) + ".");
        }
        return sb.toString();
    }

    /**
     * Hash a function by the shape of its code: mnemonic sequence plus operand kinds,
     * with addresses and immediates deliberately excluded so the hash survives rebasing
     * and constant changes between builds.
     */
    private Map<Long, List<Function>> hashFunctions(Program program, int minInstructions) {
        Map<Long, List<Function>> out = new HashMap<>();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        Listing listing = program.getListing();
        while (it.hasNext()) {
            Function f = it.next();
            if (f.isExternal() || f.isThunk()) continue;
            long hash = 0xcbf29ce484222325L;
            int count = 0;
            InstructionIterator instrs = listing.getInstructions(f.getBody(), true);
            while (instrs.hasNext()) {
                Instruction instr = instrs.next();
                hash = fnv(hash, instr.getMnemonicString());
                for (int i = 0; i < instr.getNumOperands(); i++) {
                    int kind = 0;
                    for (Object o : instr.getOpObjects(i)) {
                        if (o instanceof Register) kind |= 1;
                        else if (o instanceof Scalar) kind |= 2;
                        else if (o instanceof Address) kind |= 4;
                    }
                    hash = fnv(hash, Integer.toString(kind));
                }
                count++;
            }
            if (count < minInstructions) continue;
            hash = fnv(hash, "n" + count);
            out.computeIfAbsent(hash, k -> new ArrayList<>()).add(f);
        }
        return out;
    }

    private long fnv(long hash, String s) {
        for (int i = 0; i < s.length(); i++) {
            hash ^= s.charAt(i);
            hash *= 0x100000001b3L;
        }
        return hash;
    }

    private int countInstructions(Program program, Function f) {
        int n = 0;
        InstructionIterator it = program.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) { it.next(); n++; }
        return n;
    }

    // ==================================================================================
    // Patch emission
    // ==================================================================================

    /**
     * Emit a verified Python patcher for a set of byte edits.
     *
     * Deliberately produces a script rather than writing bytes directly: the script
     * checks a window of surrounding bytes before it touches anything, backs the file
     * up, re-verifies from disk afterwards, and can revert. A patcher that refuses to
     * run on a build it does not recognise is worth more than one that silently
     * corrupts the wrong executable.
     */
    private String generatePatchScript(String edits, String scriptName, int window) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (edits == null || edits.trim().isEmpty()) {
            return "Error: edits is required, as \"VA:old_bytes->new_bytes\" separated by "
                + "newlines or ';', e.g. \"0x140463F4F:0F 84->90 E9\"";
        }
        if (window <= 0 || window > 64) window = 12;

        List<String> py = new ArrayList<>();
        List<String> report = new ArrayList<>();
        int index = 0;

        for (String raw : edits.split("[;\n]")) {
            String line = raw.trim();
            if (line.isEmpty()) continue;
            int colon = line.indexOf(':');
            int arrow = line.indexOf("->");
            if (colon < 0 || arrow < 0 || arrow < colon) {
                return "Error: cannot parse edit '" + line + "', expected VA:old->new";
            }
            String vaPart = line.substring(0, colon).trim();
            String oldPart = line.substring(colon + 1, arrow).trim();
            String newPart = line.substring(arrow + 2).trim();

            Address addr = resolveAddress(program, vaPart);
            if (addr == null) return "Error: bad address in '" + line + "'";

            byte[] oldBytes = parsePlainBytes(oldPart);
            byte[] newBytes = parsePlainBytes(newPart);
            if (oldBytes == null || newBytes == null) {
                return "Error: bad byte list in '" + line + "' (use hex like \"0F 84\")";
            }
            if (oldBytes.length != newBytes.length) {
                return "Error: '" + line + "' changes length (" + oldBytes.length + " -> "
                    + newBytes.length + "). Instruction length must be preserved; pad with "
                    + "0x90 NOPs if needed.";
            }

            byte[] actual = new byte[oldBytes.length];
            try {
                program.getMemory().getBytes(addr, actual);
            } catch (Exception e) {
                return "Error: cannot read " + oldBytes.length + " bytes at " + addr;
            }
            if (!Arrays.equals(actual, oldBytes)) {
                return "Error: at " + addr + " the program contains " + toHexBytes(actual)
                    + " but the edit expects " + toHexBytes(oldBytes)
                    + ". Refusing to emit a patcher built on a wrong assumption.";
            }

            String offsetInfo = fileOffset(addr.toString(), null);
            long fileOff;
            try {
                String marker = "file 0x";
                int at = offsetInfo.indexOf(marker);
                if (at < 0) return "Error: " + offsetInfo;
                String hex = offsetInfo.substring(at + marker.length()).split("[^0-9a-fA-F]")[0];
                fileOff = Long.parseLong(hex, 16);
            } catch (Exception e) {
                return "Error: could not resolve a file offset for " + addr + ": " + offsetInfo;
            }

            byte[] before = new byte[window];
            byte[] after = new byte[window];
            boolean haveContext = true;
            try {
                program.getMemory().getBytes(addr.subtract(window), before);
                program.getMemory().getBytes(addr.add(oldBytes.length), after);
            } catch (Exception e) {
                haveContext = false;
            }

            Function fn = program.getFunctionManager().getFunctionContaining(addr);
            py.add(String.format(
                "    Edit(\n"
                + "        name=%s,\n"
                + "        va=0x%s,\n"
                + "        file_offset=0x%s,\n"
                + "        original=bytes.fromhex(\"%s\"),\n"
                + "        patched=bytes.fromhex(\"%s\"),\n"
                + "        context_before=bytes.fromhex(\"%s\"),\n"
                + "        context_after=bytes.fromhex(\"%s\"),\n"
                + "    ),",
                pyQuote(fn != null
                    ? fn.getName() + "+0x" + Long.toHexString(addr.subtract(fn.getEntryPoint()))
                    : "edit_" + index),
                Long.toHexString(addr.getOffset()),
                Long.toHexString(fileOff),
                hexNoSpace(oldBytes), hexNoSpace(newBytes),
                haveContext ? hexNoSpace(before) : "",
                haveContext ? hexNoSpace(after) : ""));

            report.add(String.format("%s -> file 0x%s  %s -> %s  %s", addr,
                Long.toHexString(fileOff), toHexBytes(oldBytes), toHexBytes(newBytes),
                fn != null ? fn.getName() : ""));
            index++;
        }

        if (py.isEmpty()) return "Error: no edits parsed";

        String target = program.getExecutablePath();
        String targetName = target != null && target.contains("\\")
            ? target.substring(target.lastIndexOf('\\') + 1)
            : (target != null && target.contains("/")
                ? target.substring(target.lastIndexOf('/') + 1) : programLabel(program));
        String sha = program.getExecutableSHA256();

        StringBuilder sb = new StringBuilder();
        sb.append("# ").append(index).append(" edit(s) verified against the program in Ghidra:\n# ")
          .append(String.join("\n# ", report)).append('\n');
        sb.append("# Save the script below as ")
          .append(scriptName == null || scriptName.isEmpty() ? "patch.py" : scriptName)
          .append(" and run it against ").append(targetName).append("\n\n");

        sb.append("#!/usr/bin/env python3\n");
        sb.append("\"\"\"Generated by GhidraMCP from ").append(programLabel(program))
          .append(".\n\nEvery edit is length-preserving and is verified against a window of\n")
          .append("surrounding bytes before anything is written. The script refuses to run on a\n")
          .append("build it does not recognise.\n\"\"\"\n\n");
        sb.append("import argparse\nimport hashlib\nimport shutil\nimport sys\n");
        sb.append("from dataclasses import dataclass, field\nfrom pathlib import Path\n\n");
        sb.append("EXPECTED_SHA256 = ").append(sha != null && !sha.isEmpty()
            ? "\"" + sha + "\"" : "None").append("\n\n");
        sb.append("@dataclass\nclass Edit:\n    name: str\n    va: int\n    file_offset: int\n");
        sb.append("    original: bytes\n    patched: bytes\n");
        sb.append("    context_before: bytes = b\"\"\n    context_after: bytes = b\"\"\n\n");
        sb.append("EDITS = [\n").append(String.join("\n", py)).append("\n]\n\n");
        sb.append(PATCH_SCRIPT_BODY);
        return sb.toString();
    }

    private static final String PATCH_SCRIPT_BODY =
        "def _window(data: bytes, e: Edit, patched: bool) -> tuple[bytes, bytes]:\n"
        + "    start = max(0, e.file_offset - len(e.context_before))\n"
        + "    expect_mid = e.patched if patched else e.original\n"
        + "    got = data[start:e.file_offset + len(expect_mid) + len(e.context_after)]\n"
        + "    want = e.context_before + expect_mid + e.context_after\n"
        + "    return got, want\n\n"
        + "def check(data: bytes, patched: bool) -> list[str]:\n"
        + "    problems = []\n"
        + "    for e in EDITS:\n"
        + "        got, want = _window(data, e, patched)\n"
        + "        if got != want:\n"
        + "            problems.append(\n"
        + "                f\"{e.name} at file 0x{e.file_offset:x} (VA 0x{e.va:x}):\\n\"\n"
        + "                f\"    expected {want.hex(' ')}\\n\"\n"
        + "                f\"    found    {got.hex(' ')}\"\n"
        + "            )\n"
        + "    return problems\n\n"
        + "def main() -> int:\n"
        + "    ap = argparse.ArgumentParser(description=__doc__)\n"
        + "    ap.add_argument(\"target\", type=Path)\n"
        + "    ap.add_argument(\"--check\", action=\"store_true\", help=\"verify only, write nothing\")\n"
        + "    ap.add_argument(\"--revert\", action=\"store_true\", help=\"undo the patch\")\n"
        + "    ap.add_argument(\"--force\", action=\"store_true\", help=\"skip the SHA-256 check\")\n"
        + "    args = ap.parse_args()\n\n"
        + "    data = bytearray(args.target.read_bytes())\n"
        + "    digest = hashlib.sha256(data).hexdigest()\n\n"
        + "    if EXPECTED_SHA256 and digest != EXPECTED_SHA256 and not args.force:\n"
        + "        already = not check(bytes(data), patched=True)\n"
        + "        if not already:\n"
        + "            print(f\"Refusing to touch this file.\\n\"\n"
        + "                  f\"  expected SHA-256 {EXPECTED_SHA256}\\n\"\n"
        + "                  f\"  found            {digest}\\n\"\n"
        + "                  f\"This is a different build. The offsets here do not apply to it.\")\n"
        + "            return 2\n\n"
        + "    want_patched = args.revert\n"
        + "    problems = check(bytes(data), patched=want_patched)\n"
        + "    state = \"patched\" if want_patched else \"original\"\n"
        + "    if problems:\n"
        + "        print(f\"File is not in the expected {state} state:\\n\" + \"\\n\".join(problems))\n"
        + "        return 3\n\n"
        + "    if args.check:\n"
        + "        print(f\"All {len(EDITS)} site(s) match the expected {state} bytes. Nothing written.\")\n"
        + "        return 0\n\n"
        + "    backup = args.target.with_suffix(args.target.suffix + \".bak\")\n"
        + "    if not backup.exists():\n"
        + "        shutil.copy2(args.target, backup)\n"
        + "        print(f\"Backed up to {backup}\")\n\n"
        + "    for e in EDITS:\n"
        + "        new = e.original if args.revert else e.patched\n"
        + "        data[e.file_offset:e.file_offset + len(new)] = new\n"
        + "        print(f\"{'reverted' if args.revert else 'patched '} {e.name} \"\n"
        + "              f\"at file 0x{e.file_offset:x} (VA 0x{e.va:x})\")\n\n"
        + "    args.target.write_bytes(bytes(data))\n\n"
        + "    verify = bytearray(args.target.read_bytes())\n"
        + "    problems = check(bytes(verify), patched=not args.revert)\n"
        + "    if problems:\n"
        + "        print(\"Re-read after writing does not match. Restoring backup.\\n\"\n"
        + "              + \"\\n\".join(problems))\n"
        + "        shutil.copy2(backup, args.target)\n"
        + "        return 4\n\n"
        + "    print(f\"Done. {len(EDITS)} site(s) {'reverted' if args.revert else 'patched'} \"\n"
        + "          f\"and verified from disk.\")\n"
        + "    return 0\n\n"
        + "if __name__ == \"__main__\":\n"
        + "    sys.exit(main())\n";

    private byte[] parsePlainBytes(String text) {
        if (text == null) return null;
        String cleaned = text.replace("\\x", " ").replace("0x", " ").replace(",", " ").trim();
        List<Byte> out = new ArrayList<>();
        if (cleaned.contains(" ")) {
            for (String token : cleaned.split("\\s+")) {
                if (token.isEmpty()) continue;
                if (token.length() != 2) return null;
                try { out.add((byte) Integer.parseInt(token, 16)); }
                catch (NumberFormatException e) { return null; }
            }
        } else {
            if (cleaned.length() % 2 != 0 || cleaned.isEmpty()) return null;
            for (int i = 0; i < cleaned.length(); i += 2) {
                try { out.add((byte) Integer.parseInt(cleaned.substring(i, i + 2), 16)); }
                catch (NumberFormatException e) { return null; }
            }
        }
        if (out.isEmpty()) return null;
        byte[] bytes = new byte[out.size()];
        for (int i = 0; i < out.size(); i++) bytes[i] = out.get(i);
        return bytes;
    }

    private String hexNoSpace(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private String pyQuote(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }


    // ==================================================================================
    // Programs already in the project
    //
    // import_file brings a binary in from disk; select_program switches between programs
    // that are already open. Neither opens a program that is in the project but closed,
    // which is the normal state of every binary analysed in an earlier session.
    // ==================================================================================

    /**
     * Every program in the open Ghidra project, whether or not it is currently open.
     */
    private String listProjectFiles(String filter, int limit) {
        Project project = tool.getProject();
        if (project == null) return "Error: no project is open in this Ghidra instance";
        if (limit <= 0) limit = 200;

        ProgramManager pm = tool.getService(ProgramManager.class);
        Set<String> openPaths = new HashSet<>();
        if (pm != null) {
            for (Program p : pm.getAllOpenPrograms()) {
                DomainFile df = p.getDomainFile();
                if (df != null) openPaths.add(df.getPathname());
            }
        }

        List<String> rows = new ArrayList<>();
        collectProjectFiles(project.getProjectData().getRootFolder(), filter, openPaths, rows, limit);
        if (rows.isEmpty()) {
            return "No program files in the project"
                + (filter != null && !filter.isEmpty() ? " matching: " + filter : "");
        }
        Collections.sort(rows);
        return String.format("# %d file(s) in project '%s' (open\tpath\ttype\tanalyzed)\n",
            rows.size(), project.getName()) + String.join("\n", rows);
    }

    private void collectProjectFiles(DomainFolder folder, String filter, Set<String> openPaths,
                                     List<String> rows, int limit) {
        if (folder == null || rows.size() >= limit) return;
        for (DomainFile df : folder.getFiles()) {
            if (rows.size() >= limit) return;
            String path = df.getPathname();
            if (filter != null && !filter.isEmpty()
                && !path.toLowerCase().contains(filter.toLowerCase())) {
                continue;
            }
            String analyzed = "?";
            try {
                Map<String, String> meta = df.getMetadata();
                if (meta != null) {
                    String a = meta.get("Analyzed");
                    if (a != null) analyzed = a;
                }
            } catch (Exception ignored) { }
            rows.add(String.format("%s\t%s\t%s\t%s",
                openPaths.contains(path) ? "OPEN" : "-", path, df.getContentType(), analyzed));
        }
        for (DomainFolder sub : folder.getFolders()) {
            collectProjectFiles(sub, filter, openPaths, rows, limit);
        }
    }

    /**
     * Open a program that is already in the project.
     *
     * Hidden by default: making a program current is what raises Ghidra's analyse prompt
     * and Analysis Options dialog, both modal, which would block the caller.
     */
    private String openProjectProgram(String path, boolean makeCurrent) {
        Project project = tool.getProject();
        if (project == null) return "Error: no project is open in this Ghidra instance";
        if (path == null || path.trim().isEmpty()) return "Error: path is required";
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return "Error: no program manager service in this tool";

        String want = path.trim();
        DomainFile df = project.getProjectData().getFile(want);
        if (df == null && !want.startsWith("/")) {
            df = project.getProjectData().getFile("/" + want);
        }
        if (df == null) {
            // Fall back to a unique name match, so "CDW.exe" works without the full path.
            List<String> rows = new ArrayList<>();
            collectProjectFiles(project.getProjectData().getRootFolder(), want,
                new HashSet<>(), rows, 50);
            if (rows.size() == 1) {
                df = project.getProjectData().getFile(rows.get(0).split("\t")[1]);
            } else if (rows.size() > 1) {
                return "Error: '" + want + "' matches " + rows.size()
                    + " project files; give the full path. Candidates:\n"
                    + String.join("\n", rows);
            }
        }
        if (df == null) {
            return "Error: no file '" + want + "' in the project - call list_project_files";
        }

        for (Program p : pm.getAllOpenPrograms()) {
            DomainFile open = p.getDomainFile();
            if (open != null && open.getPathname().equals(df.getPathname())) {
                return df.getPathname() + " is already open as " + programLabel(p);
            }
        }

        final DomainFile target = df;
        final Program[] opened = new Program[1];
        final int mode = makeCurrent ? ProgramManager.OPEN_CURRENT : ProgramManager.OPEN_HIDDEN;
        try {
            invokeAndWaitBounded(() -> opened[0] = pm.openProgram(target, -1, mode));
        } catch (InterruptedException | InvocationTargetException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            return "Failed to open " + target.getPathname() + ": " + cause.getMessage();
        }
        if (opened[0] == null) return "Failed to open " + target.getPathname();

        Program p = opened[0];
        return "Opened " + programLabel(p) + (makeCurrent ? " (now current)" : " (hidden)")
            + ": " + p.getFunctionManager().getFunctionCount() + " functions, "
            + (p.getLanguage() != null ? p.getLanguage().getLanguageID() : "?")
            + ", image base " + p.getImageBase()
            + (makeCurrent ? "" : ". Pass make_current=true, or call select_program, to work "
                + "on it without naming program= on every call.");
    }

    /**
     * Close an open program. The counterpart to open_program, so a session can put back
     * what it opened instead of leaving the tool cluttered.
     */
    private String closeProjectProgram(String want, boolean save) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return "No program loaded";
        final Program target;
        try {
            target = resolveProgram(want);
        } catch (NoSuchProgramException e) {
            return "Error: " + e.getMessage();
        }
        if (target == null) return "Error: no such open program: " + want;
        if (target.isChanged() && !save) {
            return "Refusing to close " + programLabel(target) + ": it has unsaved changes. "
                + "Call save_program first, or pass save=true.";
        }
        String label = programLabel(target);
        final boolean[] ok = new boolean[1];
        try {
            invokeAndWaitBounded(() -> {
                if (target.isChanged()) {
                    try {
                        target.save("GhidraMCP save before close", TaskMonitor.DUMMY);
                    } catch (Exception ignored) { }
                }
                ok[0] = pm.closeProgram(target, true);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            return "Failed to close " + label + ": " + cause.getMessage();
        }
        return ok[0] ? "Closed " + label : "Ghidra declined to close " + label;
    }


    // ==================================================================================
    // Build identification
    //
    // Five times in one session the running build had to be worked out by grepping tool
    // descriptions or hashing files on disk, and once a stale component looked exactly
    // like a working one. One call should answer it.
    // ==================================================================================

    private static final String BUILD_ID = "4.6";

    private String versionReport(String bridgeVersion) {
        StringBuilder sb = new StringBuilder();
        sb.append("plugin_build: ").append(BUILD_ID).append('\n');
        sb.append("bridge_build: ")
          .append(bridgeVersion == null || bridgeVersion.isEmpty() ? "(not reported)" : bridgeVersion)
          .append('\n');
        if (bridgeVersion != null && !bridgeVersion.isEmpty() && !bridgeVersion.equals(BUILD_ID)) {
            sb.append("MISMATCH: the bridge and the plugin are different builds. ")
              .append("Restart whichever is behind - a stale half can behave like a working one.\n");
        }
        sb.append("endpoints: ").append(endpointCount).append('\n');
        sb.append("ghidra: ").append(ghidra.framework.Application.getApplicationVersion()).append('\n');
        sb.append("java: ").append(System.getProperty("java.version")).append('\n');
        Program p = getCurrentProgram();
        sb.append("current_program: ").append(p != null ? programLabel(p) : "(none)").append('\n');
        return sb.toString();
    }

    // ==================================================================================
    // Shared view: navigation and bookmarks
    //
    // Lets findings show up in the user's own Ghidra window instead of only in chat.
    // ==================================================================================

    private static final String BOOKMARK_CATEGORY = "Claude";

    private String gotoAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Address addr = resolveAddress(program, addressStr);
        if (addr == null) return "Error: bad or missing address: " + addressStr;
        if (!program.getMemory().contains(addr)) return "Error: " + addr + " is not in program memory";
        ghidra.app.services.GoToService gs = tool.getService(ghidra.app.services.GoToService.class);
        if (gs == null) return "Error: no GoTo service - is a CodeBrowser open?";
        AtomicBoolean ok = new AtomicBoolean(false);
        try {
            invokeAndWaitBounded(() -> ok.set(gs.goTo(addr, program)));
        } catch (InterruptedException | InvocationTargetException e) {
            return "Error: " + e.getMessage();
        }
        if (!ok.get()) return "Ghidra refused to navigate to " + addr;
        Function f = program.getFunctionManager().getFunctionContaining(addr);
        return "Showing " + addr + (f != null ? " (" + f.getName() + ")" : "")
            + " in " + programLabel(program);
    }

    private String setBookmark(String addressStr, String comment, String category) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Address addr = resolveAddress(program, addressStr);
        if (addr == null) return "Error: bad or missing address: " + addressStr;
        String cat = category == null || category.isBlank() ? BOOKMARK_CATEGORY : category.trim();
        String text = comment == null ? "" : comment;
        final String[] before = new String[1];
        String err = inTransaction(program, "Bookmark " + addr, () -> {
            BookmarkManager bm = program.getBookmarkManager();
            Bookmark old = bm.getBookmark(addr, BookmarkType.NOTE, cat);
            if (old != null) before[0] = old.getComment();
            bm.setBookmark(addr, BookmarkType.NOTE, cat, text);
        });
        if (err != null) return "Bookmark failed: " + err;
        return (before[0] != null ? "Replaced bookmark at " + addr + " (was: " + before[0] + ")"
                                  : "Bookmarked " + addr) + " [" + cat + "] " + text;
    }

    private String listBookmarks(String category, String filter, boolean all, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (limit <= 0) limit = 200;
        String cat = all ? null : (category == null || category.isBlank() ? BOOKMARK_CATEGORY : category.trim());
        String needle = filter == null || filter.isBlank() ? null : filter.toLowerCase();
        List<String> rows = new ArrayList<>();
        int total = 0;
        Iterator<Bookmark> it = program.getBookmarkManager().getBookmarksIterator();
        while (it.hasNext()) {
            Bookmark b = it.next();
            if (cat != null && !cat.equals(b.getCategory())) continue;
            if (all && BookmarkType.ANALYSIS.equals(b.getTypeString()) && needle == null) continue;
            String line = b.getAddress() + "\t" + b.getTypeString() + "\t" + b.getCategory() + "\t"
                + b.getComment();
            if (needle != null && !line.toLowerCase().contains(needle)) continue;
            total++;
            if (rows.size() < limit) {
                Function f = program.getFunctionManager().getFunctionContaining(b.getAddress());
                rows.add(line + (f != null ? "\t(" + f.getName() + ")" : ""));
            }
        }
        if (rows.isEmpty()) {
            return "No bookmarks" + (cat != null ? " in category " + cat : "")
                + (needle != null ? " matching '" + filter + "'" : "");
        }
        return "# " + total + " bookmark(s)" + (total > rows.size() ? ", showing " + rows.size() : "")
            + "\n# address\ttype\tcategory\tcomment\tfunction\n" + String.join("\n", rows);
    }

    private String removeBookmark(String addressStr, String category) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Address addr = resolveAddress(program, addressStr);
        if (addr == null) return "Error: bad or missing address: " + addressStr;
        String cat = category == null || category.isBlank() ? BOOKMARK_CATEGORY : category.trim();
        final String[] removed = new String[1];
        String err = inTransactionAborting(program, "Remove bookmark " + addr, () -> {
            BookmarkManager bm = program.getBookmarkManager();
            Bookmark b = bm.getBookmark(addr, BookmarkType.NOTE, cat);
            if (b == null) return false;
            removed[0] = b.getComment();
            bm.removeBookmark(b);
            return true;
        });
        if (err != null) return "Remove failed: " + err;
        return removed[0] == null ? "No " + cat + " note bookmark at " + addr
                                  : "Removed bookmark at " + addr + ": " + removed[0];
    }

    // ==================================================================================
    // Instruction facts and control flow
    // ==================================================================================

    private static String hexBytes(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(String.format("%02x", x & 0xFF));
        }
        return sb.toString();
    }

    private String inspectInstruction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Address addr = resolveAddress(program, addressStr);
        if (addr == null) return "Error: bad or missing address: " + addressStr;
        Listing listing = program.getListing();
        Instruction ins = listing.getInstructionContaining(addr);
        if (ins == null) {
            Data d = listing.getDataContaining(addr);
            if (d != null && d.isDefined()) {
                return addr + " is data (" + d.getDataType().getName() + " at " + d.getAddress() + "), not code";
            }
            return program.getMemory().contains(addr)
                ? addr + " is not disassembled - use disassemble_range or create_function first"
                : "Error: " + addr + " is not in program memory";
        }
        StringBuilder sb = new StringBuilder();
        if (!ins.getAddress().equals(addr)) {
            sb.append("# NOTE: ").append(addr).append(" is inside this instruction (+")
              .append(addr.subtract(ins.getAddress())).append("), not its start\n");
        }
        Address at = ins.getAddress();
        Function f = program.getFunctionManager().getFunctionContaining(at);
        sb.append("address: ").append(at);
        if (f != null) sb.append("  (").append(f.getName()).append(" +0x")
            .append(Long.toHexString(at.subtract(f.getEntryPoint()))).append(')');
        sb.append('\n');
        String fo = fileOffset(at.toString(), null);
        if (fo.startsWith("VA ")) sb.append("file_offset: ").append(fo.replaceAll("^VA \\S+ -> file (\\S+).*$", "$1")).append('\n');
        byte[] bytes;
        try {
            bytes = ins.getBytes();
        } catch (Exception e) {
            return "Error reading bytes at " + at + ": " + e.getMessage();
        }
        sb.append("bytes: ").append(hexBytes(bytes)).append("  (").append(bytes.length).append(" bytes)\n");
        sb.append("text: ").append(ins.toString()).append('\n');
        ghidra.program.model.symbol.FlowType ft = ins.getFlowType();
        sb.append("flow: ").append(ft.getName());
        if (ins.getFallThrough() != null) sb.append("  fallthrough: ").append(ins.getFallThrough());
        sb.append('\n');
        Address[] flows = ins.getFlows();
        if (flows != null && flows.length > 0) {
            List<String> t = new ArrayList<>();
            for (Address a : flows) {
                Function tf = program.getFunctionManager().getFunctionAt(a);
                t.add(a + (tf != null ? " " + tf.getName() : ""));
            }
            sb.append("targets: ").append(String.join(", ", t)).append('\n');
        }
        for (int i = 0; i < ins.getNumOperands(); i++) {
            sb.append("operand ").append(i).append(": ").append(ins.getDefaultOperandRepresentation(i))
              .append("  [").append(ghidra.program.model.lang.OperandType.toString(ins.getOperandType(i)))
              .append(']');
            List<String> parts = new ArrayList<>();
            for (Object o : ins.getOpObjects(i)) {
                if (o instanceof Register r) parts.add("reg " + r.getName());
                else if (o instanceof Scalar s) parts.add("scalar " + formatConstant(s.getValue()));
                else if (o instanceof Address a) parts.add("addr " + a);
            }
            if (!parts.isEmpty()) sb.append("  ").append(String.join(", ", parts));
            sb.append('\n');
        }
        Reference[] refs = ins.getReferencesFrom();
        for (Reference r : refs) {
            sb.append("ref: -> ").append(r.getToAddress()).append(' ').append(r.getReferenceType().getName());
            Symbol s = program.getSymbolTable().getPrimarySymbol(r.getToAddress());
            if (s != null) sb.append(' ').append(s.getName());
            sb.append('\n');
        }
        String hints = x86PatchHints(program, ins, bytes);
        if (hints != null) sb.append(hints);
        return sb.toString();
    }

    /** Byte-level patch options for x86 control flow; null for anything else. */
    private String x86PatchHints(Program program, Instruction ins, byte[] b) {
        String proc = program.getLanguage().getProcessor().toString().toLowerCase();
        if (!proc.contains("x86")) return null;
        int n = b.length;
        String nops = hexBytes(repeat((byte) 0x90, n));
        int op0 = b[0] & 0xFF;
        StringBuilder sb = new StringBuilder("patch options (x86, same length):\n");
        if (n == 2 && op0 >= 0x70 && op0 <= 0x7F) {
            sb.append("  never jump : ").append(nops).append('\n');
            sb.append("  always jump: eb ").append(String.format("%02x", b[1] & 0xFF)).append('\n');
            sb.append("  invert     : ").append(String.format("%02x %02x", op0 ^ 1, b[1] & 0xFF)).append('\n');
        } else if (n == 6 && op0 == 0x0F && (b[1] & 0xF0) == 0x80) {
            String rel = hexBytes(Arrays.copyOfRange(b, 2, 6));
            sb.append("  never jump : ").append(nops).append('\n');
            sb.append("  always jump: 90 e9 ").append(rel).append('\n');
            sb.append("  invert     : 0f ").append(String.format("%02x", (b[1] & 0xFF) ^ 1)).append(' ').append(rel).append('\n');
        } else if (ins.getFlowType().isCall()) {
            sb.append("  remove call: ").append(nops)
              .append("  (the return register keeps whatever it held before)\n");
        } else if (ins.getFlowType().isTerminal() || ins.getFlowType().isJump()) {
            return null;
        } else {
            sb.append("  remove     : ").append(nops).append('\n');
        }
        sb.append("  generate_patch_script edit: ").append(ins.getAddress()).append(':')
          .append(hexBytes(b)).append("-><option bytes>\n");
        return sb.toString();
    }

    private static byte[] repeat(byte v, int n) {
        byte[] out = new byte[n];
        Arrays.fill(out, v);
        return out;
    }

    private String getBasicBlocks(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Function f = findFunction(program, addressStr, name);
        if (f == null) return "Function not found";
        ghidra.program.model.block.BasicBlockModel model =
            new ghidra.program.model.block.BasicBlockModel(program);
        List<ghidra.program.model.block.CodeBlock> blocks = new ArrayList<>();
        try {
            ghidra.program.model.block.CodeBlockIterator it =
                model.getCodeBlocksContaining(f.getBody(), TaskMonitor.DUMMY);
            while (it.hasNext()) blocks.add(it.next());
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
        blocks.sort(Comparator.comparing(b -> b.getMinAddress()));
        Address focus = addressStr != null && !addressStr.isEmpty() ? resolveAddress(program, addressStr) : null;
        long covered = 0;
        StringBuilder rows = new StringBuilder();
        Listing listing = program.getListing();
        for (ghidra.program.model.block.CodeBlock b : blocks) {
            covered += b.getNumAddresses();
            Instruction last = listing.getInstructionContaining(b.getMaxAddress());
            int count = 0;
            InstructionIterator ii = listing.getInstructions(b, true);
            while (ii.hasNext()) { ii.next(); count++; }
            List<String> succ = new ArrayList<>();
            List<String> pred = new ArrayList<>();
            try {
                ghidra.program.model.block.CodeBlockReferenceIterator d = b.getDestinations(TaskMonitor.DUMMY);
                while (d.hasNext()) {
                    ghidra.program.model.block.CodeBlockReference r = d.next();
                    if (r.getFlowType().isCall()) continue;
                    String kind = r.getFlowType().isFallthrough() ? "fall"
                        : r.getFlowType().isConditional() ? "cond" : "jump";
                    boolean outside = !f.getBody().contains(r.getDestinationAddress());
                    succ.add(r.getDestinationAddress() + " " + kind + (outside ? " (leaves function)" : ""));
                }
                ghidra.program.model.block.CodeBlockReferenceIterator s = b.getSources(TaskMonitor.DUMMY);
                while (s.hasNext()) {
                    ghidra.program.model.block.CodeBlockReference r = s.next();
                    if (r.getFlowType().isCall()) continue;
                    pred.add(r.getSourceAddress().toString());
                }
            } catch (Exception ignored) { }
            boolean mark = focus != null && b.contains(focus);
            rows.append(mark ? "> " : "  ").append(b.getMinAddress()).append('\t').append(b.getMaxAddress())
                .append('\t').append(count).append('\t')
                .append(last != null ? last.toString() : "?").append('\t')
                .append(succ.isEmpty() ? "(exit)" : String.join(", ", succ)).append('\t')
                .append(pred.size()).append('\n');
        }
        long body = f.getBody().getNumAddresses();
        StringBuilder sb = new StringBuilder();
        sb.append("# ").append(blocks.size()).append(" basic block(s) in ").append(f.getName())
          .append(" @ ").append(f.getEntryPoint()).append(", blocks cover ").append(covered)
          .append(" of ").append(body).append(" body bytes\n");
        if (covered != body) sb.append("# WARNING: blocks do not cover the body exactly - undisassembled bytes or overlap\n");
        if (focus != null) sb.append("# > marks the block containing ").append(focus).append('\n');
        sb.append("# start\tend\tinstrs\tlast instruction\tsuccessors\tpredecessor count\n");
        return sb.append(rows).toString();
    }

    // ==================================================================================
    // Function lookup by name
    // ==================================================================================

    private static class AmbiguousNameException extends RuntimeException {
        AmbiguousNameException(String m) { super(m); }
    }

    /** Functions with this name; "Ns::name" matches the qualified name. Symbol-table lookup. */
    private List<Function> functionsNamed(Program program, String name) {
        List<Function> out = new ArrayList<>();
        if (name == null || name.isEmpty()) return out;
        collectNamed(program, name, null, out);
        if (out.isEmpty() && name.contains("::")) {
            collectNamed(program, name.substring(name.lastIndexOf("::") + 2), name, out);
        }
        out.sort(Comparator.comparing(Function::getEntryPoint));
        return out;
    }

    private void collectNamed(Program program, String simple, String qualified, List<Function> out) {
        FunctionManager fm = program.getFunctionManager();
        SymbolIterator it = program.getSymbolTable().getSymbols(simple);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (!(s.getObject() instanceof Function f)) continue;
            // A thunk inherits its target's name without a symbol of its own, so the
            // symbol table only finds it through the target.
            Address[] thunks = f.getFunctionThunkAddresses(true);
            if (thunks != null) for (Address a : thunks) {
                Function t = fm.getFunctionAt(a);
                if (t != null && t.getName().equals(simple) && !out.contains(t)
                    && (qualified == null || t.getName(true).equals(qualified))) out.add(t);
            }
            if (f.isExternal() || out.contains(f)) continue;
            if (qualified != null && !f.getName(true).equals(qualified)) continue;
            out.add(f);
        }
    }

    /** The one function with this name, null if none; throws when the name is ambiguous. */
    private Function uniqueFunctionNamed(Program program, String name) {
        List<Function> all = functionsNamed(program, name);
        if (all.isEmpty()) return null;
        if (all.size() == 1) return all.get(0);
        StringBuilder sb = new StringBuilder(all.size() + " functions named '" + name
            + "' - pass an address, or a qualified Class::name. Candidates:");
        for (Function f : all.subList(0, Math.min(20, all.size()))) {
            sb.append("\n  ").append(f.getEntryPoint()).append('\t').append(f.getName(true));
        }
        throw new AmbiguousNameException(sb.toString());
    }

    // ==================================================================================
    // Self-test: invariants checked against the open program
    //
    // Generic checks that hold for any binary, so a broken build shows up as a FAIL here
    // instead of as a wrong answer later.
    // ==================================================================================

    // A hard budget under the client's 60 s: every step gets what is left, not a fresh allowance.
    private static final ThreadLocal<Long> TRACE_DEADLINE = new ThreadLocal<>();

    private static int secondsLeft(long deadline) {
        return (int) Math.max(1, (deadline - System.currentTimeMillis()) / 1000);
    }

    private String selftest(String bridgeBuild, int samples) {
        long deadline = System.currentTimeMillis() + 40_000;
        TRACE_DEADLINE.set(deadline);
        try {
            return selftestInner(bridgeBuild, samples, deadline);
        } finally {
            TRACE_DEADLINE.remove();
        }
    }

    private String selftestInner(String bridgeBuild, int samples, long deadline) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (samples <= 0) samples = 6;
        samples = Math.min(samples, 20);
        List<String> lines = new ArrayList<>();
        int[] tally = new int[2];
        java.util.function.BiConsumer<Boolean, String> check = (ok, msg) -> {
            tally[ok ? 0 : 1]++;
            lines.add((ok ? "PASS " : "FAIL ") + msg);
        };

        check.accept(bridgeBuild == null || bridgeBuild.isEmpty() || bridgeBuild.equals(BUILD_ID),
            "build match: plugin " + BUILD_ID + ", bridge " + (bridgeBuild == null ? "?" : bridgeBuild));

        FunctionManager fm = program.getFunctionManager();
        int total = fm.getFunctionCount();
        check.accept(total > 0, "program has functions (" + total + ")");
        if (total == 0) return summarise(lines, tally);

        // Evenly spaced, non-trivial functions so runs are repeatable.
        List<Function> pool = new ArrayList<>();
        int stride = Math.max(1, total / (samples * 4));
        int idx = 0;
        for (Function f : fm.getFunctions(true)) {
            if (idx++ % stride != 0 || f.isThunk()) continue;
            if (f.getBody().getNumAddresses() < 40) continue;
            pool.add(f);
            if (pool.size() >= samples) break;
        }

        // A thunk named after an import has no symbol of its own; lookup must still find it.
        for (Function f : fm.getFunctions(true)) {
            if (!f.isThunk() || f.getName().startsWith("thunk_")) continue;
            List<Function> found = functionsNamed(program, f.getName());
            check.accept(found.contains(f), "lookup finds thunk " + f.getName() + " @ " + f.getEntryPoint()
                + " (" + found.size() + " match(es))");
            break;
        }

        // Type lookup returns the exact-case type when a case-variant twin exists.
        Map<String, String> byFolded = new HashMap<>();
        String twinA = null, twinB = null;
        Iterator<DataType> dts = program.getDataTypeManager().getAllDataTypes();
        while (dts.hasNext() && twinA == null) {
            String n = dts.next().getName();
            String prev = byFolded.putIfAbsent(n.toLowerCase(), n);
            if (prev != null && !prev.equals(n)) { twinA = prev; twinB = n; }
        }
        if (twinA != null) {
            DataTypeManager dtm = program.getDataTypeManager();
            DataType ra = findDataTypeByNameInAllCategories(dtm, twinA);
            DataType rb = findDataTypeByNameInAllCategories(dtm, twinB);
            check.accept(ra != null && rb != null && ra.getName().equals(twinA) && rb.getName().equals(twinB),
                "type lookup keeps case: " + twinA + " / " + twinB);
        }

        // RTTI scan gives the same answer whatever the piece size, so boundaries lose nothing.
        if (program.getDefaultPointerSize() != 8) {
            lines.add("SKIP find_rtti piece boundaries: not a 64-bit program");
        } else {
            String whole = findRtti(null, 100000, false, false);
            String small;
            RTTI_CHUNK_OVERRIDE.set(4096);
            try {
                small = findRtti(null, 100000, false, false);
            } finally {
                RTTI_CHUNK_OVERRIDE.remove();
            }
            if (whole.startsWith("No MSVC RTTI")) {
                lines.add("SKIP find_rtti piece boundaries: no RTTI in this program");
            } else {
                String count = whole.lines().findFirst().orElse("");
                check.accept(whole.equals(small), "find_rtti identical at 16 MB and 4 KB pieces " + count.replace("# ", "(") + ")");
            }
        }

        boolean constantChecked = false;
        for (Function f : pool) {
            if (deadline - System.currentTimeMillis() < 5_000) {
                lines.add("SKIP " + (pool.size() - pool.indexOf(f)) + " of " + pool.size()
                    + " function sample(s): time budget reached - rerun with fewer samples");
                break;
            }
            String tag = f.getName() + " @ " + f.getEntryPoint();

            // name lookup finds this function (or reports ambiguity rather than a wrong one)
            try {
                Function byName = uniqueFunctionNamed(program, f.getName(true));
                check.accept(byName == f, "lookup by name " + tag);
            } catch (AmbiguousNameException e) {
                check.accept(e.getMessage().contains(f.getEntryPoint().toString()),
                    "ambiguous name lists this address " + tag);
            }

            // VA -> file -> VA round trip
            String a = fileOffset(f.getEntryPoint().toString(), null);
            Matcher m = Pattern.compile("file 0x([0-9a-f]+)").matcher(a);
            if (m.find()) {
                String back = fileOffset(null, "0x" + m.group(1));
                check.accept(back.contains("VA " + f.getEntryPoint()), "file_offset round trip " + tag);
            } else {
                check.accept(false, "file_offset for " + tag + ": " + a);
            }

            // instruction bytes reported = bytes in memory
            Instruction first = program.getListing().getInstructionAt(f.getEntryPoint());
            if (first != null) {
                String info = inspectInstruction(f.getEntryPoint().toString());
                try {
                    String want = "bytes: " + hexBytes(first.getBytes());
                    check.accept(info.contains(want), "inspect_instruction bytes " + tag);
                } catch (Exception e) {
                    check.accept(false, "read bytes " + tag + ": " + e.getMessage());
                }
            }

            // basic blocks tile the function body
            String bb = getBasicBlocks(f.getEntryPoint().toString(), null);
            check.accept(!bb.contains("WARNING") && bb.startsWith("#"), "basic blocks cover body " + tag);

            // every direct call instruction shows up as a caller of its target
            int callsChecked = 0;
            boolean callsOk = true;
            for (Instruction ins : program.getListing().getInstructions(f.getBody(), true)) {
                if (!ins.getFlowType().isCall() || ins.getFlowType().isComputed()) continue;
                for (Address t : ins.getFlows()) {
                    Function callee = fm.getFunctionAt(t);
                    if (callee == null) continue;
                    callsChecked++;
                    if (!callee.getCallingFunctions(TaskMonitor.DUMMY).contains(f)) callsOk = false;
                }
                if (callsChecked >= 10) break;
            }
            if (callsChecked > 0) check.accept(callsOk, "call graph symmetric (" + callsChecked + " calls) " + tag);

            // an immediate operand is found again by search_constant
            Instruction withScalar = null;
            long value = 0;
            for (Instruction ins : program.getListing().getInstructions(f.getBody(), true)) {
                for (int i = 0; i < ins.getNumOperands() && withScalar == null; i++) {
                    for (Object o : ins.getOpObjects(i)) {
                        if (o instanceof Scalar s && s.getSignedValue() >= 0x100 && s.getSignedValue() < 0x7fffffffL
                            && ins.getReferencesFrom().length == 0) {
                            withScalar = ins;
                            value = s.getSignedValue();
                        }
                    }
                }
                if (withScalar != null) break;
            }
            if (withScalar != null && !constantChecked && deadline - System.currentTimeMillis() > 10_000) {
                constantChecked = true; // one full-program scan is enough
                String hits = searchConstant("0x" + Long.toHexString(value), "imm", null, 100000);
                check.accept(hits.contains(withScalar.getAddress().toString()),
                    "search_constant finds " + formatConstant(value) + " at " + withScalar.getAddress());
            }

            // decompile and trace complete without error
            DecompileResults dr = decompileCached(program, f, Math.min(30, secondsLeft(deadline)));
            boolean decOk = dr != null && dr.decompileCompleted();
            check.accept(decOk, "decompile " + tag);
            if (decOk && dr.getHighFunction() != null) {
                Iterator<PcodeOpAST> ops = dr.getHighFunction().getPcodeOps();
                Address traceAt = null;
                while (ops.hasNext()) {
                    PcodeOp op = ops.next();
                    if (op.getOutput() != null && op.getSeqnum() != null) { traceAt = op.getSeqnum().getTarget(); break; }
                }
                if (traceAt != null) {
                    String t = traceValue(traceAt.toString(), null, 4, "backward", 1, 2);
                    check.accept(t.startsWith("# backward slice"), "trace_value backward at " + traceAt);
                    String fw = traceValue(traceAt.toString(), null, 4, "forward", 1, 2);
                    check.accept(fw.startsWith("# forward slice"), "trace_value forward at " + traceAt);
                }
            }
        }

        // An aborted transaction must leave nothing behind.
        Address probe = pool.isEmpty() ? fm.getFunctions(true).next().getEntryPoint() : pool.get(0).getEntryPoint();
        final boolean[] inside = new boolean[1];
        String err = inTransactionAborting(program, "selftest rollback probe", () -> {
            program.getBookmarkManager().setBookmark(probe, BookmarkType.NOTE, "selftest", "probe");
            inside[0] = program.getBookmarkManager().getBookmark(probe, BookmarkType.NOTE, "selftest") != null;
            return false;
        });
        boolean gone = program.getBookmarkManager().getBookmark(probe, BookmarkType.NOTE, "selftest") == null;
        check.accept(err == null && inside[0] && gone, "rolled-back write leaves no trace");

        return summarise(lines, tally);
    }

    private String summarise(List<String> lines, int[] tally) {
        return "# selftest on " + programLabel(getCurrentProgram()) + ": " + tally[0] + " passed, "
            + tally[1] + " failed\n" + String.join("\n", lines);
    }

    // ==================================================================================
    // MSVC RTTI
    //
    // A stripped C++ binary still carries the class names its RTTI needs. Recovering them
    // names vtables, and naming a vtable is worth more than naming a function: it labels
    // every slot in it at once.
    // ==================================================================================

    private static class RttiClass {
        String name;
        Address colAddr;
        Address typeDescriptor;
        Address vftable;
        int vtableOffset;
        int baseCount;
        int slots;
        List<String> bases = new ArrayList<>();
    }

    // MSVC RTTI layout, confirmed against Ghidra's own RTTI1/RTTI3 data type models.
    //   ClassHierarchyDescriptor: +0x00 signature, +0x04 attributes,
    //                             +0x08 numBaseClasses, +0x0c pBaseClassArray (RVA)
    //   BaseClassArray:           numBaseClasses x 4-byte RVA, each -> BaseClassDescriptor
    //   BaseClassDescriptor:      +0x00 pTypeDescriptor (RVA), +0x04 numContainedBases,
    //                             +0x08 pmd { mdisp, pdisp, vdisp }, +0x14 attributes
    private static final int CHD_NUM_BASES_OFFSET = 8;
    private static final int CHD_BASE_ARRAY_OFFSET = 12;
    private static final int BCD_TYPE_DESCRIPTOR_OFFSET = 0;
    private static final int BCD_PMD_MDISP_OFFSET = 8;

    /**
     * Recover classes from MSVC RTTI: scan for Complete Object Locators, resolve each to
     * its type descriptor name, and pair it with the vtable that points at it.
     */
    // Blocks are scanned in pieces; each piece carries a small overlap so records that
    // straddle a boundary are still read whole.
    private static final int RTTI_CHUNK = 16 * 1024 * 1024;
    // Smaller pieces put many boundaries inside real data; used to test the boundary handling.
    private static final ThreadLocal<Integer> RTTI_CHUNK_OVERRIDE = new ThreadLocal<>();

    private static int rttiChunk() {
        Integer o = RTTI_CHUNK_OVERRIDE.get();
        return o != null ? o : RTTI_CHUNK;
    }

    private byte[] readChunk(MemoryBlock block, long chunk, List<String> unread) {
        long len = Math.min((long) rttiChunk() + 32, block.getSize() - chunk);
        byte[] buf = new byte[(int) len];
        try {
            int got = block.getBytes(block.getStart().add(chunk), buf);
            return got == len ? buf : Arrays.copyOf(buf, Math.max(0, got));
        } catch (Exception e) {
            if (unread != null) unread.add(block.getName() + "+0x" + Long.toHexString(chunk));
            return null;
        }
    }

    private String findRtti(String filter, int limit, boolean apply, boolean withBases) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (limit <= 0) limit = 200;
        if (program.getDefaultPointerSize() != 8) {
            return "Error: this reads the 64-bit MSVC RTTI layout; this program has a "
                + program.getDefaultPointerSize() + "-byte pointer size";
        }

        Memory memory = program.getMemory();
        long imageBase = program.getImageBase().getOffset();
        boolean bigEndian = program.getLanguage().isBigEndian();
        if (bigEndian) return "Error: MSVC RTTI recovery assumes little-endian";

        List<MemoryBlock> blocks = new ArrayList<>();
        for (MemoryBlock b : memory.getBlocks()) {
            if (b.isInitialized() && !b.isExecute()) blocks.add(b);
        }
        if (blocks.isEmpty()) return "Error: no initialized data blocks to scan";

        // Pass 1: find Complete Object Locators. A COL is self-describing on x64 - the
        // field at +0x14 holds its own RVA - which is a strong enough validator that no
        // cross-referencing is needed to find them.
        Map<Long, RttiClass> byCol = new LinkedHashMap<>();
        List<String> unread = new ArrayList<>();
        for (MemoryBlock block : blocks) for (long chunk = 0; chunk < block.getSize(); chunk += rttiChunk()) {
            byte[] buf = readChunk(block, chunk, unread);
            if (buf == null) break;
            long base = block.getStart().getOffset() + chunk;
            int stop = (int) Math.min(rttiChunk(), buf.length);
            for (int i = 0; i < stop && i + 24 <= buf.length; i += 4) {
                int signature = readInt(buf, i);
                if (signature != 1) continue;
                long selfRva = readInt(buf, i + 20) & 0xFFFFFFFFL;
                long here = base + i;
                if (selfRva != here - imageBase) continue;

                long tdRva = readInt(buf, i + 12) & 0xFFFFFFFFL;
                long chdRva = readInt(buf, i + 16) & 0xFFFFFFFFL;
                if (tdRva == 0) continue;

                Address tdAddr;
                try {
                    tdAddr = program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(imageBase + tdRva);
                } catch (Exception e) {
                    continue;
                }
                if (!memory.contains(tdAddr)) continue;

                String mangled = readCString(program, tdAddr.add(16), 512);
                if (mangled == null || !mangled.startsWith(".?A")) continue;

                RttiClass rc = new RttiClass();
                rc.name = demangleRttiName(mangled);
                rc.colAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(here);
                rc.typeDescriptor = tdAddr;
                rc.vtableOffset = readInt(buf, i + 4);
                rc.baseCount = readBaseCount(program, imageBase, chdRva);
                if (withBases) readBaseChain(program, imageBase, chdRva, rc);
                byCol.put(here, rc);
            }
        }

        if (byCol.isEmpty()) {
            return "No MSVC RTTI found. The binary may have been built with /GR-, or the "
                + "data blocks may not be initialized in this program.";
        }

        // Pass 2: a vftable is the address immediately after a pointer to its COL.
        for (MemoryBlock block : blocks) for (long chunk = 0; chunk < block.getSize(); chunk += rttiChunk()) {
            byte[] buf = readChunk(block, chunk, null);
            if (buf == null) break;
            long base = block.getStart().getOffset() + chunk;
            int stop = (int) Math.min(rttiChunk(), buf.length);
            for (int i = 0; i < stop && i + 8 <= buf.length; i += 8) {
                long value = readLong(buf, i);
                RttiClass rc = byCol.get(value);
                if (rc == null || rc.vftable != null) continue;
                try {
                    rc.vftable = program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(base + i + 8);
                } catch (Exception ignored) { }
            }
        }

        // Count the slots that actually point at code.
        for (RttiClass rc : byCol.values()) {
            if (rc.vftable == null) continue;
            int slots = 0;
            for (int s = 0; s < 4096; s++) {
                try {
                    Address slot = rc.vftable.add((long) s * 8);
                    if (!memory.contains(slot)) break;
                    long target = memory.getLong(slot);
                    if (target == 0) break;
                    Address t = program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(target);
                    MemoryBlock tb = memory.getBlock(t);
                    if (tb == null || !tb.isExecute()) break;
                    slots++;
                } catch (Exception e) {
                    break;
                }
            }
            rc.slots = slots;
        }

        String f = (filter == null || filter.isEmpty()) ? null : filter.toLowerCase();
        List<RttiClass> matched = new ArrayList<>();
        for (RttiClass rc : byCol.values()) {
            if (f != null && !rc.name.toLowerCase().contains(f)) continue;
            matched.add(rc);
        }
        matched.sort(Comparator.comparing(a -> a.name));

        StringBuilder sb = new StringBuilder();
        if (!unread.isEmpty()) sb.append("# WARNING: could not read ").append(String.join(", ", unread)).append('\n');
        sb.append("# ").append(byCol.size()).append(" RTTI class(es) found");
        if (f != null) sb.append(", ").append(matched.size()).append(" matching \"").append(filter).append('"');
        sb.append("\n# class\tvftable\tslots\tbases\tvtable_offset\tcomplete_object_locator\n");

        int shown = 0;
        List<String> labelled = new ArrayList<>();
        for (RttiClass rc : matched) {
            if (shown++ >= limit) break;
            sb.append(rc.name).append('\t')
              .append(rc.vftable != null ? rc.vftable.toString() : "(no vftable found)").append('\t')
              .append(rc.slots).append('\t')
              .append(rc.baseCount).append('\t')
              .append("0x").append(Integer.toHexString(rc.vtableOffset)).append('\t')
              .append(rc.colAddr).append('\n');
            if (withBases && !rc.bases.isEmpty()) {
                sb.append("    bases: ").append(String.join(" <- ", rc.bases)).append('\n');
            }
            if (rc.vftable != null) labelled.add(rc.name);
        }
        if (matched.size() > shown) {
            sb.append("# ... ").append(matched.size() - shown).append(" more; raise limit or filter\n");
        }

        if (apply) {
            final List<RttiClass> toApply = new ArrayList<>();
            for (RttiClass rc : matched) {
                if (rc.vftable != null) toApply.add(rc);
            }
            final int[] done = new int[1];
            String err = inTransaction(program, "Label RTTI vftables", () -> {
                SymbolTable st = program.getSymbolTable();
                for (RttiClass rc : toApply) {
                    Symbol existing = st.getPrimarySymbol(rc.vftable);
                    if (existing != null && existing.getSource() == SourceType.USER_DEFINED) continue;
                    st.createLabel(rc.vftable, rc.name + "::vftable", SourceType.USER_DEFINED);
                    done[0]++;
                }
            });
            sb.append(err == null
                ? "\nLabelled " + done[0] + " vftable(s) in one transaction (undo reverses all)."
                : "\nLabelling failed: " + err);
        } else {
            sb.append("\nNot applied. Pass apply=true to label each vftable as <Class>::vftable.");
        }
        return sb.toString();
    }

    /**
     * Walk the BaseClassArray and collect each base class name and its offset within the
     * object. The first entry is the class itself, so it is skipped.
     */
    private void readBaseChain(Program program, long imageBase, long chdRva, RttiClass rc) {
        if (chdRva == 0) return;
        try {
            Memory memory = program.getMemory();
            ghidra.program.model.address.AddressSpace space =
                program.getAddressFactory().getDefaultAddressSpace();
            Address chd = space.getAddress(imageBase + chdRva);
            if (!memory.contains(chd)) return;

            int count = memory.getInt(chd.add(CHD_NUM_BASES_OFFSET));
            if (count <= 0 || count > 512) return;
            long arrayRva = memory.getInt(chd.add(CHD_BASE_ARRAY_OFFSET)) & 0xFFFFFFFFL;
            if (arrayRva == 0) return;
            Address array = space.getAddress(imageBase + arrayRva);
            if (!memory.contains(array)) return;

            for (int i = 0; i < count; i++) {
                long bcdRva = memory.getInt(array.add((long) i * 4)) & 0xFFFFFFFFL;
                if (bcdRva == 0) continue;
                Address bcd = space.getAddress(imageBase + bcdRva);
                if (!memory.contains(bcd)) continue;
                long tdRva = memory.getInt(bcd.add(BCD_TYPE_DESCRIPTOR_OFFSET)) & 0xFFFFFFFFL;
                if (tdRva == 0) continue;
                Address td = space.getAddress(imageBase + tdRva);
                if (!memory.contains(td)) continue;
                String mangled = readCString(program, td.add(16), 512);
                if (mangled == null || !mangled.startsWith(".?A")) continue;
                String baseName = demangleRttiName(mangled);
                if (i == 0) continue;  // entry zero is the class itself
                int mdisp = memory.getInt(bcd.add(BCD_PMD_MDISP_OFFSET));
                rc.bases.add(baseName + (mdisp != 0 ? "+0x" + Integer.toHexString(mdisp) : ""));
            }
        } catch (Exception ignored) {
            // A malformed descriptor costs that one class its base list, nothing more.
        }
    }

    private int readBaseCount(Program program, long imageBase, long chdRva) {
        if (chdRva == 0) return 0;
        try {
            Address chd = program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(imageBase + chdRva);
            if (!program.getMemory().contains(chd)) return 0;
            return program.getMemory().getInt(chd.add(8));
        } catch (Exception e) {
            return 0;
        }
    }

    private int readInt(byte[] buf, int off) {
        return (buf[off] & 0xFF) | ((buf[off + 1] & 0xFF) << 8)
             | ((buf[off + 2] & 0xFF) << 16) | ((buf[off + 3] & 0xFF) << 24);
    }

    private long readLong(byte[] buf, int off) {
        long v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | (buf[off + i] & 0xFFL);
        return v;
    }

    private String readCString(Program program, Address addr, int max) {
        StringBuilder sb = new StringBuilder();
        try {
            for (int i = 0; i < max; i++) {
                byte b = program.getMemory().getByte(addr.add(i));
                if (b == 0) break;
                if (b < 0x20 || b > 0x7E) return null;
                sb.append((char) b);
            }
        } catch (Exception e) {
            return null;
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    /**
     * Turn an RTTI type-descriptor name into a readable class name.
     * ".?AVUNetDriver@@" -> "UNetDriver", ".?AVFoo@Bar@@" -> "Bar::Foo".
     */
    private String demangleRttiName(String mangled) {
        String s = mangled;
        if (s.startsWith(".?AV") || s.startsWith(".?AU") || s.startsWith(".?AW")) {
            s = s.substring(4);
        } else if (s.startsWith(".?A")) {
            s = s.substring(3);
        }
        while (s.endsWith("@")) s = s.substring(0, s.length() - 1);
        if (s.isEmpty()) return mangled;
        if (s.contains("?$")) {
            // Templates need the real demangler; leave them recognisable rather than wrong.
            return s;
        }
        String[] parts = s.split("@");
        List<String> out = new ArrayList<>();
        for (int i = parts.length - 1; i >= 0; i--) {
            if (!parts[i].isEmpty()) out.add(parts[i]);
        }
        return out.isEmpty() ? mangled : String.join("::", out);
    }

    private String demangleName(String name) {
        if (name == null || name.isEmpty()) return "Error: name is required";
        if (name.startsWith(".?A")) {
            return name + "  ->  " + demangleRttiName(name);
        }
        try {
            List<ghidra.app.util.demangler.DemangledObject> results =
                ghidra.app.util.demangler.DemanglerUtil.demangle(getCurrentProgram(), name, null);
            if (results != null && !results.isEmpty()) {
                StringBuilder sb = new StringBuilder();
                for (ghidra.app.util.demangler.DemangledObject obj : results) {
                    if (obj == null) continue;
                    if (sb.length() > 0) sb.append('\n');
                    sb.append(name).append("  ->  ").append(obj.getSignature(false));
                }
                if (sb.length() > 0) return sb.toString();
            }
        } catch (Throwable t) {
            return "Error: demangler failed: " + t.getMessage();
        }
        return "Could not demangle: " + name;
    }

    /**
     * Trim a response to a line window so one enormous function cannot fill the
     * caller's context. start_line is 1-based; max_lines <= 0 means no limit.
     */
    private String windowLines(String text, int startLine, int maxLines) {
        if (text == null || (startLine <= 1 && maxLines <= 0)) return text;
        String[] lines = text.split("\n", -1);
        int start = Math.max(0, startLine - 1);
        if (start >= lines.length) {
            return "# start_line " + startLine + " is past the end (" + lines.length + " lines)";
        }
        int end = maxLines > 0 ? Math.min(lines.length, start + maxLines) : lines.length;
        StringBuilder sb = new StringBuilder();
        if (start > 0 || end < lines.length) {
            sb.append("# lines ").append(start + 1).append('-').append(end)
              .append(" of ").append(lines.length);
            if (end < lines.length) {
                sb.append("; continue with start_line=").append(end + 1);
            }
            sb.append('\n');
        }
        for (int i = start; i < end; i++) sb.append(lines[i]).append('\n');
        return sb.toString();
    }

    private int statusForResponse(String response) {
        if (response == null || response.isEmpty()) return 200;
        String head = response.length() > 120 ? response.substring(0, 120) : response;
        if (head.startsWith("No program loaded")) return 409;
        if (head.startsWith("Error") || head.startsWith("Address is required")
            || head.startsWith("Search term is required") || head.startsWith("Function name is required")) {
            return 400;
        }
        if (head.startsWith("No function found") || head.startsWith("Function not found")
            || head.startsWith("Type not found") || head.startsWith("No function at")) {
            return 404;
        }
        if (head.startsWith("Failed") || head.startsWith("Decompilation failed")
            || head.startsWith("Rename failed") || head.startsWith("Batch rename failed")) {
            return 500;
        }
        return 200;
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        if (serverPool != null) {
            serverPool.shutdownNow();
            serverPool = null;
        }
        synchronized (decompLock) {
            releaseDecompiler();
        }
        super.dispose();
    }
}
