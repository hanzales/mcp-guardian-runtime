# McpGuardian.Runtime

**Secure every MCP tool execution.**

McpGuardian.Runtime is a security-first, embeddable .NET 10 library that protects the tool invocation boundary of MCP servers built with the official Model Context Protocol C# SDK. It applies deterministic authorization and argument policies before a tool runs and emits redacted audit events afterward. It has no LLM, cloud service, telemetry, or persistent-store dependency.

> Preview software. Review the threat model and limitations before production use.

## Why

An MCP tool can read data, mutate systems, or invoke privileged services. Authentication alone does not decide which caller may run each tool or whether supplied arguments are safe. McpGuardian.Runtime adds an explicit, default-deny policy boundary inside the server that owns the tool.

## Features

- Official SDK `WithRequestFilters` / `AddCallToolFilter` integration
- Default deny, explicit allow/deny, and deny precedence
- Trusted caller roles and OAuth-style scope claims
- Required/type/size/string/allow-list/numeric/regex argument checks
- Canonical path boundary checks without naive prefix matching
- Redacted structured auditing through `ILogger` or a custom sink
- Startup policy validation, cancellation propagation, and thread-safe evaluation
- Real official-SDK stdio client/server integration test

## Install

```bash
dotnet add package McpGuardian.Runtime --version 0.1.0-preview.1
```

The package is prepared but not yet published. Until publication, build the repository or use the generated package from `artifacts/packages`.

## Quick start

```csharp
builder.Services.AddMcpGuardian(options =>
{
    options.AllowTool("get_system_status");
    options.AllowTool("read_document")
        .RequireRole("DocumentReader")
        .RequireScope("documents.read")
        .RequireArgument("documentId")
        .LimitString("documentId", 128);
    options.DenyTool("delete_document");
});

builder.Services.AddMcpServer()
    .WithStdioServerTransport()
    .WithMcpGuardian()
    .WithTools<SecureTools>();
```

Both calls are required: `AddMcpGuardian` registers services and policies; `WithMcpGuardian` installs the official SDK call-tool filter. For task-backed MCP calls, register task filters first so the security filter runs at the intended position. See [integration](docs/integration.md).

## Policy and argument configuration

Rules match exact, case-sensitive MCP tool names. Unknown tools are denied. An explicit deny wins over every allow. All role, scope, and argument constraints on an allowed tool must pass.

```csharp
options.AllowTool("read_file")
    .RequireRole("Reader")
    .MaxArgumentSize(16_384)
    .RestrictPath("path", "/workspace", mustExist: true);
```

Regex rules use the non-backtracking engine and a timeout. Path checks canonicalize the root and candidate and use `Path.GetRelativePath`; they are validation, not filesystem isolation.

## Caller authorization

The default caller provider reads the SDK request's transport-authenticated `ClaimsPrincipal`. It never reads identity, roles, or scopes from tool arguments. Role claims use the principal's configured role claim type; scopes use space-separated `scope` claims. Identity-dependent policies deny when no authenticated principal exists.

HTTP servers should authenticate requests in ASP.NET Core before MCP processing. Stdio normally represents the local process boundary and does not provide a verified end-user identity; role/scope policies therefore deny unless the application supplies a trusted custom `IMcpCallerContextProvider`.

## Auditing

`LoggerMcpSecurityAuditSink` records tool name, decision, policy ID, safe reason code, duration, outcome, correlation ID, and optional caller ID. Raw arguments and secrets are not recorded. Replace `IMcpSecurityAuditSink` to send events elsewhere. Audit failures are ignored by default after authorization; set `FailOnAuditError = true` to make an audit failure fail the call.

## Run the sample

```bash
dotnet run --project samples/SecureMcpServer
```

Example client configuration:

```json
{
  "mcpServers": {
    "secure-sample": {
      "command": "dotnet",
      "args": ["run", "--project", "/absolute/path/mcp-guardian-runtime/samples/SecureMcpServer"]
    }
  }
}
```

The sample allows `get_system_status`, requires `DocumentReader` for `read_document`, and denies `delete_document`. It exposes no arbitrary filesystem operation.

## Build, test, package, benchmark

```bash
dotnet restore McpGuardian.Runtime.slnx --configfile NuGet.config
dotnet build McpGuardian.Runtime.slnx -c Release --no-restore
dotnet test McpGuardian.Runtime.slnx -c Release --no-build --no-restore
dotnet pack src/McpGuardian.Runtime -c Release --no-build -o artifacts/packages
dotnet run -c Release --project benchmarks/McpGuardian.Runtime.Benchmarks
```

No benchmark numbers are claimed; run them on your target environment.

## Threat model and limitations

This library protects calls only inside an MCP server where it is installed. It does not authenticate a transport, secure unrelated servers, isolate filesystem access, sanitize tool responses, detect prompt injection, prevent tool poisoning, or guarantee end-to-end agent behavior. Canonical path validation cannot eliminate symlink races; use OS permissions, sandboxing, narrowly scoped service credentials, and safe tool implementations. See [security model](docs/security-model.md) and [limitations](docs/limitations.md).

## Roadmap

Rate limiting, human approval, persistent policy stores, response validation, richer ASP.NET Core examples, and dialect-specific path policies are tracked in [ROADMAP.md](ROADMAP.md).

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and the [MIT license](LICENSE).
