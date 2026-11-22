# Integration

Register services with `AddMcpGuardian`, then install the filter with `WithMcpGuardian` on the official `IMcpServerBuilder`. Omitting the second call leaves tools unfiltered; this is explicit because the SDK builder owns filter ordering.

Ordinary call-tool filters compose in registration order. Configure task-backed call filters before McpGuardian, following the official SDK ordering rules. On HTTP transports, authenticate in ASP.NET Core so `RequestContext.User` is populated. On stdio, no verified end-user identity normally exists; anonymous-safe rules may allow, but role/scope rules deny.

The integration test starts the sample through the official `StdioClientTransport`, performs the MCP handshake, calls an allowed tool, and verifies an explicitly denied tool returns an error without executing its implementation.
