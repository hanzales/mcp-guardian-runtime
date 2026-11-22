# Architecture

The official MCP SDK call-tool filter resolves the request principal and registered services. `McpSecurityPipeline` asks the immutable `McpPolicyEngine` for a decision, invokes the SDK's next delegate only on allow, then emits a redacted audit event. Policies and regexes are compiled once when options are materialized. The engine is read-only after construction and safe for concurrent calls.

The package does not parse MCP wire messages or replace SDK routing. It depends on the SDK filter contract and preserves the original request and cancellation token.
