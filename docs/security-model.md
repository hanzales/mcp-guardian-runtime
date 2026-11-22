# Security Model

McpGuardian.Runtime assumes the MCP SDK correctly routes a parsed tool call and the host supplies a trustworthy principal. It treats every tool name and argument as untrusted. Unknown tools, missing identities for identity-dependent rules, validator failures, and policy-engine exceptions fail closed.

Denying a call prevents the SDK next delegate from running. Externally visible denials use a generic message; detailed, non-secret reason codes remain in audit events.

Transport authentication is out of scope. A role or scope passed as a normal tool argument has no authorization effect. Path validation prevents lexical traversal after canonicalization but cannot prevent symlink changes between validation and use. Enforce filesystem boundaries using OS permissions or a sandbox and open files defensively.
