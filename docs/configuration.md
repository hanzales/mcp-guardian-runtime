# Configuration

`AddMcpGuardian` accepts fluent policies. Tool names are exact and case-sensitive. Multiple allow policies for the same tool are evaluated in registration order and all applicable constraints must pass; any explicit deny immediately wins. Policy IDs are deterministic within registration order. The preview enforces default deny and rejects an allow default.

Available argument checks include required values, JSON kinds, total serialized size, maximum string length, allowed values, numeric bounds, non-backtracking regexes with timeouts, and canonical path roots.
