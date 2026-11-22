# Limitations

- Exact tool-name policies only; wildcards are intentionally absent in the preview.
- No built-in rate limiting, approval workflow, persistent policy store, or response sanitization.
- No transport authentication or OAuth server.
- Stdio has no inherent verified end-user identity.
- Path validation is not a filesystem sandbox and cannot eliminate TOCTOU or symlink races.
- Audit sinks receive caller identifiers; deployments must classify and protect audit data.
- The library does not detect prompt injection, data exfiltration, or malicious tool descriptions.
