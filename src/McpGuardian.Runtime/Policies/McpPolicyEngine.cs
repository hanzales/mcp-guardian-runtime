using McpGuardian.Runtime.Abstractions;
using McpGuardian.Runtime.Configuration;
using McpGuardian.Runtime.Validation;
using Microsoft.Extensions.Options;

namespace McpGuardian.Runtime.Policies;

/// <summary>Thread-safe, immutable, deterministic policy engine.</summary>
public sealed class McpPolicyEngine : IMcpPolicyEngine
{
    private readonly Dictionary<string, McpPolicy[]> _policies;
    /// <summary>Creates an engine and validates all policies.</summary>
    public McpPolicyEngine(IOptions<McpSecurityOptions> options)
        => _policies = options.Value.Compile().GroupBy(x => x.ToolName, StringComparer.Ordinal).ToDictionary(x => x.Key, x => x.ToArray(), StringComparer.Ordinal);

    /// <inheritdoc />
    public ValueTask<McpPolicyResult> EvaluateAsync(McpPolicyContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_policies.TryGetValue(context.ToolName, out var policies)) return ValueTask.FromResult(Deny("default-deny", "unknown_tool"));
        var explicitDeny = policies.FirstOrDefault(x => x.Action == McpPolicyAction.Deny);
        if (explicitDeny is not null) return ValueTask.FromResult(Deny(explicitDeny.Id, "explicit_deny"));
        foreach (var policy in policies.Where(x => x.Action == McpPolicyAction.Allow))
        {
            if ((policy.RequiredRoles.Count > 0 || policy.RequiredScopes.Count > 0) && !context.Caller.IsAuthenticated) return ValueTask.FromResult(Deny(policy.Id, "missing_identity"));
            if (!policy.RequiredRoles.All(context.Caller.Roles.Contains)) return ValueTask.FromResult(Deny(policy.Id, "missing_role"));
            if (!policy.RequiredScopes.All(context.Caller.Scopes.Contains)) return ValueTask.FromResult(Deny(policy.Id, "missing_scope"));
            var invalid = ArgumentValidator.Validate(context.Arguments, policy);
            if (invalid is not null) return ValueTask.FromResult(Deny(policy.Id, invalid));
        }
        var allow = policies.FirstOrDefault(x => x.Action == McpPolicyAction.Allow);
        return ValueTask.FromResult(allow is null ? Deny("default-deny", "no_allow_policy") : new McpPolicyResult(McpPolicyDecision.Allow, allow.Id));
    }
    private static McpPolicyResult Deny(string id, string reason) => new(McpPolicyDecision.Deny, id, reason, "Tool execution was denied by security policy.");
}
