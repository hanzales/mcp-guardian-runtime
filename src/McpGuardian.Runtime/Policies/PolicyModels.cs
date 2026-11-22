using System.Text.Json;
using McpGuardian.Runtime.Authorization;

namespace McpGuardian.Runtime.Policies;

/// <summary>Policy action.</summary>
public enum McpPolicyAction
{
    /// <summary>Deny execution.</summary>
    Deny,
    /// <summary>Allow execution when all constraints pass.</summary>
    Allow
}
/// <summary>Final authorization decision.</summary>
public enum McpPolicyDecision
{
    /// <summary>Execution is denied.</summary>
    Deny,
    /// <summary>Execution is allowed.</summary>
    Allow
}

/// <summary>Context supplied to the policy engine.</summary>
public sealed record McpPolicyContext(string ToolName, IReadOnlyDictionary<string, JsonElement> Arguments, McpCallerContext Caller);

/// <summary>Deterministic policy evaluation result.</summary>
public sealed record McpPolicyResult(McpPolicyDecision Decision, string PolicyId, string? ReasonCode = null, string? SafeMessage = null)
{
    /// <summary>True only for an explicit allow result.</summary>
    public bool IsAllowed => Decision == McpPolicyDecision.Allow;
}

/// <summary>Immutable tool policy compiled at startup.</summary>
public sealed class McpPolicy
{
    internal McpPolicy(string id, string toolName, McpPolicyAction action, IReadOnlySet<string> roles, IReadOnlySet<string> scopes, IReadOnlyList<Validation.ArgumentRule> rules, int? maximumArgumentBytes)
        => (Id, ToolName, Action, RequiredRoles, RequiredScopes, ArgumentRules, MaximumArgumentBytes) = (id, toolName, action, roles, scopes, rules, maximumArgumentBytes);
    /// <summary>Stable policy identifier.</summary>
    public string Id { get; }
    /// <summary>Exact MCP tool name.</summary>
    public string ToolName { get; }
    /// <summary>Allow or deny action.</summary>
    public McpPolicyAction Action { get; }
    /// <summary>Roles all of which are required.</summary>
    public IReadOnlySet<string> RequiredRoles { get; }
    /// <summary>Scopes all of which are required.</summary>
    public IReadOnlySet<string> RequiredScopes { get; }
    /// <summary>Argument constraints.</summary>
    public IReadOnlyList<Validation.ArgumentRule> ArgumentRules { get; }
    /// <summary>Maximum serialized argument size.</summary>
    public int? MaximumArgumentBytes { get; }
}
