using McpGuardian.Runtime.Authorization;
using McpGuardian.Runtime.Policies;

namespace McpGuardian.Runtime.Abstractions;

/// <summary>Evaluates compiled policies for one tool invocation.</summary>
public interface IMcpPolicyEngine
{
    /// <summary>Evaluates a tool invocation without invoking the tool.</summary>
    ValueTask<McpPolicyResult> EvaluateAsync(McpPolicyContext context, CancellationToken cancellationToken = default);
}

/// <summary>Provides caller identity derived from trusted transport state.</summary>
public interface IMcpCallerContextProvider
{
    /// <summary>Creates the caller context for a request.</summary>
    ValueTask<McpCallerContext> GetCallerContextAsync(System.Security.Claims.ClaimsPrincipal? principal, CancellationToken cancellationToken = default);
}
