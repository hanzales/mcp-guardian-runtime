using System.Diagnostics;
using System.Text.Json;
using McpGuardian.Runtime.Abstractions;
using McpGuardian.Runtime.Auditing;
using McpGuardian.Runtime.Authorization;
using McpGuardian.Runtime.Configuration;
using McpGuardian.Runtime.Policies;
using Microsoft.Extensions.Options;

namespace McpGuardian.Runtime.Filters;

/// <summary>Runs fail-closed authorization, invocation, and redacted auditing.</summary>
public sealed class McpSecurityPipeline(IMcpPolicyEngine engine, IMcpSecurityAuditSink auditSink, IOptions<McpSecurityOptions> options)
{
    /// <summary>Protects one tool invocation and invokes <paramref name="next"/> at most once.</summary>
    public async ValueTask<T> InvokeAsync<T>(string toolName, IReadOnlyDictionary<string, JsonElement> arguments, McpCallerContext caller,
        Func<CancellationToken, ValueTask<T>> next, string? correlationId = null, CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        McpPolicyResult decision;
        try { decision = await engine.EvaluateAsync(new(toolName, arguments, caller), cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception) { decision = new(McpPolicyDecision.Deny, "evaluation-failure", "policy_evaluation_failed", "Tool execution was denied by security policy."); }

        var outcome = McpExecutionOutcome.NotExecuted;
        try
        {
            if (!decision.IsAllowed) throw new Exceptions.McpAuthorizationException();
            var value = await next(cancellationToken).ConfigureAwait(false);
            outcome = McpExecutionOutcome.Succeeded;
            return value;
        }
        catch (OperationCanceledException) { outcome = McpExecutionOutcome.Cancelled; throw; }
        catch { if (decision.IsAllowed) outcome = McpExecutionOutcome.Failed; throw; }
        finally
        {
            var auditEvent = new McpSecurityAuditEvent(DateTimeOffset.UtcNow, toolName, decision.Decision, decision.PolicyId, decision.ReasonCode,
                stopwatch.Elapsed, outcome, correlationId ?? Guid.NewGuid().ToString("N"), caller.CallerId);
            try { await auditSink.WriteAsync(auditEvent, CancellationToken.None).ConfigureAwait(false); }
            catch when (!options.Value.FailOnAuditError) { }
        }
    }
}
