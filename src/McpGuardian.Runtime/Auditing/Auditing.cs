using Microsoft.Extensions.Logging;

namespace McpGuardian.Runtime.Auditing;

/// <summary>Receives redacted structured security events.</summary>
public interface IMcpSecurityAuditSink
{
    /// <summary>Writes one event. Argument values are never included.</summary>
    ValueTask WriteAsync(McpSecurityAuditEvent auditEvent, CancellationToken cancellationToken = default);
}

/// <summary>Outcome after an authorized tool invocation.</summary>
public enum McpExecutionOutcome
{
    /// <summary>The protected tool was not invoked.</summary>
    NotExecuted,
    /// <summary>The tool completed successfully.</summary>
    Succeeded,
    /// <summary>The tool threw an exception.</summary>
    Failed,
    /// <summary>The tool invocation was cancelled.</summary>
    Cancelled
}

/// <summary>Redacted security audit event.</summary>
public sealed record McpSecurityAuditEvent(DateTimeOffset Timestamp, string ToolName, Policies.McpPolicyDecision Decision, string PolicyId,
    string? DenialReasonCode, TimeSpan Duration, McpExecutionOutcome Outcome, string CorrelationId, string? CallerId);

/// <summary>Writes structured audit records through Microsoft.Extensions.Logging.</summary>
public sealed class LoggerMcpSecurityAuditSink : IMcpSecurityAuditSink
{
    private readonly ILogger<LoggerMcpSecurityAuditSink> _logger;
    /// <summary>Creates a logging audit sink.</summary>
    public LoggerMcpSecurityAuditSink(ILogger<LoggerMcpSecurityAuditSink> logger) => _logger = logger;
    /// <inheritdoc />
    public ValueTask WriteAsync(McpSecurityAuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        if (_logger.IsEnabled(LogLevel.Information))
        {
#pragma warning disable CA1848
            _logger.LogInformation(new EventId(7001, "McpSecurityAudit"), "MCP security audit: Tool={Tool} Decision={Decision} Policy={Policy} Reason={Reason} Outcome={Outcome} DurationMs={DurationMs} CorrelationId={CorrelationId} CallerId={CallerId}", auditEvent.ToolName, auditEvent.Decision, auditEvent.PolicyId, auditEvent.DenialReasonCode, auditEvent.Outcome, auditEvent.Duration.TotalMilliseconds, auditEvent.CorrelationId, auditEvent.CallerId);
#pragma warning restore CA1848
        }
        return ValueTask.CompletedTask;
    }
}
