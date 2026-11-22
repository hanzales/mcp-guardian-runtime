using System.Text.Json;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using McpGuardian.Runtime.Auditing;
using McpGuardian.Runtime.Authorization;
using McpGuardian.Runtime.Configuration;
using McpGuardian.Runtime.Filters;
using McpGuardian.Runtime.Policies;
using McpGuardian.Runtime.Validation;
using Microsoft.Extensions.Options;

BenchmarkRunner.Run<SecurityPipelineBenchmarks>();

[MemoryDiagnoser]
public class SecurityPipelineBenchmarks
{
    private readonly McpPolicyEngine _engine;
    private readonly McpSecurityPipeline _pipeline;
    private readonly IReadOnlyDictionary<string, JsonElement> _arguments = new Dictionary<string, JsonElement> { ["path"] = JsonSerializer.SerializeToElement("document.txt") };
    private readonly McpCallerContext _caller = new(true, "benchmark", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Reader" }, new HashSet<string> { "documents.read" });
    public SecurityPipelineBenchmarks()
    {
        var options = new McpSecurityOptions();
        options.AllowTool("read").RequireRole("Reader").RequireScope("documents.read").RequireArgument("path", McpArgumentType.Text).LimitString("path", 256);
        var wrapped = Options.Create(options); _engine = new McpPolicyEngine(wrapped); _pipeline = new(_engine, new NoOpAuditSink(), wrapped);
    }
    [Benchmark] public ValueTask<McpPolicyResult> AllowDecision() => _engine.EvaluateAsync(new("read", _arguments, _caller));
    [Benchmark] public ValueTask<McpPolicyResult> DenyDecision() => _engine.EvaluateAsync(new("unknown", _arguments, _caller));
    [Benchmark] public ValueTask<int> FullPipeline() => _pipeline.InvokeAsync("read", _arguments, _caller, _ => ValueTask.FromResult(1));
    private sealed class NoOpAuditSink : IMcpSecurityAuditSink { public ValueTask WriteAsync(McpSecurityAuditEvent auditEvent, CancellationToken cancellationToken = default) => ValueTask.CompletedTask; }
}
