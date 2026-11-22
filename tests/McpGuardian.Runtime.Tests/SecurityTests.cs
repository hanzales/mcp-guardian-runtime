using System.Security.Claims;
using System.Text.Json;
using McpGuardian.Runtime.Abstractions;
using McpGuardian.Runtime.Auditing;
using McpGuardian.Runtime.Authorization;
using McpGuardian.Runtime.Configuration;
using McpGuardian.Runtime.Exceptions;
using McpGuardian.Runtime.Filters;
using McpGuardian.Runtime.Policies;
using McpGuardian.Runtime.Validation;
using Microsoft.Extensions.Options;

namespace McpGuardian.Runtime.Tests;

public sealed class SecurityTests
{
    [Fact] public async Task Unknown_tool_is_denied() => Assert.Equal(McpPolicyDecision.Deny, (await Engine(o => o.AllowTool("known")).EvaluateAsync(Context("unknown"))).Decision);
    [Fact] public async Task Explicit_allow_succeeds() => Assert.True((await Engine(o => o.AllowTool("status")).EvaluateAsync(Context("status"))).IsAllowed);
    [Fact] public async Task Explicit_deny_overrides_allow() { var result = await Engine(o => { o.AllowTool("danger"); o.DenyTool("danger"); }).EvaluateAsync(Context("danger")); Assert.Equal("explicit_deny", result.ReasonCode); }
    [Theory]
    [InlineData(false, "Admin", "read", "missing_identity")][InlineData(true, "User", "read", "missing_role")][InlineData(true, "Admin", "write", "missing_scope")]
    public async Task Identity_role_and_scope_fail_closed(bool authenticated, string role, string scope, string reason)
    {
        var caller = new McpCallerContext(authenticated, "caller", new HashSet<string> { role }, new HashSet<string> { scope });
        var result = await Engine(o => o.AllowTool("read").RequireRole("Admin").RequireScope("read")).EvaluateAsync(Context("read", caller: caller));
        Assert.Equal(reason, result.ReasonCode);
    }
    [Fact] public async Task Invalid_type_and_oversize_are_rejected()
    {
        var typeResult = await Engine(o => o.AllowTool("x").RequireArgument("count", McpArgumentType.Number)).EvaluateAsync(Context("x", Args(("count", "wrong"))));
        var sizeResult = await Engine(o => o.AllowTool("y").MaxArgumentSize(8)).EvaluateAsync(Context("y", Args(("value", "too large"))));
        Assert.Equal("invalid_argument_type", typeResult.ReasonCode); Assert.Equal("argument_size_exceeded", sizeResult.ReasonCode);
    }
    [Theory][InlineData("../secret.txt")][InlineData("/etc/passwd")]
    public async Task Path_escape_is_rejected(string path)
    {
        var root = Path.Combine(Path.GetTempPath(), "mcpguardian-tests");
        var result = await Engine(o => o.AllowTool("read").RestrictPath("path", root)).EvaluateAsync(Context("read", Args(("path", path))));
        Assert.Equal("path_not_allowed", result.ReasonCode);
    }
    [Fact] public void Invalid_regex_is_rejected_during_configuration() => Assert.ThrowsAny<ArgumentException>(() => new McpSecurityOptions().AllowTool("x").Match("v", "["));
    [Fact] public async Task Denied_pipeline_never_invokes_tool_and_audits()
    {
        var invoked = 0; var audit = new RecordingAuditSink(); var pipeline = Pipeline(o => o.DenyTool("x"), audit);
        await Assert.ThrowsAsync<McpAuthorizationException>(async () => await pipeline.InvokeAsync("x", Empty, McpCallerContext.Anonymous, _ => { invoked++; return ValueTask.FromResult(1); }));
        Assert.Equal(0, invoked); Assert.Single(audit.Events); Assert.Equal(McpExecutionOutcome.NotExecuted, audit.Events[0].Outcome);
    }
    [Fact] public async Task Allowed_pipeline_invokes_once_and_preserves_exception()
    {
        var invoked = 0; var pipeline = Pipeline(o => o.AllowTool("x"), new RecordingAuditSink());
        var value = await pipeline.InvokeAsync("x", Empty, McpCallerContext.Anonymous, _ => { invoked++; return ValueTask.FromResult(42); });
        Assert.Equal(42, value); Assert.Equal(1, invoked);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await pipeline.InvokeAsync<int>("x", Empty, McpCallerContext.Anonymous, _ => throw new InvalidOperationException("tool failure")));
    }
    [Fact] public async Task Cancellation_and_concurrency_are_supported()
    {
        var pipeline = Pipeline(o => o.AllowTool("x"), new RecordingAuditSink()); using var source = new CancellationTokenSource(); source.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await pipeline.InvokeAsync("x", Empty, McpCallerContext.Anonymous, token => { token.ThrowIfCancellationRequested(); return ValueTask.FromResult(0); }, cancellationToken: source.Token));
        var tasks = Enumerable.Range(0, 100).Select(i => pipeline.InvokeAsync("x", Empty, McpCallerContext.Anonymous, _ => ValueTask.FromResult(i)).AsTask());
        Assert.Equal(100, (await Task.WhenAll(tasks)).Length);
    }
    [Fact] public async Task Claims_provider_uses_principal_not_arguments()
    {
        var identity = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "service-1"), new Claim(ClaimTypes.Role, "Reader"), new Claim("scope", "documents.read other")], "Bearer");
        var caller = await new ClaimsPrincipalMcpCallerContextProvider().GetCallerContextAsync(new ClaimsPrincipal(identity));
        Assert.True(caller.IsAuthenticated); Assert.Contains("Reader", caller.Roles); Assert.Contains("documents.read", caller.Scopes);
    }
    private static readonly IReadOnlyDictionary<string, JsonElement> Empty = new Dictionary<string, JsonElement>();
    private static McpPolicyEngine Engine(Action<McpSecurityOptions> configure) { var o = new McpSecurityOptions(); configure(o); return new(Options.Create(o)); }
    private static McpPolicyContext Context(string tool, IReadOnlyDictionary<string, JsonElement>? args = null, McpCallerContext? caller = null) => new(tool, args ?? Empty, caller ?? McpCallerContext.Anonymous);
    private static Dictionary<string, JsonElement> Args(params (string Key, object Value)[] values) => values.ToDictionary(x => x.Key, x => JsonSerializer.SerializeToElement(x.Value));
    private static McpSecurityPipeline Pipeline(Action<McpSecurityOptions> configure, IMcpSecurityAuditSink sink) { var o = new McpSecurityOptions(); configure(o); return new(new McpPolicyEngine(Options.Create(o)), sink, Options.Create(o)); }
    private sealed class RecordingAuditSink : IMcpSecurityAuditSink { public List<McpSecurityAuditEvent> Events { get; } = []; public ValueTask WriteAsync(McpSecurityAuditEvent auditEvent, CancellationToken cancellationToken = default) { lock (Events) Events.Add(auditEvent); return ValueTask.CompletedTask; } }
}
