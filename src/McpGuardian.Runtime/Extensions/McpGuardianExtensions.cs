using System.Text.Json;
using McpGuardian.Runtime.Abstractions;
using McpGuardian.Runtime.Auditing;
using McpGuardian.Runtime.Authorization;
using McpGuardian.Runtime.Configuration;
using McpGuardian.Runtime.Exceptions;
using McpGuardian.Runtime.Filters;
using McpGuardian.Runtime.Policies;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Protocol;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Dependency injection and official MCP SDK filter integration.</summary>
public static class McpGuardianExtensions
{
    /// <summary>Registers McpGuardian services. Call <see cref="WithMcpGuardian"/> on the MCP server builder as well.</summary>
    public static IServiceCollection AddMcpGuardian(this IServiceCollection services, Action<McpSecurityOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services); ArgumentNullException.ThrowIfNull(configure);
        services.AddOptions<McpSecurityOptions>().Configure(configure).Validate(options => { try { _ = options.Compile(); return true; } catch { return false; } }, "Invalid McpGuardian policy configuration.").ValidateOnStart();
        services.TryAddSingleton<IMcpPolicyEngine, McpPolicyEngine>();
        services.TryAddSingleton<IMcpCallerContextProvider, ClaimsPrincipalMcpCallerContextProvider>();
        services.TryAddSingleton<IMcpSecurityAuditSink, LoggerMcpSecurityAuditSink>();
        services.TryAddSingleton<McpSecurityPipeline>();
        return services;
    }

    /// <summary>Adds the official SDK call-tool filter. Register after task filters and before tools when ordering matters.</summary>
    public static IMcpServerBuilder WithMcpGuardian(this IMcpServerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.WithRequestFilters(filters => filters.AddCallToolFilter(next => async (context, cancellationToken) =>
        {
            var services = context.Services ?? throw new McpSecurityConfigurationException("McpGuardian requires request services.", new InvalidOperationException());
            var pipeline = services.GetRequiredService<McpSecurityPipeline>();
            var callerProvider = services.GetRequiredService<IMcpCallerContextProvider>();
            var caller = await callerProvider.GetCallerContextAsync(context.User, cancellationToken).ConfigureAwait(false);
            IReadOnlyDictionary<string, JsonElement> arguments = context.Params.Arguments is { } supplied
                ? new Dictionary<string, JsonElement>(supplied, StringComparer.Ordinal)
                : new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            try
            {
                return await pipeline.InvokeAsync(context.Params.Name, arguments, caller,
                    token => next(context, token), context.JsonRpcRequest.Id.ToString(), cancellationToken).ConfigureAwait(false);
            }
            catch (McpAuthorizationException)
            {
                return new CallToolResult { IsError = true, Content = [new TextContentBlock { Text = "Tool execution was denied by security policy." }] };
            }
        }));
    }
}
