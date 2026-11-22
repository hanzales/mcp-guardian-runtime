using System.Security.Claims;
using McpGuardian.Runtime.Abstractions;

namespace McpGuardian.Runtime.Authorization;

/// <summary>Trusted authorization facts about an MCP caller.</summary>
public sealed record McpCallerContext(bool IsAuthenticated, string? CallerId, IReadOnlySet<string> Roles, IReadOnlySet<string> Scopes)
{
    /// <summary>An unauthenticated caller.</summary>
    public static McpCallerContext Anonymous { get; } = new(false, null, new HashSet<string>(StringComparer.Ordinal), new HashSet<string>(StringComparer.Ordinal));
}

/// <summary>Reads identity, roles, and scope claims from a transport-authenticated principal.</summary>
public sealed class ClaimsPrincipalMcpCallerContextProvider : IMcpCallerContextProvider
{
    /// <inheritdoc />
    public ValueTask<McpCallerContext> GetCallerContextAsync(ClaimsPrincipal? principal, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (principal?.Identity?.IsAuthenticated != true) return ValueTask.FromResult(McpCallerContext.Anonymous);
        var roleClaimType = (principal.Identity as ClaimsIdentity)?.RoleClaimType ?? ClaimTypes.Role;
        var roles = principal.FindAll(roleClaimType).Select(x => x.Value).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var scopes = principal.FindAll("scope").SelectMany(x => x.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)).ToHashSet(StringComparer.Ordinal);
        var id = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? principal.Identity.Name;
        return ValueTask.FromResult(new McpCallerContext(true, id, roles, scopes));
    }
}
