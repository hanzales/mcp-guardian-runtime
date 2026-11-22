using System.Text.RegularExpressions;
using McpGuardian.Runtime.Policies;
using McpGuardian.Runtime.Validation;

namespace McpGuardian.Runtime.Configuration;

/// <summary>Configures McpGuardian policy and auditing behavior.</summary>
public sealed class McpSecurityOptions
{
    private readonly List<McpPolicyBuilder> _builders = [];
    /// <summary>Action for unknown tools. Secure default is deny.</summary>
    public McpPolicyAction DefaultAction { get; set; } = McpPolicyAction.Deny;
    /// <summary>Whether an audit sink failure should fail an otherwise authorized call.</summary>
    public bool FailOnAuditError { get; set; }
    /// <summary>Adds an allow policy for an exact tool name.</summary>
    public McpPolicyBuilder AllowTool(string toolName) => Add(toolName, McpPolicyAction.Allow);
    /// <summary>Adds a deny policy for an exact tool name.</summary>
    public McpPolicyBuilder DenyTool(string toolName) => Add(toolName, McpPolicyAction.Deny);
    internal IReadOnlyList<McpPolicy> Compile()
    {
        if (DefaultAction != McpPolicyAction.Deny) throw new InvalidOperationException("McpGuardian requires default-deny in this release.");
        if (_builders.GroupBy(x => x.Id, StringComparer.Ordinal).Any(x => x.Count() > 1)) throw new InvalidOperationException("Policy identifiers must be unique.");
        return _builders.Select(x => x.Build()).ToArray();
    }
    private McpPolicyBuilder Add(string toolName, McpPolicyAction action)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(toolName);
        var builder = new McpPolicyBuilder($"{action.ToString().ToLowerInvariant()}:{toolName}:{_builders.Count + 1}", toolName, action);
        _builders.Add(builder); return builder;
    }
}

/// <summary>Fluent builder for one tool policy.</summary>
public sealed class McpPolicyBuilder
{
    private readonly HashSet<string> _roles = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _scopes = new(StringComparer.Ordinal);
    private readonly List<ArgumentRule> _rules = [];
    private int? _maxBytes;
    internal McpPolicyBuilder(string id, string toolName, McpPolicyAction action) => (Id, ToolName, Action) = (id, toolName, action);
    internal string Id { get; } internal string ToolName { get; } internal McpPolicyAction Action { get; }
    /// <summary>Requires an authenticated caller with the role.</summary>
    public McpPolicyBuilder RequireRole(string role) { ArgumentException.ThrowIfNullOrWhiteSpace(role); _roles.Add(role); return this; }
    /// <summary>Requires an authenticated caller with the scope.</summary>
    public McpPolicyBuilder RequireScope(string scope) { ArgumentException.ThrowIfNullOrWhiteSpace(scope); _scopes.Add(scope); return this; }
    /// <summary>Limits total serialized argument bytes.</summary>
    public McpPolicyBuilder MaxArgumentSize(int bytes) { ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bytes); _maxBytes = bytes; return this; }
    /// <summary>Requires an argument.</summary>
    public McpPolicyBuilder RequireArgument(string name, McpArgumentType? type = null) { _rules.Add(new(name, true, type)); return this; }
    /// <summary>Limits a string argument.</summary>
    public McpPolicyBuilder LimitString(string name, int maximumLength) { ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumLength); _rules.Add(new(name, MaximumStringLength: maximumLength)); return this; }
    /// <summary>Restricts a string argument to configured values.</summary>
    public McpPolicyBuilder AllowValues(string name, params string[] values) { _rules.Add(new(name, AllowedValues: values.ToHashSet(StringComparer.Ordinal))); return this; }
    /// <summary>Constrains a numeric argument.</summary>
    public McpPolicyBuilder NumberRange(string name, double? minimum, double? maximum) { if (minimum > maximum) throw new ArgumentException("Minimum cannot exceed maximum."); _rules.Add(new(name, Minimum: minimum, Maximum: maximum)); return this; }
    /// <summary>Adds a compiled regular expression with a mandatory timeout.</summary>
    public McpPolicyBuilder Match(string name, string pattern, TimeSpan? timeout = null) { _rules.Add(new(name, Pattern: new Regex(pattern, RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, timeout ?? TimeSpan.FromMilliseconds(100)))); return this; }
    /// <summary>Constrains a path argument beneath an approved root using canonical paths.</summary>
    public McpPolicyBuilder RestrictPath(string argumentName, string rootPath, bool mustExist = false) { ArgumentException.ThrowIfNullOrWhiteSpace(rootPath); _rules.Add(new(argumentName, Type: McpArgumentType.Text, Path: new(Path.GetFullPath(rootPath), mustExist))); return this; }
    /// <summary>Convenience constraint for a conventional <c>path</c> argument.</summary>
    public McpPolicyBuilder RestrictPaths(string rootPath) => RestrictPath("path", rootPath);
    internal McpPolicy Build() => new(Id, ToolName, Action, _roles, _scopes, _rules, _maxBytes);
}
