namespace McpGuardian.Runtime.Exceptions;

/// <summary>Base exception for runtime security failures.</summary>
public class McpSecurityException : Exception
{
    /// <summary>Creates a safe security exception.</summary>
    public McpSecurityException(string message) : base(message) { }
    /// <summary>Creates a safe security exception with an internal cause.</summary>
    public McpSecurityException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>Represents a denied tool invocation.</summary>
public sealed class McpAuthorizationException : McpSecurityException { internal McpAuthorizationException() : base("Tool execution was denied by security policy.") { } }
/// <summary>Represents invalid security configuration.</summary>
public sealed class McpSecurityConfigurationException : McpSecurityException { internal McpSecurityConfigurationException(string message, Exception inner) : base(message, inner) { } }
