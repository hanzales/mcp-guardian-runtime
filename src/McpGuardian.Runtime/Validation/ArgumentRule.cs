using System.Text.Json;
using System.Text.RegularExpressions;
using McpGuardian.Runtime.Policies;

namespace McpGuardian.Runtime.Validation;

/// <summary>Supported JSON argument kinds.</summary>
public enum McpArgumentType
{
    /// <summary>JSON string.</summary>
    Text,
    /// <summary>JSON number.</summary>
    Number,
    /// <summary>JSON boolean.</summary>
    Boolean,
    /// <summary>JSON object.</summary>
    JsonObject,
    /// <summary>JSON array.</summary>
    JsonArray
}

/// <summary>A precompiled deterministic argument constraint.</summary>
public sealed record ArgumentRule(string Name, bool Required = false, McpArgumentType? Type = null, int? MaximumStringLength = null,
    IReadOnlySet<string>? AllowedValues = null, double? Minimum = null, double? Maximum = null, Regex? Pattern = null, SafePathConstraint? Path = null);

/// <summary>Constrains a path argument to one configured root.</summary>
public sealed record SafePathConstraint(string RootPath, bool MustExist);

internal static class ArgumentValidator
{
    public static string? Validate(IReadOnlyDictionary<string, JsonElement> arguments, McpPolicy policy)
    {
        if (policy.MaximumArgumentBytes is int max && JsonSerializer.SerializeToUtf8Bytes(arguments).Length > max) return "argument_size_exceeded";
        foreach (var rule in policy.ArgumentRules)
        {
            if (!arguments.TryGetValue(rule.Name, out var value)) { if (rule.Required) return "required_argument_missing"; continue; }
            if (rule.Type is { } type && !Matches(value.ValueKind, type)) return "invalid_argument_type";
            if (value.ValueKind == JsonValueKind.String)
            {
                var text = value.GetString() ?? string.Empty;
                if (rule.MaximumStringLength is int length && text.Length > length) return "string_length_exceeded";
                if (rule.AllowedValues is { } allowed && !allowed.Contains(text)) return "value_not_allowed";
                if (rule.Pattern is { } regex && !regex.IsMatch(text)) return "pattern_mismatch";
                if (rule.Path is { } path && !IsPathAllowed(text, path)) return "path_not_allowed";
            }
            if (value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out var number))
            {
                if (rule.Minimum is double min && number < min) return "number_out_of_range";
                if (rule.Maximum is double maxNumber && number > maxNumber) return "number_out_of_range";
            }
        }
        return null;
    }

    private static bool Matches(JsonValueKind kind, McpArgumentType type) => type switch
    {
        McpArgumentType.Text => kind == JsonValueKind.String, McpArgumentType.Number => kind == JsonValueKind.Number,
        McpArgumentType.Boolean => kind is JsonValueKind.True or JsonValueKind.False, McpArgumentType.JsonObject => kind == JsonValueKind.Object,
        McpArgumentType.JsonArray => kind == JsonValueKind.Array, _ => false
    };

    private static bool IsPathAllowed(string candidate, SafePathConstraint constraint)
    {
        try
        {
            var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(constraint.RootPath));
            var full = Path.GetFullPath(candidate, root);
            var relative = Path.GetRelativePath(root, full);
            if (relative == ".." || relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) || Path.IsPathRooted(relative)) return false;
            if (constraint.MustExist && !File.Exists(full) && !Directory.Exists(full)) return false;
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
    }
}
