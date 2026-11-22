using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;

var builder = Host.CreateApplicationBuilder(args);
builder.Logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);
builder.Services.AddMcpGuardian(options =>
{
    options.AllowTool("get_system_status");
    options.AllowTool("read_document").RequireRole("DocumentReader").RequireArgument("documentId");
    options.DenyTool("delete_document");
});
builder.Services.AddMcpServer().WithStdioServerTransport().WithMcpGuardian().WithTools<SecureTools>();
await builder.Build().RunAsync();

[McpServerToolType]
public sealed class SecureTools
{
    [McpServerTool(Name = "get_system_status"), Description("Returns a non-sensitive service status.")]
    public static string GetSystemStatus() => "healthy";
    [McpServerTool(Name = "read_document"), Description("Reads one predefined demonstration document.")]
    public static string ReadDocument(string documentId) => documentId == "welcome" ? "Welcome to the secure MCP sample." : "Document not found.";
    [McpServerTool(Name = "delete_document"), Description("Demonstrates an explicitly denied destructive operation.")]
    public static string DeleteDocument(string documentId) => $"deleted:{documentId}";
}
