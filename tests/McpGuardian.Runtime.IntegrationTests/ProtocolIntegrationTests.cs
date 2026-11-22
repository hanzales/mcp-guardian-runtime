using ModelContextProtocol.Client;

namespace McpGuardian.Runtime.IntegrationTests;

public sealed class ProtocolIntegrationTests
{
    [Fact]
    public async Task Official_sdk_client_observes_allow_and_deny_filters()
    {
        var repository = FindRepositoryRoot();
        var server = Path.Combine(repository, "samples", "SecureMcpServer", "bin", "Release", "net10.0", "SecureMcpServer.dll");
        Assert.True(File.Exists(server), $"Build the solution before integration tests. Missing: {server}");
        var transport = new StdioClientTransport(new StdioClientTransportOptions { Name = "secure-sample", Command = "/usr/local/share/dotnet/dotnet", Arguments = [server], WorkingDirectory = repository, InheritEnvironmentVariables = false, EnvironmentVariables = StdioClientTransportOptions.GetDefaultEnvironmentVariables(), ShutdownTimeout = TimeSpan.FromSeconds(5) });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var client = await McpClient.CreateAsync(transport, cancellationToken: timeout.Token);
        var allowed = await client.CallToolAsync("get_system_status", cancellationToken: timeout.Token);
        var denied = await client.CallToolAsync("delete_document", new Dictionary<string, object?> { ["documentId"] = "welcome" }, cancellationToken: timeout.Token);
        Assert.NotEqual(true, allowed.IsError); Assert.True(denied.IsError);
        Assert.Contains("denied", denied.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Single().Text, StringComparison.OrdinalIgnoreCase);
    }
    private static string FindRepositoryRoot() { var directory = new DirectoryInfo(AppContext.BaseDirectory); while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "McpGuardian.Runtime.slnx"))) directory = directory.Parent; return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root not found."); }
}
