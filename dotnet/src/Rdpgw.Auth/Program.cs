using Microsoft.AspNetCore.Server.Kestrel.Core;
using Rdpgw.Auth;
using Rdpgw.Auth.Config;
using Rdpgw.Auth.Database;
using Rdpgw.Auth.Ntlm;

CommandLineOptions options;
try
{
    options = CommandLineOptions.Parse(args);
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    CommandLineOptions.PrintHelp(Console.Error);
    return 2;
}

if (options.Help)
{
    CommandLineOptions.PrintHelp(Console.Out);
    return 0;
}

using var bootstrapLoggerFactory = LoggerFactory.Create(logging => logging.AddSimpleConsole());
var bootstrapLogger = bootstrapLoggerFactory.CreateLogger("Rdpgw.Auth.Startup");

var socketPath = Path.GetFullPath(options.SocketAddr);
var configuration = Configuration.Load(options.ConfigFile, bootstrapLogger);
if (File.Exists(socketPath))
{
    File.Delete(socketPath);
}

if (options.AllowUid.Count > 0 || options.AllowGid.Count > 0)
{
    bootstrapLogger.LogWarning("rdpgw-auth: --allow-uid/--allow-gid are accepted for CLI compatibility; ASP.NET Core transport relies on socket file permissions.");
}

var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = [] });
builder.Services.AddGrpc();
builder.Services.AddSingleton(configuration);
builder.Services.AddSingleton<IUserDatabase>(_ => new ConfigDatabase(configuration.Users));
builder.Services.AddSingleton(_ => new PamAuthenticator(options.ServiceName));
builder.Services.AddSingleton<NtlmAuth>();
builder.Services.AddSingleton<AuthService>();
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.ListenUnixSocket(socketPath, listenOptions =>
    {
        listenOptions.Protocols = HttpProtocols.Http2;
    });
});

var app = builder.Build();
app.MapGrpcService<AuthService>();

app.Logger.LogInformation("Starting auth server on {SocketAddr}", options.SocketAddr);
uint oldUmask = 0;
var changedUmask = OperatingSystem.IsLinux();
if (changedUmask)
{
    oldUmask = NativeUnix.umask(Convert.ToUInt32("117", 8));
}

try
{
    await app.StartAsync();
}
finally
{
    if (changedUmask)
    {
        NativeUnix.umask(oldUmask);
    }
}

if (OperatingSystem.IsLinux() && File.Exists(socketPath))
{
    var rc = NativeUnix.chmod(socketPath, Convert.ToUInt32("660", 8));
    if (rc != 0)
    {
        app.Logger.LogError("Failed to chmod socket {SocketPath}: errno {Errno}", socketPath, System.Runtime.InteropServices.Marshal.GetLastPInvokeError());
    }
}

await app.WaitForShutdownAsync();
return 0;
